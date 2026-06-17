import puppeteer from 'puppeteer-core';
import { existsSync, mkdirSync } from 'fs';
import { readFile, writeFile } from 'fs/promises';
import { fetchOtpFromEmail } from './otpFetcher.js';

const log = (...args) => console.log('[Auth]', ...args);
const logStep = (step, detail = '') => console.log('[Auth]', `Step: ${step}`, detail ? `— ${detail}` : '');

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let cachedAuth = null;
let cachedAtMs = 0;
let cacheLoaded = false;
let inFlightAuthPromise = null;

const AUTH_CACHE_FILE =
  (process.env.AUTH_CACHE_FILE && String(process.env.AUTH_CACHE_FILE).trim()) ||
  '/tmp/bayan-auth-cache.json';

function base64UrlDecodeToString(s) {
  try {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(b64, 'base64').toString('utf8');
  } catch (_) {
    return '';
  }
}

function tryGetJwtExpMs(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  const payloadStr = base64UrlDecodeToString(parts[1]);
  if (!payloadStr) return null;
  try {
    const payload = JSON.parse(payloadStr);
    const exp = payload?.exp;
    if (!Number.isFinite(exp)) return null;
    return Number(exp) * 1000;
  } catch (_) {
    return null;
  }
}

function isCachedAuthValid({ ttlMs, skewMs = 60_000 } = {}) {
  if (!cachedAuth) return false;
  // When JWT exp is available, also honor TTL since cookies/WAF tokens may expire earlier than JWT.
  const expMs = tryGetJwtExpMs(cachedAuth.accessToken);
  if (expMs) {
    const okJwt = Date.now() < expMs - skewMs;
    const okTtl = ttlMs > 0 && cachedAtMs > 0 ? Date.now() - cachedAtMs < ttlMs : true;
    return okJwt && okTtl;
  }
  if (ttlMs > 0 && cachedAtMs > 0) return Date.now() - cachedAtMs < ttlMs;
  return false;
}

async function loadAuthCacheOnce() {
  if (cacheLoaded) return;
  cacheLoaded = true;
  try {
    const raw = await readFile(AUTH_CACHE_FILE, 'utf8');
    const obj = JSON.parse(raw);
    if (obj && typeof obj === 'object') {
      cachedAuth = obj.cachedAuth ?? null;
      cachedAtMs = Number(obj.cachedAtMs) || 0;
      if (cachedAuth) log('Loaded auth cache from disk', { file: AUTH_CACHE_FILE, cachedAtMs });
    }
  } catch (_) {
    // ignore (file missing/corrupt)
  }
}

async function persistAuthCache() {
  try {
    await writeFile(
      AUTH_CACHE_FILE,
      JSON.stringify({ cachedAtMs, cachedAuth }, null, 2),
      'utf8'
    );
  } catch (e) {
    console.error('[Auth] Failed to persist auth cache:', e?.message);
  }
}

async function detectServerOops(page) {
  try {
    const txt = await page.evaluate(() => document?.body?.innerText || '');
    return /oops!\s*something went wrong on the server/i.test(txt) || /i-s\s*oops/i.test(txt);
  } catch (_) {
    return false;
  }
}

async function throwIfServerOops(page, where) {
  const isOops = await detectServerOops(page);
  if (isOops) {
    logStep('Server OOPS detected', where);
    const screenshot = `bayan-server-oops-${Date.now()}.png`;
    await page.screenshot({ path: screenshot, fullPage: true }).catch(() => {});
    console.log('[Auth] Screenshot saved:', screenshot);
    const err = new Error(`Bayan server error page at: ${where}`);
    err.debugScreenshot = screenshot;
    err.code = 'BAYAN_SERVER_OOPS';
    throw err;
  }
}

/** True if element exists and is shown (not display:none on self). */
async function isElementDisplayed(page, selector) {
  return page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return false;
    const style = window.getComputedStyle(el);
    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
  }, selector);
}

async function dismissRememberedAccountsIfPresent(page) {
  const accountsPhase = '#phase-accounts';
  if (!(await isElementDisplayed(page, accountsPhase))) return;
  logStep('IAM', 'remembered accounts list visible — use another account');
  const useAnother = await page.$('#useAnotherAccount');
  if (useAnother) await useAnother.click().catch(() => {});
  await delay(500);
}

/** IAM (iam.logisti.sa) phased login after Bayan redirects to SSO. */
async function completeIamProgressiveLogin(page, { IDENTITY_NUMBER, PASSWORD, OTP_SENDER }) {
  await dismissRememberedAccountsIfPresent(page);

  logStep('IAM', 'identifier — #Username, #continueBtn');
  await page.waitForSelector('#Username', { visible: true, timeout: 25000 });
  await throwIfServerOops(page, 'IAM identifier');
  await page.click('#Username', { clickCount: 3 }).catch(() => {});
  await page.type('#Username', IDENTITY_NUMBER, { delay: 80 });
  await delay(200);
  await page.click('#continueBtn');
  await delay(800);

  const pickPasswordFromMethods = () =>
    page.evaluate(() => {
      const grid = document.getElementById('methods-grid');
      if (!grid) return false;
      const candidates = Array.from(grid.querySelectorAll('button, [role="button"], a.btn'));
      const isPasskeyish = (t) =>
        /passkey|webauthn|fingerprint|face\s*id|بصمة|مفتاح\s*المرور|الوجه/i.test(t);
      for (const el of candidates) {
        const t = (el.textContent || '').toLowerCase();
        if (isPasskeyish(t)) continue;
        if (t.includes('password') || t.includes('كلمة') || t.includes('مرور')) {
          el.click();
          return true;
        }
      }
      const nonPk = candidates.find((el) => !isPasskeyish((el.textContent || '').toLowerCase()));
      if (nonPk) {
        nonPk.click();
        return true;
      }
      return false;
    });

  const PASSWORD_PHASE_DEADLINE_MS = Number(process.env.IAM_PASSWORD_PHASE_DEADLINE_MS || 60000);
  const phaseDeadline = Date.now() + PASSWORD_PHASE_DEADLINE_MS;
  let lastObservedPhase = '';
  while (Date.now() < phaseDeadline) {
    if (await isElementDisplayed(page, '#password')) break;
    await throwIfServerOops(page, 'IAM phases');

    if (await isElementDisplayed(page, '#phase-passkey')) {
      if (lastObservedPhase !== 'passkey') {
        logStep('IAM', 'passkey prompt — #passkeyTryAnother');
        lastObservedPhase = 'passkey';
      }
      await page.click('#passkeyTryAnother').catch(() => {});
      await delay(1200);
      continue;
    }

    if (await isElementDisplayed(page, '#phase-methods')) {
      if (lastObservedPhase !== 'methods') {
        logStep('IAM', 'method grid — choose password');
        lastObservedPhase = 'methods';
      }
      await pickPasswordFromMethods().catch(() => {});
      await delay(1200);
      continue;
    }

    if (lastObservedPhase !== 'waiting') {
      logStep('IAM', 'no recognized phase visible — waiting for password/passkey/methods');
      lastObservedPhase = 'waiting';
    }
    await delay(750);
  }

  if (!(await isElementDisplayed(page, '#password'))) {
    const screenshot = `bayan-iam-no-password-${Date.now()}.png`;
    await page.screenshot({ path: screenshot, fullPage: true }).catch(() => {});
    const debugInfo = await page
      .evaluate(() => {
        const phases = ['phase-accounts', 'phase-passkey', 'phase-methods', 'phase-otp', 'phase-password'];
        const visible = phases.filter((id) => {
          const el = document.getElementById(id);
          if (!el) return false;
          const s = window.getComputedStyle(el);
          return s.display !== 'none' && s.visibility !== 'hidden';
        });
        const url = window.location.href;
        const title = document.title;
        const bodyText = (document.body?.innerText || '').slice(0, 500);
        return { url, title, visiblePhases: visible, bodyText };
      })
      .catch(() => null);
    log('Password phase never appeared. Debug:', JSON.stringify(debugInfo));
    log('Screenshot:', screenshot);
    throw new Error('IAM password phase never appeared (#password not visible)');
  }

  logStep('IAM', 'password phase — #password, Policy Email, #passwordSubmitBtn');
  await throwIfServerOops(page, 'IAM password');
  await page.click('#password', { clickCount: 3 }).catch(() => {});
  await page.type('#password', PASSWORD, { delay: 80 });
  const emailPolicy = await page.$('input[name="Policy"][value="Email"]');
  if (emailPolicy) {
    await emailPolicy.click().catch(() => {});
  }
  await delay(300);

  let baselineOtpMsgId = null;
  try {
    const { getLatestMessageMeta } = await import('./otpFetcher.js');
    const meta = await getLatestMessageMeta(OTP_SENDER);
    baselineOtpMsgId = meta?.id ?? null;
    log('OTP baseline message id (before password submit)', baselineOtpMsgId ?? 'none');
  } catch (e) {
    log('OTP baseline fetch failed (will still try OTP)', e?.message);
  }

  logStep('IAM', 'submit password');
  await page.click('#passwordSubmitBtn');
  await delay(800);

  logStep('IAM', 'wait for inline OTP (#phase-otp) or standalone /Account/VerifyOtp');
  await page.waitForFunction(
    () => {
      const path = (window.location.pathname || '').toLowerCase();
      if (path.includes('verifyotp')) return true;
      const form = document.getElementById('formId');
      const act = (form?.getAttribute('action') || '').toLowerCase();
      if (act.includes('verifyotp')) return true;
      const tfc = document.getElementById('TwoFactorCode1');
      if (tfc) {
        const st = window.getComputedStyle(tfc);
        if (st.display !== 'none' && st.visibility !== 'hidden') return true;
      }
      const phase = document.getElementById('phase-otp');
      if (!phase || window.getComputedStyle(phase).display === 'none') return false;
      const send = document.getElementById('otp-send-step');
      const verify = document.getElementById('otp-verify-step');
      const sendOn = send && window.getComputedStyle(send).display !== 'none';
      const verifyOn = verify && window.getComputedStyle(verify).display !== 'none';
      return sendOn || verifyOn;
    },
    { timeout: 45000 }
  );
  await throwIfServerOops(page, 'IAM OTP');

  const standaloneVerify = await page.evaluate(() => {
    const path = (window.location.pathname || '').toLowerCase();
    if (path.includes('verifyotp')) return true;
    const form = document.getElementById('formId');
    const act = form?.getAttribute('action') || '';
    return act.includes('VerifyOtp');
  });

  if (standaloneVerify) {
    logStep('IAM', 'standalone VerifyOtp — inputs ready (no #phase-otp send step)');
    await page.waitForSelector('#TwoFactorCode1', { visible: true, timeout: 20000 });
    await page
      .waitForFunction(() => typeof window.jQuery === 'function', { timeout: 15000 })
      .catch(() => null);
  } else {
    const sendStepVisible = await page.evaluate(() => {
      const el = document.getElementById('otp-send-step');
      return el && window.getComputedStyle(el).display !== 'none';
    });
    if (sendStepVisible) {
      logStep('IAM', 'OTP send step — #otpSendBtn');
      await page.click('#otpSendBtn');
      const afterSendMs = Number(process.env.OTP_AFTER_SEND_MS || 4000);
      await delay(Number.isFinite(afterSendMs) && afterSendMs >= 0 ? afterSendMs : 4000);
    }

    await page.waitForFunction(
      () => {
        const step = document.getElementById('otp-verify-step');
        return step && window.getComputedStyle(step).display !== 'none';
      },
      { timeout: 25000 }
    );
  }

  logStep('IAM', 'OTP inputs ready (.otp-input / TwoFactorCode*)');
  await page.waitForSelector('#TwoFactorCode1, .otp-input', { visible: true, timeout: 15000 });

  return { baselineOtpMsgId };
}

async function typeIamOtpAndVerify(page, otp) {
  const digits = String(otp || '').replace(/\D/g, '').slice(0, 4);
  if (digits.length < 4) throw new Error(`OTP too short: ${otp}`);

  await page.waitForSelector('#TwoFactorCode1, .otp-input', { visible: true, timeout: 20000 });

  logStep('IAM', 'OTP entry (jQuery .val + trigger input — matches otp-code.js)');
  const jqFill = await page.evaluate((digs) => {
    const $w = window.jQuery || window.$;
    if (typeof $w !== 'function') return { ok: false, reason: 'no-jquery' };
    digs.split('').forEach((digit, i) => {
      const $el = $w(`.otp-input[data-index="${i + 1}"]`);
      if ($el.length) $el.val(digit).trigger('input');
    });
    return { ok: true };
  }, digits);

  let filledOk = jqFill?.ok === true;
  if (!filledOk) {
    logStep('IAM', 'jQuery missing — Puppeteer keyboard per #TwoFactorCodeN');
    for (let i = 0; i < 4; i++) {
      const sel = `#TwoFactorCode${i + 1}`;
      const h = await page.$(sel);
      if (!h) throw new Error(`Missing ${sel}`);
      await h.click({ clickCount: 3 });
      await page.keyboard.press('Backspace').catch(() => {});
      await page.keyboard.type(digits[i], { delay: 60 });
      await delay(80);
    }
    filledOk = true;
  }

  const valuesOk = await page.evaluate(() =>
    [1, 2, 3, 4].every((n) => {
      const el = document.getElementById(`TwoFactorCode${n}`);
      return el && String(el.value || '').length === 1;
    })
  );
  if (!valuesOk) {
    logStep('IAM', 'OTP cells incomplete — paste-style fill');
    await page.evaluate((digs) => {
      const $w = window.jQuery || window.$;
      if (typeof $w === 'function') {
        digs.split('').forEach((digit, i) => {
          const $el = $w(`.otp-input[data-index="${i + 1}"]`);
          if ($el.length) $el.val(digit).trigger('input');
        });
        return;
      }
      digs.split('').forEach((digit, i) => {
        const el = document.getElementById(`TwoFactorCode${i + 1}`);
        if (el) {
          el.value = digit;
          el.dispatchEvent(new Event('input', { bubbles: true }));
        }
      });
    }, digits);
  }

  await delay(400);

  logStep('IAM', 'OTP verify button (VerifyOtp form or inline IAM)');
  await page.waitForFunction(
    () => {
      const primary = document.querySelector(
        'button[type="submit"][name="button"][value="verify"]:not(#fakeSubmitBtnExecuteOnEnter)'
      );
      if (primary && !primary.disabled) {
        const r = primary.getBoundingClientRect();
        if (r.width > 4 && r.height > 4) return true;
      }
      const a = document.getElementById('otpVerifyBtn');
      if (a && !a.disabled) return true;
      const b = document.querySelector('button.verify-code[type="submit"]');
      return b && !b.disabled;
    },
    { timeout: 20000 }
  );

  const clicked = await page.evaluate(() => {
    const primary = document.querySelector(
      'button[type="submit"][name="button"][value="verify"]:not(#fakeSubmitBtnExecuteOnEnter)'
    );
    if (primary && !primary.disabled) {
      const r = primary.getBoundingClientRect();
      if (r.width > 4 && r.height > 4) {
        primary.click();
        return 'verify-submit-primary';
      }
    }
    const a = document.getElementById('otpVerifyBtn');
    if (a && !a.disabled) {
      a.click();
      return 'otpVerifyBtn';
    }
    const b = document.querySelector('button.verify-code[type="submit"]');
    if (b && !b.disabled) {
      b.click();
      return 'verify-code';
    }
    return '';
  });
  if (!clicked) throw new Error('No enabled OTP verify button found');
}

async function waitForOtpResendEnabled(page, timeoutMs) {
  logStep('IAM', 'waiting for resend (#otpResendBtn or #btnResendSms) to enable');
  await page.waitForFunction(
    () => {
      const a = document.getElementById('otpResendBtn');
      if (a && !a.disabled) return true;
      const b = document.getElementById('btnResendSms');
      if (!b || b.disabled) return false;
      if (b.hasAttribute('hidden')) return false;
      return true;
    },
    { timeout: timeoutMs }
  );
}

async function fetchOtpWithResendFallback(page, params) {
  const {
    OTP_SENDER,
    baselineOtpMsgId,
    OTP_WAIT_MS,
    OTP_RESEND_MAX,
    OTP_RESEND_ENABLE_TIMEOUT_MS,
    OTP_WAIT_AFTER_RESEND_MS,
    OTP_FETCH_RETRIES,
    OTP_FETCH_DELAY_MS,
  } = params;

  let baseline = baselineOtpMsgId;
  logStep('OTP', `waiting ${OTP_WAIT_MS}ms on 2FA page before polling mail`);
  await delay(OTP_WAIT_MS);

  let otp = await fetchOtpFromEmail(
    OTP_SENDER,
    OTP_FETCH_RETRIES,
    OTP_FETCH_DELAY_MS,
    0,
    baseline
  );

  const maxResend = Math.min(Math.max(0, OTP_RESEND_MAX), 5);
  for (let round = 0; !otp && round < maxResend; round++) {
    logStep('OTP', `no OTP from mail — IAM resend (${round + 1}/${maxResend})`);
    try {
      await waitForOtpResendEnabled(page, OTP_RESEND_ENABLE_TIMEOUT_MS);
    } catch (e) {
      log('Resend button did not become enabled in time:', e?.message || e);
      break;
    }
    try {
      const { getLatestMessageMeta } = await import('./otpFetcher.js');
      const meta = await getLatestMessageMeta(OTP_SENDER);
      if (meta?.id) baseline = meta.id;
    } catch (e) {
      log('getLatestMessageMeta before resend failed:', e?.message);
    }
    await page
      .evaluate(() => {
        const a = document.getElementById('otpResendBtn');
        if (a && !a.disabled) {
          a.click();
          return;
        }
        const b = document.getElementById('btnResendSms');
        if (b && !b.disabled && !b.hasAttribute('hidden')) b.click();
      })
      .catch((e) => log('resend click failed:', e?.message));
    logStep('OTP', `waiting ${OTP_WAIT_AFTER_RESEND_MS}ms after resend before polling again`);
    await delay(OTP_WAIT_AFTER_RESEND_MS);
    otp = await fetchOtpFromEmail(
      OTP_SENDER,
      OTP_FETCH_RETRIES,
      OTP_FETCH_DELAY_MS,
      0,
      baseline
    );
  }

  return otp;
}

function firstExistingPath(paths) {
  for (const p of paths) {
    if (typeof p !== 'string' || !p.trim()) continue;
    try {
      if (existsSync(p)) return p;
    } catch (_) {
      // ignore permission/fs errors
    }
  }
  return null;
}

function isRootUser() {
  try {
    return typeof process.getuid === 'function' && process.getuid() === 0;
  } catch (_) {
    return false;
  }
}

function ensureLinuxRootRuntimeDir() {
  // Chromium (when run as root) may try to create XDG_RUNTIME_DIR at /run/user/0.
  // In some minimal/container environments /run/user can be read-only/unavailable.
  if (process.platform !== 'linux') return;
  if (!isRootUser()) return;

  const current = (process.env.XDG_RUNTIME_DIR || '').trim();
  if (current && current !== '/run/user/0') return;

  const fallback = '/tmp/xdg-runtime-root';
  try {
    mkdirSync(fallback, { recursive: true, mode: 0o700 });
  } catch (_) {
    // ignore; we'll still set env and let Chromium try
  }
  process.env.XDG_RUNTIME_DIR = fallback;
}

function getBrowserExecutablePath() {
  const envPath =
    typeof process.env.PUPPETEER_EXECUTABLE_PATH === 'string'
      ? process.env.PUPPETEER_EXECUTABLE_PATH.trim()
      : '';
  if (envPath) {
    try {
      if (existsSync(envPath)) return envPath;
    } catch (_) {
      // ignore fs errors
    }
  }

  const platform = process.platform;

  if (platform === 'darwin') {
    return firstExistingPath([
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
      '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    ]);
  }

  if (platform === 'win32') {
    const pf = process.env.PROGRAMFILES;
    const pf86 = process.env['PROGRAMFILES(X86)'];
    const local = process.env.LOCALAPPDATA;

    return firstExistingPath([
      // Chrome
      pf ? `${pf}\\Google\\Chrome\\Application\\chrome.exe` : null,
      pf86 ? `${pf86}\\Google\\Chrome\\Application\\chrome.exe` : null,
      local ? `${local}\\Google\\Chrome\\Application\\chrome.exe` : null,
      // Edge
      pf ? `${pf}\\Microsoft\\Edge\\Application\\msedge.exe` : null,
      pf86 ? `${pf86}\\Microsoft\\Edge\\Application\\msedge.exe` : null,
      local ? `${local}\\Microsoft\\Edge\\Application\\msedge.exe` : null,
    ]);
  }

  // linux + others (includes common paths on Amazon Linux, RHEL, Debian, etc.)
  return firstExistingPath([
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium-browser-unstable',
    '/snap/bin/chromium',
    '/usr/bin/microsoft-edge',
    '/usr/bin/microsoft-edge-stable',
    '/usr/lib64/chromium-browser/chromium-browser', // some Amazon Linux / RHEL
  ]);
}

/**
 * Login to bayan.logisti.sa and return cookie and access token.
 * @returns {Promise<{ cookie: string, cookieHeader: string, accessToken: string | null, headers: object }>}
 */
// Fallback TTL for non-JWT tokens/cookies. If accessToken is a JWT, we prefer its exp time.
// Set AUTH_CACHE_TTL_MS=0 to disable fallback TTL usage entirely.
const DEFAULT_AUTH_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

export async function invalidateAuthCache({ persist = true } = {}) {
  cachedAuth = null;
  cachedAtMs = 0;
  try {
    inFlightAuthPromise = null;
  } catch (_) {}
  if (persist) await persistAuthCache();
}

export async function getAuth(options = {}) {
  log('getAuth() started');
  await loadAuthCacheOnce();

  const forceRefresh = options?.forceRefresh === true;
  if (forceRefresh) {
    log('Force refresh requested; invalidating cache');
    await invalidateAuthCache({ persist: false });
  }

  // Coalesce concurrent calls so only one login/OTP happens at a time.
  if (!forceRefresh && inFlightAuthPromise) {
    log('Awaiting in-flight auth refresh');
    return await inFlightAuthPromise;
  }

  const envTtl = process.env.AUTH_CACHE_TTL_MS;
  const ttlMs = envTtl === undefined || envTtl === '' ? DEFAULT_AUTH_CACHE_TTL_MS : Number(envTtl) || 0;
  if (!forceRefresh && isCachedAuthValid({ ttlMs })) {
    log('Using cached auth', { cacheAgeMs: Date.now() - cachedAtMs, ttlMs });
    return cachedAuth;
  }
  logStep('Cache', ttlMs > 0 ? `TTL=${ttlMs}ms, cache miss` : 'caching disabled');

  inFlightAuthPromise = (async () => {

  const IDENTITY_NUMBER = process.env.BAYAN_IDENTITY_NUMBER;
  const PASSWORD = process.env.BAYAN_PASSWORD;
  const OTP_SENDER = process.env.BAYAN_OTP_SENDER || 'NoReply@logisti.sa';
  const OTP_WAIT_MS = Number(process.env.OTP_WAIT_MS || 25000);
  const OTP_AFTER_SEND_MS = Number(process.env.OTP_AFTER_SEND_MS || 4000);
  const rawResend = process.env.OTP_RESEND_MAX;
  const OTP_RESEND_MAX =
    rawResend === undefined || rawResend === ''
      ? 2
      : Math.min(5, Math.max(0, Number(rawResend) || 0));
  const OTP_RESEND_ENABLE_TIMEOUT_MS = Number(process.env.OTP_RESEND_ENABLE_TIMEOUT_MS || 120000);
  const OTP_WAIT_AFTER_RESEND_MS = Number(process.env.OTP_WAIT_AFTER_RESEND_MS || 8000);
  const OTP_FETCH_RETRIES = Number(process.env.OTP_FETCH_RETRIES || 35);
  const OTP_FETCH_DELAY_MS = Number(process.env.OTP_FETCH_DELAY_MS || 2000);
  const MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 3);
  logStep(
    'Config',
    `OTP_SENDER=${OTP_SENDER}, OTP_WAIT_MS=${OTP_WAIT_MS}, OTP_AFTER_SEND_MS=${OTP_AFTER_SEND_MS}, OTP_RESEND_MAX=${OTP_RESEND_MAX}, OTP_FETCH_RETRIES=${OTP_FETCH_RETRIES}, MAX_ATTEMPTS=${MAX_ATTEMPTS}, credentials=${IDENTITY_NUMBER ? 'set' : 'missing'}`
  );

  if (!IDENTITY_NUMBER || !PASSWORD) {
    console.error('[Auth] Missing BAYAN_IDENTITY_NUMBER or BAYAN_PASSWORD');
    throw new Error('Missing BAYAN_IDENTITY_NUMBER or BAYAN_PASSWORD in environment');
  }

  const executablePath = getBrowserExecutablePath();
  if (!executablePath) {
    console.error('[Auth] No Chrome/Chromium/Edge executable found');
    throw new Error(
      'Chrome/Chromium/Edge not found. Install a supported browser, or set PUPPETEER_EXECUTABLE_PATH and use it here.'
    );
  }
  logStep('Browser', `executable=${executablePath}`);

  const headless = process.env.HEADLESS !== 'false';
  logStep('Launch', `headless=${headless}`);

  let browser;
  try {
    ensureLinuxRootRuntimeDir();

    const args = [
      '--no-first-run',
      '--disable-blink-features=AutomationControlled',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-software-rasterizer',
      '--disable-extensions',
    ];

    // Root on Linux cannot use Chromium sandbox; keep args consistent.
    // If we disable zygote, Chromium requires sandbox be disabled too.
    if (process.platform === 'linux' && isRootUser()) {
      args.push('--no-sandbox', '--disable-setuid-sandbox', '--no-zygote');
    }

    browser = await puppeteer.launch({
      headless,
      args,
      defaultViewport: null,
      ignoreHTTPSErrors: true,
      timeout: 60000,
      executablePath,
    });
  } catch (err) {
    console.error('[Auth] Browser launch failed:', err.message);
    throw new Error('Failed to launch browser: ' + err.message);
  }
  log('Browser launched successfully');

  try {
    let lastErr = null;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      logStep(`Attempt ${attempt}/${MAX_ATTEMPTS}`, 'create context and page');
      const ctx = await browser.createBrowserContext();
      const page = await ctx.newPage();

      // If running headless, override UA to look like regular Chrome (avoid "HeadlessChrome")
      try {
        const ua = await browser.userAgent();
        const fixedUa = ua.replace('HeadlessChrome', 'Chrome');
        await page.setUserAgent(fixedUa);
      } catch (_) {
        // ignore
      }

      let lastBearerToken = null;
      page.on('request', async (req) => {
        try {
          const h = req.headers?.() ?? {};
          const auth = h.authorization || h.Authorization;
          if (typeof auth === 'string' && auth.toLowerCase().startsWith('bearer ')) {
            lastBearerToken = auth.slice('bearer '.length).trim();
          }

          const url = req.url() || '';
          if (url.includes('/connect/authorize')) {
            try {
              const u = new URL(url);
              const p = Object.fromEntries(u.searchParams.entries());
              console.log('[OIDC sniff] /connect/authorize', JSON.stringify({
                client_id: p.client_id,
                response_type: p.response_type,
                response_mode: p.response_mode,
                scope: p.scope,
                redirect_uri: p.redirect_uri,
                code_challenge_method: p.code_challenge_method,
                acr_values: p.acr_values,
                prompt: p.prompt,
              }));
            } catch (_) {}
          }
          if (url.includes('/connect/token')) {
            try {
              const post = (await req.fetchPostData()) || '';
              const p = Object.fromEntries(new URLSearchParams(post).entries());
              const r = { ...p };
              if (r.password) r.password = '***';
              if (r.code) r.code = '***';
              if (r.code_verifier) r.code_verifier = '***';
              if (r.client_secret) r.client_secret = '***';
              if (r.refresh_token) r.refresh_token = '***';
              console.log('[OIDC sniff] /connect/token request', JSON.stringify(r));
            } catch (_) {}
          }
        } catch (_) {
          // ignore
        }
      });

      let pendingReloadReason = null;
      page.on('requestfailed', (req) => {
        try {
          if (req.resourceType?.() !== 'document') return;
          const url = req.url() || '';
          if (!/bayan\.logisti\.sa/.test(url)) return;
          const failure = req.failure?.();
          const errText = failure?.errorText || 'unknown';
          console.log('[Auth] [requestfailed]', errText, url.slice(0, 200));
          pendingReloadReason = errText;
        } catch (_) {}
      });

      page.on('response', async (res) => {
        try {
          const url = res.url() || '';
          if (!url.includes('/connect/token')) return;
          const status = res.status();
          let body = '';
          try { body = await res.text(); } catch (_) {}
          let parsed = null;
          try { parsed = JSON.parse(body); } catch (_) {}
          if (parsed && typeof parsed === 'object') {
            const r = { ...parsed };
            if (r.access_token) r.access_token = `<jwt:len=${String(r.access_token).length}>`;
            if (r.id_token) r.id_token = `<jwt:len=${String(r.id_token).length}>`;
            if (r.refresh_token) r.refresh_token = '***';
            console.log('[OIDC sniff] /connect/token response', status, JSON.stringify(r));
          } else {
            console.log('[OIDC sniff] /connect/token response', status, body.slice(0, 300));
          }
        } catch (_) {
          // ignore
        }
      });

      try {
        logStep('Navigate', 'bayan.logisti.sa');
        await page.goto('https://bayan.logisti.sa/', { waitUntil: 'networkidle2', timeout: 30000 });
        logStep('Page load', 'waiting for Bayan app-root or IAM login');
        await page.waitForFunction(
          () => document.querySelector('app-root') || document.querySelector('#Username'),
          { timeout: 20000 }
        );
        await throwIfServerOops(page, 'landing');

        await delay(1500);
        logStep('Landing', 'waiting for Bayan role cards or IAM #Username');
        await page.waitForFunction(
          () => document.querySelector('.card') || document.querySelector('#Username'),
          { timeout: 20000 }
        );
        await throwIfServerOops(page, 'landing cards');

        const urlAfterLoad = page.url();
        if (!urlAfterLoad.includes('iam.logisti.sa')) {
          logStep('Landing', 'click Local Carrier / first card');
          const clicked = await page.evaluate(() => {
            const titles = Array.from(document.querySelectorAll('h4.card-title'));
            const localCarrierTitle = titles.find((el) => el.textContent.trim() === 'Local Carrier');
            if (localCarrierTitle) {
              const card = localCarrierTitle.closest('.card');
              if (card) {
                card.click();
                return true;
              }
            }
            return false;
          });
          if (!clicked) {
            const hasCard = await page.$('.column:first-child .card');
            if (hasCard) await page.click('.column:first-child .card');
          }
          await delay(2500);
          await throwIfServerOops(page, 'after local carrier click');
        } else {
          logStep('Landing', 'already on IAM — skip Bayan card');
        }

        logStep('Login', 'IAM progressive flow (identifier → password → OTP)');
        const { baselineOtpMsgId } = await completeIamProgressiveLogin(page, {
          IDENTITY_NUMBER,
          PASSWORD,
          OTP_SENDER,
        });
        await throwIfServerOops(page, 'IAM before email OTP fetch');

        const otp = await fetchOtpWithResendFallback(page, {
          OTP_SENDER,
          baselineOtpMsgId,
          OTP_WAIT_MS,
          OTP_RESEND_MAX,
          OTP_RESEND_ENABLE_TIMEOUT_MS,
          OTP_WAIT_AFTER_RESEND_MS,
          OTP_FETCH_RETRIES,
          OTP_FETCH_DELAY_MS,
        });
        if (!otp) {
          console.error('[Auth] OTP fetch returned empty after waits and resend(s)');
          throw new Error('Failed to fetch OTP from email');
        }
        logStep('OTP', `received (length=${otp.length})`);

        await typeIamOtpAndVerify(page, otp);

        const POST_LOGIN_TIMEOUT_MS = Number(process.env.POST_LOGIN_TIMEOUT_MS || 180000);
        logStep('Post-login', `waiting for dashboard/session (up to ${POST_LOGIN_TIMEOUT_MS}ms)`);
        const waitForPostLogin = async (timeoutMs = POST_LOGIN_TIMEOUT_MS) => {
          const start = Date.now();
          let callbackSeenAt = 0;
          let reloadCount = 0;
          let gotoFallbackUsed = false;
          const STUCK_RELOAD_MS = Number(process.env.OAUTH_CALLBACK_STUCK_MS || 3000);
          const MAX_RELOADS = Number(process.env.OAUTH_CALLBACK_MAX_RELOADS || 6);
          const RELOAD_TIMEOUT_MS = Number(process.env.OAUTH_CALLBACK_RELOAD_TIMEOUT_MS || 12000);
          const GOTO_FALLBACK_AFTER = Number(process.env.OAUTH_CALLBACK_GOTO_AFTER || 3);
          const isChromeErrorPage = async () => {
            try {
              const has = await page.$('#main-frame-error, #main-message');
              return has != null;
            } catch (_) {
              return false;
            }
          };
          const withTimeout = async (p, ms, label) => {
            return Promise.race([
              p,
              new Promise((_, rej) => setTimeout(() => rej(new Error(`${label} timeout ${ms}ms`)), ms)),
            ]);
          };
          let lastTick = 0;
          while (Date.now() - start < timeoutMs) {
            const elapsed = Date.now() - start;
            if (elapsed - lastTick > 5000) {
              lastTick = elapsed;
              logStep('Post-login', `tick ${Math.round(elapsed / 1000)}s url=${(page.url() || '').slice(0, 120)}`);
            }

            await throwIfServerOops(page, 'post-login wait').catch(() => {});
            let url = page.url();

            let cookies = [];
            try {
              cookies = await withTimeout(page.cookies(), 3000, 'cookies');
            } catch (_) {
              cookies = [];
            }
            const names = new Set((cookies || []).map((c) => c?.name).filter(Boolean));
            const hasDashboard = await withTimeout(page.$('.sidebar-menu'), 2000, 'sidebar').catch(() => null);
            const hasSessionCookie = names.has('JSESSIONID') || names.has('TS01f96da1') || names.has('lang');
            const stillOnLogin = url.includes('/login') || (url.includes('#') && url.toLowerCase().includes('login'));
            if (hasDashboard || (hasSessionCookie && !stillOnLogin)) return;

            const onOAuthCallback = /[?&]code=/.test(url) && /bayan\.logisti\.sa/.test(url);
            const failed = pendingReloadReason !== null;
            const errorPage = onOAuthCallback
              ? await withTimeout(isChromeErrorPage(), 2000, 'errpage').catch(() => false)
              : false;

            if (onOAuthCallback || failed) {
              if (!callbackSeenAt) callbackSeenAt = Date.now();
              const stuckLongEnough = Date.now() - callbackSeenAt > STUCK_RELOAD_MS;
              const shouldReload = (failed || errorPage || stuckLongEnough) && reloadCount < MAX_RELOADS;
              if (shouldReload) {
                reloadCount += 1;
                const reason = failed
                  ? `requestfailed=${pendingReloadReason}`
                  : errorPage
                  ? 'chrome error page'
                  : 'stuck on OAuth callback';
                pendingReloadReason = null;
                if (reloadCount >= GOTO_FALLBACK_AFTER && !gotoFallbackUsed) {
                  gotoFallbackUsed = true;
                  logStep('Post-login', `${reloadCount} reloads failed (${reason}) — navigating to bayan root for fresh SSO`);
                  await page
                    .goto('https://bayan.logisti.sa/', { waitUntil: 'domcontentloaded', timeout: RELOAD_TIMEOUT_MS })
                    .catch((e) => log('goto bayan root failed:', e?.message));
                } else {
                  logStep('Post-login', `${reason} ${reloadCount}/${MAX_RELOADS} — reloading`);
                  await page
                    .reload({ waitUntil: 'domcontentloaded', timeout: RELOAD_TIMEOUT_MS })
                    .catch((e) => log('reload failed:', e?.message));
                }
                callbackSeenAt = 0;
              }
            } else {
              callbackSeenAt = 0;
            }

            await delay(750);
          }
          throw new Error('Post-login state not reached (still on login/OTP page)');
        };
        await waitForPostLogin();
        logStep('Post-login', 'reached');

        await delay(1500);
        await throwIfServerOops(page, 'after login');

        logStep('Result', 'reading cookies and storage');
        let cookies = [];
        try {
          cookies = await page.cookies();
        } catch (e) {
          console.error('[Auth] page.cookies() failed:', e?.message);
          throw new Error('Failed to read cookies: ' + (e?.message ?? 'unknown'));
        }
        const cookieHeader = (cookies || []).map((c) => `${c?.name}=${c?.value}`).filter(Boolean).join('; ');
        const cookiesObj = {};
        (cookies || []).forEach((c) => {
          if (c?.name != null) cookiesObj[c.name] = c.value ?? '';
        });

        let response = { localStorage: {}, sessionStorage: {} };
        try {
          response = await page.evaluate(() => {
            const localStorage = {};
            const sessionStorage = {};
            try {
              for (let i = 0; i < window.localStorage.length; i++) {
                const key = window.localStorage.key(i);
                localStorage[key] = window.localStorage.getItem(key);
              }
              for (let i = 0; i < window.sessionStorage.length; i++) {
                const key = window.sessionStorage.key(i);
                sessionStorage[key] = window.sessionStorage.getItem(key);
              }
            } catch (_) {}
            return { localStorage, sessionStorage };
          });
        } catch (e) {
          log('page.evaluate(storage) failed, continuing without storage:', e?.message);
        }
        if (!response || typeof response !== 'object') {
          response = { localStorage: {}, sessionStorage: {} };
        }

        // Same logic as getAuthHeaders.js (raw values)
        let accessToken = null;
        const checkStorage = (storage) => {
          if (!storage) return;
          Object.keys(storage).forEach((key) => {
            const k = key.toLowerCase();
            if (k.includes('token') || k.includes('auth') || k.includes('bearer')) {
              const val = storage[key];
              if (val && k.includes('token')) {
                accessToken = typeof val === 'string' ? val : String(val);
              }
            }
          });
        };
        checkStorage(response.localStorage);
        if (!accessToken) checkStorage(response.sessionStorage);
        if (!accessToken && lastBearerToken) accessToken = lastBearerToken;
        log('Token source', accessToken ? 'localStorage/sessionStorage or request' : 'none');

        let userAgent = '';
        try {
          userAgent = await page.evaluate(() => navigator?.userAgent || '');
        } catch (_) {}
        const headers = {
          Cookie: cookieHeader,
          'User-Agent': userAgent || 'Mozilla/5.0',
          Referer: 'https://bayan.logisti.sa/',
          Origin: 'https://bayan.logisti.sa',
        };
        if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;

        await ctx.close().catch(() => {});

        const result = { cookie: cookiesObj, cookieHeader, accessToken, headers };
        const cookieCount = Object.keys(cookiesObj).length;
        logStep('Success', `cookies=${cookieCount}, accessToken=${accessToken ? 'yes' : 'no'}`);
        if (ttlMs > 0 || tryGetJwtExpMs(result?.accessToken)) {
          cachedAuth = result;
          cachedAtMs = Date.now();
          log('Cached result', { ttlMs });
          await persistAuthCache();
        }
        return result;
      } catch (e) {
        lastErr = e;
        console.error('[Auth] Attempt failed:', e?.message, e?.code || '');
        await ctx.close().catch(() => {});
        if (attempt < MAX_ATTEMPTS) {
          const backoff = 1500 * attempt;
          logStep('Retry', `backoff ${backoff}ms before attempt ${attempt + 1}`);
          await delay(backoff);
          continue;
        }
      }
    }

    console.error('[Auth] All attempts exhausted');
    throw lastErr ?? new Error('Login failed');
  } catch (error) {
    console.error('[Auth] getAuth failed:', error?.message);
    throw error;
  } finally {
    if (browser?.isConnected?.()) {
      await browser.close().catch((e) => console.error('[Auth] browser.close error:', e?.message));
    }
  }
  })();

  try {
    return await inFlightAuthPromise;
  } finally {
    inFlightAuthPromise = null;
  }
}

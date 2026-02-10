import puppeteer from 'puppeteer-core';
import { existsSync } from 'fs';
import { fetchOtpFromEmail } from './otpFetcher.js';

const log = (...args) => console.log('[Auth]', ...args);
const logStep = (step, detail = '') => console.log('[Auth]', `Step: ${step}`, detail ? `— ${detail}` : '');

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let cachedAuth = null;
let cachedAtMs = 0;

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
export async function getAuth() {
  log('getAuth() started');
  const ttlMs = Number(process.env.AUTH_CACHE_TTL_MS || 0);
  if (ttlMs > 0 && cachedAuth && Date.now() - cachedAtMs < ttlMs) {
    log('Using cached auth', { cacheAgeMs: Date.now() - cachedAtMs, ttlMs });
    return cachedAuth;
  }
  logStep('Cache', ttlMs > 0 ? `TTL=${ttlMs}ms, cache miss` : 'caching disabled');

  const IDENTITY_NUMBER = process.env.BAYAN_IDENTITY_NUMBER;
  const PASSWORD = process.env.BAYAN_PASSWORD;
  const OTP_SENDER = process.env.BAYAN_OTP_SENDER || 'NoReply@logisti.sa';
  const OTP_WAIT_MS = Number(process.env.OTP_WAIT_MS || 10000);
  const MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 3);
  logStep('Config', `OTP_SENDER=${OTP_SENDER}, OTP_WAIT_MS=${OTP_WAIT_MS}, MAX_ATTEMPTS=${MAX_ATTEMPTS}, credentials=${IDENTITY_NUMBER ? 'set' : 'missing'}`);

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
    const args = [
      '--no-first-run',
      '--no-zygote',
      '--disable-blink-features=AutomationControlled',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-software-rasterizer',
      '--disable-extensions',
    ];
    if (process.platform === 'linux') {
      args.push('--no-sandbox', '--disable-setuid-sandbox');
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
      page.on('request', (req) => {
        try {
          const h = req.headers?.() ?? {};
          const auth = h.authorization || h.Authorization;
          if (typeof auth === 'string' && auth.toLowerCase().startsWith('bearer ')) {
            lastBearerToken = auth.slice('bearer '.length).trim();
          }
        } catch (_) {
          // ignore
        }
      });

      try {
        logStep('Navigate', 'bayan.logisti.sa');
        await page.goto('https://bayan.logisti.sa/', { waitUntil: 'networkidle2', timeout: 30000 });
        logStep('Page load', 'waiting for app-root');
        await page.waitForSelector('app-root', { timeout: 15000 });
        await throwIfServerOops(page, 'landing');

        await delay(1500);
        logStep('Landing', 'waiting for .card');
        await page.waitForSelector('.card', { visible: true, timeout: 15000 });
        await throwIfServerOops(page, 'landing cards');

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
          await page.click('.column:first-child .card');
        }

        await delay(2500);
        await throwIfServerOops(page, 'after local carrier click');

        logStep('Login form', 'waiting for #Username, #password');
        await page.waitForSelector('#Username', { visible: true, timeout: 20000 });
        await page.waitForSelector('#password', { visible: true, timeout: 20000 });
        await throwIfServerOops(page, 'login page');

        logStep('Login form', 'filling credentials and Policy=Email');
        await page.type('#Username', IDENTITY_NUMBER, { delay: 80 });
        await page.type('#password', PASSWORD, { delay: 80 });
        await page.select('#Policy', 'Email');
        await delay(300);

        logStep('OTP baseline', 'getting latest message id before submit');
        let baselineOtpMsgId = null;
        try {
          const { getLatestMessageMeta } = await import('./otpFetcher.js');
          const meta = await getLatestMessageMeta(OTP_SENDER);
          baselineOtpMsgId = meta?.id ?? null;
          log('OTP baseline message id', baselineOtpMsgId ?? 'none');
        } catch (e) {
          log('OTP baseline fetch failed (will still try OTP)', e?.message);
        }

        logStep('Login', 'submit credentials');
        await page.click('button[type="submit"][value="login"]');
        logStep('OTP page', 'waiting for #TwoFactorCode1');
        await page.waitForSelector('#TwoFactorCode1', { visible: true, timeout: 25000 });
        await throwIfServerOops(page, 'otp page');

        logStep('OTP', `waiting ${OTP_WAIT_MS}ms for email then fetching OTP`);
        await delay(OTP_WAIT_MS);
        const otp = await fetchOtpFromEmail(OTP_SENDER, 30, 2000, 0, baselineOtpMsgId);
        if (!otp) {
          console.error('[Auth] OTP fetch returned empty');
          throw new Error('Failed to fetch OTP from email');
        }
        logStep('OTP', `received (length=${otp.length})`);

        const otpDigits = otp.split('');
        if (otpDigits.length < 4) {
          console.error('[Auth] OTP too short:', otp?.length);
          throw new Error(`OTP too short: ${otp}`);
        }
        logStep('OTP', 'typing digits into TwoFactorCode1-4');
        for (let i = 0; i < 4; i++) {
          const fieldId = `#TwoFactorCode${i + 1}`;
          await page.click(fieldId);
          await page.evaluate((id) => {
            document.querySelector(id).value = '';
          }, fieldId);
          await page.type(fieldId, otpDigits[i], { delay: 40 });
          await delay(150);
        }
        await delay(300);

        logStep('OTP', 'waiting for verify button enabled, then submit');
        await page.waitForFunction(
          () => {
            const btn = document.querySelector('button.verify-code');
            return btn && !btn.disabled;
          },
          { timeout: 10000 }
        );
        await page.click('button.verify-code[type="submit"]');

        logStep('Post-login', 'waiting for dashboard/session (up to 60s)');
        const waitForPostLogin = async (timeoutMs = 60000) => {
          const start = Date.now();
          while (Date.now() - start < timeoutMs) {
            await throwIfServerOops(page, 'post-login wait');
            let url = '';
            let cookies = [];
            try {
              url = page.url();
              cookies = await page.cookies();
            } catch (e) {
              await delay(750);
              continue;
            }
            const names = new Set((cookies || []).map((c) => c?.name).filter(Boolean));
            const hasDashboard = (await page.$('.sidebar-menu').catch(() => null)) != null;
            const hasSessionCookie = names.has('JSESSIONID') || names.has('TS01f96da1') || names.has('lang');
            const stillOnLogin = url.includes('/login') || (url.includes('#') && url.toLowerCase().includes('login'));
            if (hasDashboard || (hasSessionCookie && !stillOnLogin)) return;
            await delay(750);
          }
          throw new Error('Post-login state not reached (still on login/OTP page)');
        };
        await waitForPostLogin(60000);
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
        if (ttlMs > 0) {
          cachedAuth = result;
          cachedAtMs = Date.now();
          log('Cached result', { ttlMs });
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
}

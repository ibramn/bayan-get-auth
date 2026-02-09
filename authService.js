import puppeteer from 'puppeteer-core';
import { existsSync } from 'fs';
import { fetchOtpFromEmail } from './otpFetcher.js';

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
  if (await detectServerOops(page)) {
    const screenshot = `bayan-server-oops-${Date.now()}.png`;
    await page.screenshot({ path: screenshot, fullPage: true }).catch(() => {});
    const err = new Error(`Bayan server error page at: ${where}`);
    err.debugScreenshot = screenshot;
    err.code = 'BAYAN_SERVER_OOPS';
    throw err;
  }
}

function firstExistingPath(paths) {
  for (const p of paths) {
    if (p && existsSync(p)) return p;
  }
  return null;
}

function getBrowserExecutablePath() {
  // Allow override for headless servers (e.g. Amazon Linux) where Chrome is in a custom path
  const envPath = process.env.PUPPETEER_EXECUTABLE_PATH;
  if (envPath && existsSync(envPath)) return envPath;

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
  const ttlMs = Number(process.env.AUTH_CACHE_TTL_MS || 0);
  if (ttlMs > 0 && cachedAuth && Date.now() - cachedAtMs < ttlMs) {
    return cachedAuth;
  }

  const IDENTITY_NUMBER = process.env.BAYAN_IDENTITY_NUMBER;
  const PASSWORD = process.env.BAYAN_PASSWORD;
  const OTP_SENDER = process.env.BAYAN_OTP_SENDER || 'NoReply@logisti.sa';
  const OTP_WAIT_MS = Number(process.env.OTP_WAIT_MS || 10000);
  const MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 3);

  if (!IDENTITY_NUMBER || !PASSWORD) {
    throw new Error('Missing BAYAN_IDENTITY_NUMBER or BAYAN_PASSWORD in environment');
  }

  const executablePath = getBrowserExecutablePath();
  if (!executablePath) {
    throw new Error(
      'Chrome/Chromium/Edge not found. Install a supported browser, or set PUPPETEER_EXECUTABLE_PATH and use it here.'
    );
  }

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
      // Default back to headless (set HEADLESS=false to see the browser)
      headless: process.env.HEADLESS !== 'false',
      args,
      defaultViewport: null,
      ignoreHTTPSErrors: true,
      timeout: 60000,
      executablePath,
    });
  } catch (err) {
    throw new Error('Failed to launch browser: ' + err.message);
  }

  try {
    let lastErr = null;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
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
        await page.goto('https://bayan.logisti.sa/', { waitUntil: 'networkidle2', timeout: 30000 });
        await page.waitForSelector('app-root', { timeout: 15000 });
        await throwIfServerOops(page, 'landing');

        await delay(1500);
        await page.waitForSelector('.card', { visible: true, timeout: 15000 });
        await throwIfServerOops(page, 'landing cards');

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

        await page.waitForSelector('#Username', { visible: true, timeout: 20000 });
        await page.waitForSelector('#password', { visible: true, timeout: 20000 });
        await throwIfServerOops(page, 'login page');

        await page.type('#Username', IDENTITY_NUMBER, { delay: 80 });
        await page.type('#password', PASSWORD, { delay: 80 });
        await page.select('#Policy', 'Email');
        await delay(300);

        // Capture baseline email ID BEFORE triggering OTP (so we can wait for a NEW email)
        let baselineOtpMsgId = null;
        try {
          const { getLatestMessageMeta } = await import('./otpFetcher.js');
          const meta = await getLatestMessageMeta(OTP_SENDER);
          baselineOtpMsgId = meta?.id ?? null;
        } catch (_) {}

        await page.click('button[type="submit"][value="login"]');
        await page.waitForSelector('#TwoFactorCode1', { visible: true, timeout: 25000 });
        await throwIfServerOops(page, 'otp page');

        // Give Bayan time to send OTP email
        await delay(OTP_WAIT_MS);
        // Simple mode: always read the latest email from sender and extract OTP
        // Wait for a NEW OTP email (by messageId) and then extract OTP from that newest message.
        const otp = await fetchOtpFromEmail(OTP_SENDER, 30, 2000, 0, baselineOtpMsgId);
        if (!otp) throw new Error('Failed to fetch OTP from email');

        const otpDigits = otp.split('');
        if (otpDigits.length < 4) throw new Error(`OTP too short: ${otp}`);
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

        await page.waitForFunction(
          () => {
            const btn = document.querySelector('button.verify-code');
            return btn && !btn.disabled;
          },
          { timeout: 10000 }
        );
        await page.click('button.verify-code[type="submit"]');

        // Wait until we are REALLY logged in (dashboard OR session cookies)
        const waitForPostLogin = async (timeoutMs = 60000) => {
          const start = Date.now();
          while (Date.now() - start < timeoutMs) {
            await throwIfServerOops(page, 'post-login wait');
            const url = page.url();
            const cookies = await page.cookies();
            const names = new Set(cookies.map((c) => c.name));
            const hasDashboard = (await page.$('.sidebar-menu').catch(() => null)) != null;
            const hasSessionCookie = names.has('JSESSIONID') || names.has('TS01f96da1') || names.has('lang');
            const stillOnLogin = url.includes('/login') || (url.includes('#') && url.toLowerCase().includes('login'));
            if (hasDashboard || (hasSessionCookie && !stillOnLogin)) return;
            await delay(750);
          }
          throw new Error('Post-login state not reached (still on login/OTP page)');
        };
        await waitForPostLogin(60000);

        await delay(1500);
        await throwIfServerOops(page, 'after login');

        const cookies = await page.cookies();
        const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
        const cookiesObj = {};
        cookies.forEach((c) => {
          cookiesObj[c.name] = c.value;
        });

        const response = await page.evaluate(() => {
          const localStorage = {};
          const sessionStorage = {};
          for (let i = 0; i < window.localStorage.length; i++) {
            const key = window.localStorage.key(i);
            localStorage[key] = window.localStorage.getItem(key);
          }
          for (let i = 0; i < window.sessionStorage.length; i++) {
            const key = window.sessionStorage.key(i);
            sessionStorage[key] = window.sessionStorage.getItem(key);
          }
          return { localStorage, sessionStorage };
        });

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

        const userAgent = await page.evaluate(() => navigator.userAgent);
        const headers = {
          Cookie: cookieHeader,
          'User-Agent': userAgent,
          Referer: 'https://bayan.logisti.sa/',
          Origin: 'https://bayan.logisti.sa',
        };
        if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;

        await ctx.close().catch(() => {});

        const result = { cookie: cookiesObj, cookieHeader, accessToken, headers };
        if (ttlMs > 0) {
          cachedAuth = result;
          cachedAtMs = Date.now();
        }
        return result;
      } catch (e) {
        lastErr = e;
        await ctx.close().catch(() => {});
        // Retry only on Bayan server error page (or first attempt generic flake)
        if (attempt < MAX_ATTEMPTS) {
          await delay(1500 * attempt);
          continue;
        }
      }
    }

    throw lastErr ?? new Error('Login failed');
  } catch (error) {
    if (browser && browser.isConnected()) {
      await browser.close().catch(() => {});
    }
    throw error;
  }
}

// Browser-free Bayan auth — drives the IAM (iam.logisti.sa) OpenID Connect authorization-code + PKCE
// flow over plain HTTP, no Puppeteer/Chrome. Replicates the ASP.NET Core Identity login form posts
// (Username → Password+Policy → email OTP), then exchanges the code at /connect/token.
//
// Returns the same shape as authService.getAuth(): { cookie, cookieHeader, accessToken, headers }.
//
// Reuses the existing Microsoft Graph OTP fetch (otpFetcher.js). The OTP form field name is
// auto-detected from the live page, since it can't be inspected without first triggering an OTP.

import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fetchOtpFromEmail, getLatestMessageMeta } from './otpFetcher.js';

const log = (...a) => console.log('[AuthHTTP]', ...a);
const logStep = (step, detail = '') => console.log('[AuthHTTP]', `Step: ${step}`, detail ? `— ${detail}` : '');

const UA =
  process.env.HTTP_AUTH_UA ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function base64Url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── tiny single-host cookie jar ───────────────────────────────────────────────
class CookieJar {
  constructor() {
    this.cookies = new Map();
  }
  absorb(res) {
    const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    for (const sc of list) {
      const first = (sc.split(';')[0] || '').trim();
      const eq = first.indexOf('=');
      if (eq < 0) continue;
      const name = first.slice(0, eq).trim();
      const value = first.slice(eq + 1).trim();
      if (!name) continue;
      if (value === '' || /expires=Thu, 01 Jan 1970/i.test(sc)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }
  header() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

async function request(jar, url, { method = 'GET', body = null, referer = null } = {}) {
  const headers = {
    'User-Agent': UA,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
  };
  const cookie = jar.header();
  if (cookie) headers.Cookie = cookie;
  if (referer) headers.Referer = referer;
  if (body != null) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    headers.Origin = new URL(url).origin;
  }
  const res = await fetch(url, { method, headers, body, redirect: 'manual' });
  jar.absorb(res);
  return res;
}

function appHost() {
  try {
    return new URL(process.env.BAYAN_REDIRECT_URI || 'https://bayan.logisti.sa/#/login').host;
  } catch {
    return 'bayan.logisti.sa';
  }
}

function extractCode(u) {
  try {
    const url = new URL(u);
    const fromQuery = url.searchParams.get('code');
    if (fromQuery) return fromQuery;
    if (url.hash) {
      const frag = url.hash.replace(/^#/, '');
      const qs = frag.includes('?') ? frag.slice(frag.indexOf('?') + 1) : frag;
      const code = new URLSearchParams(qs).get('code');
      if (code) return code;
    }
  } catch {
    /* ignore */
  }
  return null;
}

// Follow 3xx hops (manually, carrying cookies) until a non-redirect, or until we're sent to the SPA
// host carrying the authorization code. Returns the final response + URL + body text.
async function follow(jar, startUrl, opts = {}, maxHops = 12) {
  let url = startUrl;
  let method = opts.method || 'GET';
  let body = opts.body ?? null;
  let referer = opts.referer ?? null;

  for (let i = 0; i < maxHops; i++) {
    const res = await request(jar, url, { method, body, referer });
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      const next = new URL(loc, url).toString();
      if (new URL(next).host === appHost()) {
        return { res, url: next, html: '', toApp: true, code: extractCode(next) };
      }
      referer = url;
      url = next;
      method = 'GET';
      body = null;
      continue;
    }
    const html = await res.text();
    return { res, url, html, toApp: false, code: null };
  }
  throw new Error('AuthHTTP: too many redirects');
}

// ── HTML form helpers (regex; the IAM forms are stable ASP.NET Identity markup) ──
function sliceFormContaining(html, marker) {
  const idx = html.indexOf(marker);
  if (idx < 0) return html;
  const start = html.lastIndexOf('<form', idx);
  const end = html.indexOf('</form>', idx);
  if (start < 0 || end < 0) return html;
  return html.slice(start, end + 7);
}

// Resolve a form's POST target. An empty/absent action means "submit to the current document URL"
// — which carries the ?ReturnUrl=… that ties the login back to the authorize request. Dropping it
// makes IAM lose the OIDC context and bounce to /home/error.
function resolveFormTarget(formHtml, pageUrl) {
  const action = formHtml.match(/<form[^>]*\baction=["']([^"']*)["']/i)?.[1];
  return action && action.trim() ? new URL(action, pageUrl).toString() : pageUrl;
}

// HTML-decode form values — critically ReturnUrl, whose &amp; entities otherwise corrupt the OIDC
// callback URL and bounce IAM to /home/error.
function decodeEntities(s) {
  return String(s ?? '')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#x2F;/gi, '/')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

function formFields(formHtml) {
  const fields = {};
  const re = /<input\b[^>]*>/gi;
  let m;
  while ((m = re.exec(formHtml))) {
    const tag = m[0];
    const name = tag.match(/\bname=["']([^"']+)["']/i)?.[1];
    if (!name) continue;
    const value = decodeEntities(tag.match(/\bvalue=["']([^"']*)["']/i)?.[1] ?? '');
    const type = (tag.match(/\btype=["']([^"']+)["']/i)?.[1] || 'text').toLowerCase();
    if (type === 'radio' || type === 'checkbox') {
      if (/\bchecked\b/i.test(tag)) fields[name] = value || 'on';
      continue; // unchecked options are set explicitly by the caller
    }
    fields[name] = value;
  }
  return fields;
}

/**
 * Browser-free Bayan auth via OIDC code + PKCE.
 * @returns {Promise<{ cookie: string, cookieHeader: string, accessToken: string|null, headers: object }>}
 */
export async function getAuthHttp() {
  logStep('getAuthHttp() started');

  const IDENTITY = process.env.BAYAN_IDENTITY_NUMBER;
  const PASSWORD = process.env.BAYAN_PASSWORD;
  const OTP_SENDER = process.env.BAYAN_OTP_SENDER || 'NoReply@logisti.sa';
  if (!IDENTITY || !PASSWORD) throw new Error('BAYAN_IDENTITY_NUMBER and BAYAN_PASSWORD are required');

  const clientId = process.env.BAYAN_CLIENT_ID || 'bayanClient';
  const scope = process.env.BAYAN_AUTHORIZE_SCOPE || 'profile email roles openid';
  const redirectUri = process.env.BAYAN_REDIRECT_URI || 'https://bayan.logisti.sa/#/login';
  const uiLocales = process.env.BAYAN_UI_LOCALES || 'en';
  const otpPolicy = process.env.BAYAN_OTP_POLICY || 'Email';

  let authorizeEndpoint = 'https://iam.logisti.sa/connect/authorize';
  let tokenEndpoint = 'https://iam.logisti.sa/connect/token';
  try {
    const disc = JSON.parse(await readFile(process.env.OPENID_FILE || './openid.json', 'utf8'));
    if (disc.authorization_endpoint) authorizeEndpoint = disc.authorization_endpoint;
    if (disc.token_endpoint) tokenEndpoint = disc.token_endpoint;
  } catch {
    /* keep defaults */
  }

  // PKCE — verifier is kept for the token exchange (this flow does its own code→token swap).
  const codeVerifier = base64Url(randomBytes(32));
  const codeChallenge = base64Url(createHash('sha256').update(codeVerifier).digest());
  const authorizeUrl =
    `${authorizeEndpoint}?` +
    new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      state: base64Url(randomBytes(16)),
      redirect_uri: redirectUri,
      scope,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      nonce: base64Url(randomBytes(16)),
      ui_locales: uiLocales,
    });

  const jar = new CookieJar();

  // 1) authorize → IAM login page
  logStep('authorize', 'GET /connect/authorize → IAM login');
  const landing = await follow(jar, authorizeUrl);
  if (landing.toApp && landing.code) {
    logStep('SSO', 'existing IAM session — code issued without login');
    return finalize(jar, tokenEndpoint, landing.code, { clientId, redirectUri, codeVerifier });
  }
  if (!/name=["']Username["']/i.test(landing.html)) {
    throw new Error(`AuthHTTP: login form not found (landed ${landing.url}). First 300 chars: ${landing.html.slice(0, 300)}`);
  }

  // 2) submit credentials (Username + Password + OTP delivery Policy) in one post
  const loginForm = sliceFormContaining(landing.html, 'name="Username"');
  const loginAction = resolveFormTarget(loginForm, landing.url);
  const loginFields = formFields(loginForm);
  loginFields.Username = IDENTITY;
  loginFields.Password = PASSWORD;
  loginFields.Policy = otpPolicy; // Email vs SMS OTP delivery
  if (!('RememberLogin' in loginFields)) loginFields.RememberLogin = 'false';

  // OTP email baseline so we only accept a code that arrives AFTER we submit.
  let baselineOtpId = null;
  try {
    baselineOtpId = (await getLatestMessageMeta(OTP_SENDER))?.id ?? null;
  } catch (e) {
    log('OTP baseline fetch failed (continuing):', e?.message);
  }
  log('OTP baseline message id', baselineOtpId ?? 'none');

  logStep('credentials', `POST ${loginAction} (Policy=${otpPolicy})`);
  let step = await follow(jar, loginAction, {
    method: 'POST',
    body: new URLSearchParams(loginFields).toString(),
    referer: landing.url,
  });

  if (step.toApp && step.code) {
    logStep('no-2fa', 'code issued right after credentials');
    return finalize(jar, tokenEndpoint, step.code, { clientId, redirectUri, codeVerifier });
  }

  // 3) OTP page — locate the verification form and its (auto-detected) code field(s)
  if (!looksLikeOtpPage(step.html)) {
    throw new Error(`AuthHTTP: expected OTP page after credentials (landed ${step.url}). Snippet: ${textSnippet(step.html)}`);
  }
  const otpForm = sliceFormContaining(step.html, '__RequestVerificationToken');
  const otpAction = resolveFormTarget(otpForm, step.url);
  const otpFields = formFields(otpForm);
  const codeFieldNames = detectOtpFields(otpForm);
  logStep('OTP page', `action=${otpAction} fields=${JSON.stringify(Object.keys(otpFields))} otpField(s)=${JSON.stringify(codeFieldNames)}`);

  // 4) fetch the OTP from email (only newer than baseline)
  const retries = Number(process.env.OTP_FETCH_RETRIES || 35);
  const delayMs = Number(process.env.OTP_FETCH_DELAY_MS || 2000);
  logStep('OTP fetch', `polling email from ${OTP_SENDER}`);
  const otp = await fetchOtpFromEmail(OTP_SENDER, retries, delayMs, 5, baselineOtpId);
  if (!otp) throw new Error('AuthHTTP: OTP not received from email');
  const digits = String(otp).replace(/\D/g, '');
  log('OTP obtained', `${digits.length} digits`);

  // 5) submit the OTP
  if (codeFieldNames.length <= 1) {
    otpFields[codeFieldNames[0] || 'Input.Code'] = digits;
  } else {
    // split single-digit-per-field forms (e.g. TwoFactorCode1..N)
    codeFieldNames.forEach((n, i) => (otpFields[n] = digits[i] ?? ''));
  }
  logStep('verify OTP', `POST ${otpAction}`);
  const verified = await follow(jar, otpAction, {
    method: 'POST',
    body: new URLSearchParams(otpFields).toString(),
    referer: step.url,
  });

  let code = verified.toApp ? verified.code : null;
  if (!code) {
    // Some IAM variants 200 back to a continue page; try to find a code or a resume link.
    code = extractCode(verified.url);
  }
  if (!code) {
    throw new Error(`AuthHTTP: no authorization code after OTP (landed ${verified.url}). Snippet: ${textSnippet(verified.html)}`);
  }

  return finalize(jar, tokenEndpoint, code, { clientId, redirectUri, codeVerifier });
}

function looksLikeOtpPage(html) {
  return /VerifyOtp|TwoFactor|LoginWith2fa|otp|one[- ]?time|رمz|رمز|التحقق/i.test(html) &&
    /name=["'][^"']*(Code|Otp|TwoFactor)[^"']*["']/i.test(html);
}

function detectOtpFields(formHtml) {
  const names = [];
  const re = /<input\b[^>]*\bname=["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = re.exec(formHtml))) {
    const name = m[1];
    if (name === '__RequestVerificationToken') continue;
    if (/(code|otp|twofactor|pin)/i.test(name)) names.push(name);
  }
  // Prefer single combined field; else the per-digit set in document order.
  const single = names.find((n) => !/\d$/.test(n));
  if (single && names.length > 1 && names.every((n) => n === single)) return [single];
  return names.length ? names : ['Input.Code'];
}

function textSnippet(html) {
  return String(html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 300);
}

async function finalize(jar, tokenEndpoint, code, { clientId, redirectUri, codeVerifier }) {
  logStep('token', 'POST /connect/token (authorization_code + PKCE)');
  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'User-Agent': UA,
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      ...(jar.header() ? { Cookie: jar.header() } : {}),
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier,
    }).toString(),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`AuthHTTP: token endpoint returned non-JSON (${res.status}): ${text.slice(0, 200)}`);
  }
  if (!res.ok || !json.access_token) {
    throw new Error(`AuthHTTP: token exchange failed (${res.status}): ${json.error || ''} ${json.error_description || ''}`.trim());
  }

  const accessToken = json.access_token;
  const cookieHeader = jar.header();
  logStep('done', `access token (${accessToken.length} chars), ${jar.cookies.size} cookies`);
  return {
    cookie: cookieHeader,
    cookieHeader,
    accessToken,
    headers: {
      ...(cookieHeader ? { Cookie: cookieHeader } : {}),
      Authorization: `Bearer ${accessToken}`,
    },
  };
}

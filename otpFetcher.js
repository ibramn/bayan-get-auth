import 'dotenv/config';
import { ClientSecretCredential } from '@azure/identity';
import { Client } from '@microsoft/microsoft-graph-client';
import { TokenCredentialAuthenticationProvider } from '@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials/index.js';
import { extractOtp } from './otpUtils.js';

const DEBUG = process.env.DEBUG_OTP === 'true';
const dlog = (...args) => {
  if (DEBUG) console.log('[OTP_DEBUG]', ...args);
};
const log = (...args) => console.log('[OTP]', ...args);

const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;
const clientSecret = process.env.AZURE_CLIENT_SECRET;
const userEmail = process.env.USER_EMAIL;

let graphClient = null;

function getGraphClient() {
  if (graphClient) {
    log('Graph client reused');
    return graphClient;
  }
  log('Initializing Microsoft Graph client');
  const t = typeof tenantId === 'string' ? tenantId.trim() : '';
  const c = typeof clientId === 'string' ? clientId.trim() : '';
  const s = typeof clientSecret === 'string' ? clientSecret.trim() : '';
  const u = typeof userEmail === 'string' ? userEmail.trim() : '';
  if (!t || !c || !s || !u) {
    console.error('[OTP] Missing env: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, USER_EMAIL');
    throw new Error('Missing: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, USER_EMAIL');
  }
  try {
    const credential = new ClientSecretCredential(t, c, s);
    const authProvider = new TokenCredentialAuthenticationProvider(credential, {
      scopes: ['https://graph.microsoft.com/.default'],
    });
    graphClient = Client.initWithMiddleware({ authProvider });
    log('Graph client ready', { userEmail: u });
    return graphClient;
  } catch (e) {
    console.error('[OTP] Graph client init failed:', e?.message);
    throw e;
  }
}

function getFromAddress(msg) {
  return (msg?.from?.emailAddress?.address || msg?.sender?.emailAddress?.address || '').trim();
}

function matchSender(addr, wanted) {
  const a = (addr || '').trim().toLowerCase();
  const w = (wanted || '').trim().toLowerCase();
  if (!a || !w) return false;
  if (a === w) return true;
  // Fallback: sometimes tenant normalizes casing/aliases
  if (a.includes(w)) return true;
  const domain = w.includes('@') ? w.split('@')[1] : '';
  if (domain && a.endsWith(`@${domain}`)) return true;
  return false;
}

async function fetchMessages(client, { folder, top = 25, filter, orderBy, select }) {
  if (!client?.api) return [];
  try {
    const path = folder
      ? `/users/${userEmail}/mailFolders/${folder}/messages`
      : `/users/${userEmail}/messages`;
    let req = client.api(path).top(Math.min(Number(top) || 25, 200)).select(select || 'id,subject,receivedDateTime,from,sender,bodyPreview');
    if (filter) req = req.filter(filter);
    if (orderBy) req = req.orderby(orderBy);
    const res = await req.get();
    const list = res?.value;
    return Array.isArray(list) ? list : [];
  } catch (e) {
    log('fetchMessages failed', folder || 'messages', e?.message);
    return [];
  }
}

async function getLatestMessageFrom(fromAddress, client) {
  const wanted = (fromAddress || '').trim().toLowerCase();
  // NOTE: We do NOT rely on Graph's server-side "from =" filter because it can be brittle
  // (aliases/casing/display differences). We fetch newest emails and match locally.
  try {
    dlog('USER_EMAIL (mailbox being read):', userEmail);
    dlog('Sender requested:', fromAddress);

    const selectFields = 'id,subject,receivedDateTime,from,sender,bodyPreview';
    const orderBy = 'receivedDateTime desc';

    // Prefer Inbox, then Junk, then All. Always match locally (case-insensitive).
    const pickLatestMatch = (msgs, label) => {
      const match = msgs.find((m) => matchSender(getFromAddress(m), wanted));
      dlog(`${label} checked=${msgs.length} matched=${match ? 1 : 0}`);
      return match ?? null;
    };

    const inbox = await fetchMessages(client, { folder: 'inbox', top: 100, filter: null, orderBy, select: selectFields });
    const inboxMatch = pickLatestMatch(inbox, 'Inbox');
    if (inboxMatch) return inboxMatch;

    const junk = await fetchMessages(client, { folder: 'junkemail', top: 100, filter: null, orderBy, select: selectFields });
    const junkMatch = pickLatestMatch(junk, 'JunkEmail');
    if (junkMatch) return junkMatch;

    const all = await fetchMessages(client, { folder: null, top: 200, filter: null, orderBy, select: selectFields });
    const allMatch = pickLatestMatch(all, 'All');
    return allMatch;
  } catch (e) {
    const msg = e?.message ?? '';
    // Orderby can fail on some tenants. Fallback: fetch without orderby and sort locally.
    if (!msg.includes('restriction or sort order is too complex')) throw e;
    dlog('Graph complained about sort/filter complexity; fetching without orderby and sorting locally.');
    const selectFields = 'id,subject,receivedDateTime,from,sender,bodyPreview';
    const recent = await fetchMessages(client, { folder: null, top: 200, filter: null, orderBy: null, select: selectFields });
    const sorted = recent.slice().sort((a, b) => new Date(b.receivedDateTime) - new Date(a.receivedDateTime));
    return sorted.find((m) => matchSender(getFromAddress(m), wanted)) ?? null;
  }
}

async function getMessageBodyById(messageId, client) {
  if (!messageId || !client?.api) return null;
  try {
    return await client
      .api(`/users/${userEmail}/messages/${messageId}`)
      .select('id,subject,receivedDateTime,from,sender,body,bodyPreview')
      .get();
  } catch (e) {
    log('getMessageBodyById failed', messageId, e?.message);
    return null;
  }
}

export async function getLatestMessageMeta(fromAddress = 'NoReply@logisti.sa') {
  const from = typeof fromAddress === 'string' ? fromAddress.trim() : 'NoReply@logisti.sa';
  log('getLatestMessageMeta', { fromAddress: from });
  try {
    const client = getGraphClient();
    const msg = await getLatestMessageFrom(from, client);
    if (!msg) {
      log('getLatestMessageMeta: no message found');
      return null;
    }
    const meta = {
      id: msg.id,
      from: getFromAddress(msg),
      receivedDateTime: msg.receivedDateTime,
      subject: (msg.subject || '').slice(0, 500),
    };
    log('getLatestMessageMeta: found', { id: meta.id, subject: meta.subject?.slice(0, 50) });
    return meta;
  } catch (e) {
    console.error('[OTP] getLatestMessageMeta failed:', e?.message);
    return null;
  }
}

/**
 * Fetch OTP from the latest email (simple mode).
 * Retries until the latest email contains an OTP and is recent enough.
 */
export async function fetchOtpFromEmail(
  fromAddress = 'NoReply@logisti.sa',
  retries = 5,
  delayMs = 2000,
  maxAgeMinutes = 2,
  afterMessageId = null
) {
  const from = typeof fromAddress === 'string' ? fromAddress.trim() : 'NoReply@logisti.sa';
  const maxRetries = Math.min(Math.max(1, Number(retries) || 5), 50);
  const delay = Math.min(Math.max(500, Number(delayMs) || 2000), 60000);
  const maxAgeMin = Number(maxAgeMinutes);
  log('fetchOtpFromEmail started', { fromAddress: from, retries: maxRetries, delayMs: delay, maxAgeMinutes: maxAgeMin, afterMessageId: afterMessageId ?? 'none' });
  let client;
  try {
    client = getGraphClient();
  } catch (e) {
    console.error('[OTP] fetchOtpFromEmail getGraphClient failed:', e?.message);
    return null;
  }
  const maxAge = (Number.isFinite(maxAgeMin) && maxAgeMin > 0 ? maxAgeMin : 2) * 60 * 1000;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const startTime = Date.now();
      log('fetchOtpFromEmail attempt', `${attempt}/${maxRetries}`);
      dlog(`Attempt ${attempt}/${maxRetries}…`);
      const msg = await getLatestMessageFrom(from, client);

      if (msg) {
        if (afterMessageId && msg.id === afterMessageId) {
          dlog('Latest message is still the baseline id; waiting for a newer email…', { afterMessageId });
          if (attempt < retries) await new Promise((r) => setTimeout(r, delayMs));
          continue;
        }

        const from =
          (msg.from?.emailAddress?.address || msg.sender?.emailAddress?.address || '').trim();
        const msgTime = new Date(msg.receivedDateTime).getTime();
        const age = startTime - msgTime;
        dlog('Latest matched message:', {
          id: msg.id,
          from,
          receivedDateTime: msg.receivedDateTime,
          ageSeconds: Math.round(age / 1000),
          subject: msg.subject || '',
        });
        const subject = msg.subject || '';
        const preview = msg.bodyPreview || '';
        dlog('Preview (first 200 chars):', preview.slice(0, 200).replace(/\s+/g, ' '));
        // If maxAgeMinutes <= 0, accept any age. Otherwise enforce it.
        if (!Number.isFinite(maxAgeMin) || maxAgeMin <= 0 || age <= maxAge) {
          let otp = extractOtp(subject) || extractOtp(preview);
          dlog('OTP from subject/preview:', otp);

          if (!otp || DEBUG) {
            const full = await getMessageBodyById(msg.id, client);
            const bodyContent =
              (full?.body?.contentType === 'text' ? full.body?.content : '') ||
              (full?.body?.contentType === 'html' ? full.body?.content : '') ||
              '';
            if (DEBUG) {
              dlog(`Body contentType=${full?.body?.contentType} length=${bodyContent.length}`);
              dlog('Body snippet (first 400 chars):', bodyContent.slice(0, 400).replace(/\s+/g, ' '));
            }
            otp = otp || extractOtp(subject) || extractOtp(preview) || extractOtp(bodyContent);
            dlog('OTP after reading full body:', otp);
          }

          if (otp) {
            log('fetchOtpFromEmail success', { attempt, otpLength: otp.length });
            return otp;
          }
        } else {
          log('fetchOtpFromEmail message too old', { maxAgeMinutes: maxAgeMin });
          dlog(`Message too old (>${maxAgeMin} min).`);
        }
      } else {
        log('fetchOtpFromEmail no message from sender');
        dlog('No message matched the sender filter.');
      }

      if (attempt < maxRetries) {
        log('fetchOtpFromEmail retry in', delay, 'ms');
        await new Promise((r) => setTimeout(r, delay));
      }
    } catch (error) {
      console.error('[OTP] fetchOtpFromEmail attempt failed:', error?.message || error);
      dlog('OTP fetch attempt failed:', error?.message || error);
      if (attempt < maxRetries) await new Promise((r) => setTimeout(r, delay));
    }
  }
  log('fetchOtpFromEmail exhausted retries, returning null');
  return null;
}

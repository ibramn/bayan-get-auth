import 'dotenv/config';
import { ClientSecretCredential } from '@azure/identity';
import { Client } from '@microsoft/microsoft-graph-client';
import { TokenCredentialAuthenticationProvider } from '@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials/index.js';
import { extractOtp } from './otpUtils.js';

const DEBUG = process.env.DEBUG_OTP === 'true';
const dlog = (...args) => {
  if (DEBUG) console.log('[DEBUG_OTP]', ...args);
};

const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;
const clientSecret = process.env.AZURE_CLIENT_SECRET;
const userEmail = process.env.USER_EMAIL;

let graphClient = null;

function getGraphClient() {
  if (graphClient) return graphClient;
  if (!tenantId || !clientId || !clientSecret || !userEmail) {
    throw new Error('Missing: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, USER_EMAIL');
  }
  const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
  const authProvider = new TokenCredentialAuthenticationProvider(credential, {
    scopes: ['https://graph.microsoft.com/.default'],
  });
  graphClient = Client.initWithMiddleware({ authProvider });
  return graphClient;
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
  const path = folder
    ? `/users/${userEmail}/mailFolders/${folder}/messages`
    : `/users/${userEmail}/messages`;
  let req = client.api(path).top(top).select(select);
  if (filter) req = req.filter(filter);
  if (orderBy) req = req.orderby(orderBy);
  const res = await req.get();
  return res?.value ?? [];
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
  return await client
    .api(`/users/${userEmail}/messages/${messageId}`)
    .select('id,subject,receivedDateTime,from,sender,body,bodyPreview')
    .get();
}

export async function getLatestMessageMeta(fromAddress = 'NoReply@logisti.sa') {
  const client = getGraphClient();
  const msg = await getLatestMessageFrom(fromAddress, client);
  if (!msg) return null;
  return {
    id: msg.id,
    from: getFromAddress(msg),
    receivedDateTime: msg.receivedDateTime,
    subject: msg.subject || '',
  };
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
  const client = getGraphClient();
  const maxAge = maxAgeMinutes * 60 * 1000;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const startTime = Date.now();
      dlog(`Attempt ${attempt}/${retries}…`);
      const msg = await getLatestMessageFrom(fromAddress, client);

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
        if (!Number.isFinite(maxAgeMinutes) || maxAgeMinutes <= 0 || age <= maxAge) {
          // Try subject/preview first
          let otp = extractOtp(subject) || extractOtp(preview);
          dlog('OTP from subject/preview:', otp);

          // Fallback: fetch full body
          // For DEBUG_OTP, always fetch body once so you can see content.
          if (!otp || DEBUG) {
            const full = await getMessageBodyById(msg.id, client);
            const bodyContent =
              (full.body?.contentType === 'text' ? full.body?.content : '') ||
              (full.body?.contentType === 'html' ? full.body?.content : '') ||
              '';
            if (DEBUG) {
              dlog(`Body contentType=${full.body?.contentType} length=${bodyContent.length}`);
              dlog('Body snippet (first 400 chars):', bodyContent.slice(0, 400).replace(/\s+/g, ' '));
            }
            otp = otp || extractOtp(subject) || extractOtp(preview) || extractOtp(bodyContent);
            dlog('OTP after reading full body:', otp);
          }

          if (otp) return otp;
        } else {
          dlog(`Message too old (>${maxAgeMinutes} min).`);
        }
      } else {
        dlog('No message matched the sender filter.');
      }

      if (attempt < retries) await new Promise((r) => setTimeout(r, delayMs));
    } catch (error) {
      dlog('OTP fetch attempt failed:', error?.message || error);
      if (attempt < retries) await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  return null;
}

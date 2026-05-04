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

/**
 * Newest-first messages from `fromAddress` merged across Inbox + Junk (same sender can
 * appear in both; Inbox-only "latest" used to hide a newer Junk OTP).
 */
async function getRecentMessagesFromSender(fromAddress, client, topPerFolder = 80, maxMerged = 40) {
  const wanted = (fromAddress || '').trim().toLowerCase();
  const selectFields = 'id,subject,receivedDateTime,from,sender,bodyPreview';
  const orderBy = 'receivedDateTime desc';
  const folders = ['inbox', 'junkemail'];

  const lists = await Promise.all(
    folders.map((folder) =>
      fetchMessages(client, { folder, top: topPerFolder, filter: null, orderBy, select: selectFields })
    )
  );

  const seen = new Set();
  const merged = [];
  for (const list of lists) {
    for (const m of list) {
      if (!m?.id || seen.has(m.id)) continue;
      if (!matchSender(getFromAddress(m), wanted)) continue;
      seen.add(m.id);
      merged.push(m);
    }
  }
  merged.sort((a, b) => new Date(b.receivedDateTime) - new Date(a.receivedDateTime));
  dlog('merged inbox+junk from sender', { count: merged.length, wanted });
  return merged.slice(0, maxMerged);
}

async function getLatestMessageFrom(fromAddress, client) {
  const wanted = (fromAddress || '').trim().toLowerCase();
  try {
    dlog('USER_EMAIL (mailbox being read):', userEmail);
    dlog('Sender requested:', fromAddress);

    const merged = await getRecentMessagesFromSender(fromAddress, client, 100, 50);
    if (merged.length) return merged[0];

    const selectFields = 'id,subject,receivedDateTime,from,sender,bodyPreview';
    const orderBy = 'receivedDateTime desc';
    const all = await fetchMessages(client, { folder: null, top: 200, filter: null, orderBy, select: selectFields });
    const allMatch =
      all.filter((m) => matchSender(getFromAddress(m), wanted)).sort(
        (a, b) => new Date(b.receivedDateTime) - new Date(a.receivedDateTime)
      )[0] ?? null;
    return allMatch;
  } catch (e) {
    const msg = e?.message ?? '';
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
      const messages = await getRecentMessagesFromSender(from, client, 100, 40);

      if (!messages.length) {
        log('fetchOtpFromEmail no message from sender (inbox+junk)');
        dlog('No message matched the sender filter.');
        if (attempt === maxRetries || attempt % 5 === 0) {
          try {
            const peek = await Promise.all(
              ['inbox', 'junkemail'].map((folder) =>
                fetchMessages(client, {
                  folder,
                  top: 5,
                  filter: null,
                  orderBy: 'receivedDateTime desc',
                  select: 'id,subject,receivedDateTime,from,sender',
                }).then((list) => ({ folder, list }))
              )
            );
            for (const { folder, list } of peek) {
              const summary = (list || []).map((m) => ({
                from: getFromAddress(m),
                subject: (m.subject || '').slice(0, 80),
                received: m.receivedDateTime,
              }));
              log(`fetchOtpFromEmail peek ${folder} latest 5:`, JSON.stringify(summary));
            }
          } catch (e) {
            log('fetchOtpFromEmail peek failed:', e?.message);
          }
        }
      } else {
        const onlyBaseline =
          afterMessageId && messages.length === 1 && messages[0].id === afterMessageId;
        if (onlyBaseline) {
          dlog('Only message is still the baseline id; waiting for a newer email…', { afterMessageId });
        } else {
          for (const msg of messages) {
            if (afterMessageId && msg.id === afterMessageId) continue;

            const fromAddr =
              (msg.from?.emailAddress?.address || msg.sender?.emailAddress?.address || '').trim();
            const msgTime = new Date(msg.receivedDateTime).getTime();
            const age = startTime - msgTime;
            dlog('Candidate message:', {
              id: msg.id,
              from: fromAddr,
              receivedDateTime: msg.receivedDateTime,
              ageSeconds: Math.round(age / 1000),
              subject: (msg.subject || '').slice(0, 120),
            });

            if (Number.isFinite(maxAgeMin) && maxAgeMin > 0 && age > maxAge) {
              dlog(`Skip message too old (>${maxAgeMin} min).`);
              continue;
            }

            const subject = msg.subject || '';
            const preview = msg.bodyPreview || '';
            dlog('Preview (first 200 chars):', preview.slice(0, 200).replace(/\s+/g, ' '));

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
              log('fetchOtpFromEmail success', {
                attempt,
                messageId: msg.id,
                otpLength: otp.length,
              });
              return otp;
            }
          }
        }
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

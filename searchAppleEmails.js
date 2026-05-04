import 'dotenv/config';
import { ClientSecretCredential } from '@azure/identity';
import { Client } from '@microsoft/microsoft-graph-client';
import { TokenCredentialAuthenticationProvider } from '@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials/index.js';

const SEARCH_KEYWORDS = ['nda', 'apple', 'vas', 'apple vas'];

function usage() {
  console.log(`
Usage:
  node searchAppleEmails.js <recipientEmail> [hoursBack] [maxResults]

Examples:
  node searchAppleEmails.js user@company.com
  node searchAppleEmails.js user@company.com 48 20
`);
}

function mustEnv(name) {
  const value = (process.env[name] || '').trim();
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

function getGraphClient() {
  const tenantId = mustEnv('AZURE_TENANT_ID');
  const clientId = mustEnv('AZURE_CLIENT_ID');
  const clientSecret = mustEnv('AZURE_CLIENT_SECRET');

  const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
  const authProvider = new TokenCredentialAuthenticationProvider(credential, {
    scopes: ['https://graph.microsoft.com/.default'],
  });
  return Client.initWithMiddleware({ authProvider });
}

function toIsoHoursBack(hoursBack) {
  const hours = Number.isFinite(Number(hoursBack)) ? Number(hoursBack) : 24;
  const safeHours = Math.min(Math.max(hours, 1), 24 * 30);
  return new Date(Date.now() - safeHours * 60 * 60 * 1000).toISOString();
}

function normalizeAddress(addr) {
  return (addr || '').trim().toLowerCase();
}

function toSafePositiveInt(value, fallback, { min = 1, max = 1000 } = {}) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

function isAppleSender(message) {
  const from =
    normalizeAddress(message?.from?.emailAddress?.address) ||
    normalizeAddress(message?.sender?.emailAddress?.address);
  return from.endsWith('@apple.com');
}

function hasRecipient(message, recipientEmail) {
  const wanted = normalizeAddress(recipientEmail);
  const recipients = [
    ...(Array.isArray(message?.toRecipients) ? message.toRecipients : []),
    ...(Array.isArray(message?.ccRecipients) ? message.ccRecipients : []),
  ];
  return recipients.some((r) => normalizeAddress(r?.emailAddress?.address) === wanted);
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function textContainsKeyword(text, keyword) {
  const normalizedKeyword = String(keyword || '').trim().toLowerCase();
  if (!normalizedKeyword) return false;

  const pattern = normalizedKeyword
    .split(/\s+/)
    .map((part) => escapeRegex(part))
    .join('\\s+');

  return new RegExp(`\\b${pattern}\\b`, 'i').test(text || '');
}

function textContainsSearchKeywords(text) {
  return SEARCH_KEYWORDS.some((keyword) => textContainsKeyword(text, keyword));
}

function containsKeywordPreview(message) {
  return (
    textContainsSearchKeywords(message?.subject) ||
    textContainsSearchKeywords(message?.bodyPreview)
  );
}

async function fetchFolderMessages({ client, userEmail, folderId, sinceIso, pageSize, maxScan }) {
  const allMessages = [];
  let nextLink = null;

  while (allMessages.length < maxScan) {
    let request = nextLink
      ? client.api(nextLink)
      : client
          .api(`/users/${userEmail}/mailFolders/${folderId}/messages`)
          .filter(`receivedDateTime ge ${sinceIso}`)
          .orderby('receivedDateTime desc')
          .top(pageSize)
          .select(
            'id,subject,from,sender,toRecipients,ccRecipients,receivedDateTime,bodyPreview,webLink,parentFolderId'
          );

    const response = await request.get();
    const messages = Array.isArray(response?.value) ? response.value : [];
    allMessages.push(...messages);

    nextLink = response?.['@odata.nextLink'] || null;
    if (!nextLink || messages.length === 0) break;
  }

  return allMessages.slice(0, maxScan);
}

async function getMessageBodyText({ client, userEmail, messageId }) {
  try {
    const response = await client
      .api(`/users/${userEmail}/messages/${messageId}`)
      .header('Prefer', 'outlook.body-content-type="text"')
      .select('body')
      .get();
    return response?.body?.content || '';
  } catch (error) {
    return '';
  }
}

async function matchesSearchCriteria({ client, userEmail, message, recipientEmail }) {
  if (!hasRecipient(message, recipientEmail)) return false;
  if (isAppleSender(message)) return true;
  if (containsKeywordPreview(message)) return true;

  const fullBody = await getMessageBodyText({
    client,
    userEmail,
    messageId: message.id,
  });
  return textContainsSearchKeywords(fullBody);
}

async function searchAppleEmails({ recipientEmail, hoursBack = 24, maxResults = 25 }) {
  const userEmail = mustEnv('USER_EMAIL');
  const client = getGraphClient();
  const sinceIso = toIsoHoursBack(hoursBack);
  const wantedRecipient = normalizeAddress(recipientEmail);
  const limit = toSafePositiveInt(maxResults, 25, { min: 1, max: 200 });
  const pageSize = Math.min(Math.max(limit, 25), 100);
  const maxScan = Math.min(Math.max(limit * 10, 100), 1000);
  const folders = [
    { id: 'inbox', name: 'Inbox' },
    { id: 'junkemail', name: 'Junk Email' },
    { id: 'deleteditems', name: 'Deleted Items' },
  ];

  if (!wantedRecipient || !wantedRecipient.includes('@')) {
    throw new Error('recipientEmail must be a valid email address');
  }

  const folderResults = await Promise.all(
    folders.map(async (folder) => {
      try {
        const messages = await fetchFolderMessages({
          client,
          userEmail,
          folderId: folder.id,
          sinceIso,
          pageSize,
          maxScan,
        });
        return {
          folder: folder.name,
          error: null,
          messages: messages.map((message) => ({ ...message, _folder: folder.name })),
        };
      } catch (error) {
        return {
          folder: folder.name,
          error: error?.message || `Failed to read ${folder.name}`,
          messages: [],
        };
      }
    })
  );

  const dedupedById = new Map();
  for (const result of folderResults) {
    for (const message of result.messages) {
      if (!message?.id) continue;
      if (!dedupedById.has(message.id)) dedupedById.set(message.id, message);
    }
  }

  const uniqueMessages = Array.from(dedupedById.values()).sort(
    (a, b) => new Date(b.receivedDateTime || 0) - new Date(a.receivedDateTime || 0)
  );
  const matches = [];

  for (const message of uniqueMessages) {
    const matched = await matchesSearchCriteria({
      client,
      userEmail,
      message,
      recipientEmail: wantedRecipient,
    });
    if (!matched) continue;

    matches.push({
      id: message.id,
      folder: message._folder || 'Unknown',
      from: message?.from?.emailAddress?.address || message?.sender?.emailAddress?.address || '',
      to: [
        ...(Array.isArray(message?.toRecipients) ? message.toRecipients : []),
        ...(Array.isArray(message?.ccRecipients) ? message.ccRecipients : []),
      ]
        .map((r) => r?.emailAddress?.address)
        .filter(Boolean),
      subject: message.subject || '',
      receivedDateTime: message.receivedDateTime,
      bodyPreview: message.bodyPreview || '',
      webLink: message.webLink || '',
    });

    if (matches.length >= limit) break;
  }

  return {
    folderWarnings: folderResults.filter((result) => result.error),
    scannedCount: uniqueMessages.length,
    results: matches,
  };
}

async function main() {
  const recipientEmail = process.argv[2];
  const hoursBack = process.argv[3] ?? '24';
  const maxResults = process.argv[4] ?? '25';

  if (!recipientEmail) {
    usage();
    process.exit(1);
  }

  try {
    const searchResult = await searchAppleEmails({ recipientEmail, hoursBack, maxResults });
    console.log(
      JSON.stringify(
        {
          recipientEmail,
          matchedCount: searchResult.results.length,
          scannedCount: searchResult.scannedCount,
          folderWarnings: searchResult.folderWarnings,
          results: searchResult.results,
        },
        null,
        2
      )
    );
  } catch (error) {
    console.error('[searchAppleEmails] Failed:', error?.message || error);
    process.exit(1);
  }
}

main();

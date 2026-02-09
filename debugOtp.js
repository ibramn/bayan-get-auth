import 'dotenv/config';
import { ClientSecretCredential } from '@azure/identity';
import { Client } from '@microsoft/microsoft-graph-client';
import { TokenCredentialAuthenticationProvider } from '@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials/index.js';
import { extractOtp } from './otpUtils.js';

const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;
const clientSecret = process.env.AZURE_CLIENT_SECRET;
const userEmail = process.env.USER_EMAIL;
const fromAddress = process.env.BAYAN_OTP_SENDER || 'NoReply@logisti.sa';

if (!tenantId || !clientId || !clientSecret || !userEmail) {
  throw new Error('Missing env: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, USER_EMAIL');
}

const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
const authProvider = new TokenCredentialAuthenticationProvider(credential, {
  scopes: ['https://graph.microsoft.com/.default'],
});
const graph = Client.initWithMiddleware({ authProvider });

function fromAddr(m) {
  return (m.from?.emailAddress?.address || m.sender?.emailAddress?.address || '').trim();
}

console.log('USER_EMAIL:', userEmail);
console.log('Looking for sender:', fromAddress);
console.log('---- Latest 15 messages (any sender) ----');

const res = await graph
  .api(`/users/${userEmail}/messages`)
  .top(15)
  .select('id,subject,receivedDateTime,from,sender,bodyPreview')
  .get();

const msgs = (res?.value ?? [])
  .slice()
  .sort((a, b) => new Date(b.receivedDateTime) - new Date(a.receivedDateTime));

for (const m of msgs) {
  const received = m.receivedDateTime;
  const addr = fromAddr(m);
  const subject = m.subject || '';
  const preview = (m.bodyPreview || '').slice(0, 140).replace(/\s+/g, ' ');
  const otp = extractOtp(subject) || extractOtp(preview);
  console.log(`- ${received} | from=${addr} | otp=${otp || '-'} | subject=${JSON.stringify(subject)}`);
}

console.log('\n---- Latest 25 messages filtered locally by sender ----');
const wanted = fromAddress.trim().toLowerCase();
const domain = wanted.includes('@') ? wanted.split('@')[1] : '';
const filtered = msgs.filter((m) => {
  const a = fromAddr(m).toLowerCase();
  if (!a) return false;
  if (a === wanted) return true;
  if (a.includes(wanted)) return true;
  if (domain && a.endsWith(`@${domain}`)) return true;
  return false;
});

for (const m of filtered.slice(0, 10)) {
  const received = m.receivedDateTime;
  const addr = fromAddr(m);
  const subject = m.subject || '';
  const preview = (m.bodyPreview || '').slice(0, 200).replace(/\s+/g, ' ');
  console.log(`- ${received} | from=${addr} | subject=${JSON.stringify(subject)} | preview=${JSON.stringify(preview)}`);
}


import 'dotenv/config';
import { readFile } from 'fs/promises';

const OPENID_FILE = process.env.OPENID_FILE || './openid.json';

async function loadDiscovery() {
  const raw = await readFile(OPENID_FILE, 'utf8');
  return JSON.parse(raw);
}

function decodeJwtPayload(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return null;
  const pad = '='.repeat((4 - (parts[1].length % 4)) % 4);
  const b64 = (parts[1] + pad).replace(/-/g, '+').replace(/_/g, '/');
  try {
    return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

async function getTokenViaPassword({ tokenEndpoint, clientId, clientSecret, username, password, scope }) {
  const body = new URLSearchParams({
    grant_type: 'password',
    client_id: clientId,
    username,
    password,
    scope,
  });
  if (clientSecret) body.set('client_secret', clientSecret);

  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body,
  });

  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep raw */ }

  if (!res.ok) {
    const detail = json ? JSON.stringify(json) : text;
    const err = new Error(`Token endpoint ${res.status} ${res.statusText}: ${detail}`);
    err.status = res.status;
    err.body = json ?? text;
    throw err;
  }
  return json;
}

async function main() {
  const username = process.env.BAYAN_IDENTITY_NUMBER;
  const password = process.env.BAYAN_PASSWORD;
  const clientId = process.env.BAYAN_CLIENT_ID || 'bayanClient';
  const clientSecret = process.env.BAYAN_CLIENT_SECRET || '';
  const scope = process.env.BAYAN_SCOPE || 'openid profile email offline_access';

  if (!username || !password) {
    console.error('Missing BAYAN_IDENTITY_NUMBER or BAYAN_PASSWORD in env');
    process.exit(1);
  }

  const discovery = await loadDiscovery();
  const tokenEndpoint = discovery.token_endpoint;
  if (!tokenEndpoint) {
    console.error('No token_endpoint in', OPENID_FILE);
    process.exit(1);
  }

  console.log('[OIDC] token_endpoint:', tokenEndpoint);
  console.log('[OIDC] client_id:', clientId);
  console.log('[OIDC] scope:', scope);
  console.log('[OIDC] username:', username);

  const tokens = await getTokenViaPassword({
    tokenEndpoint, clientId, clientSecret, username, password, scope,
  });

  console.log('\n[OIDC] response:');
  console.log(JSON.stringify(tokens, null, 2));

  if (tokens.access_token) {
    const payload = decodeJwtPayload(tokens.access_token);
    if (payload) {
      console.log('\n[OIDC] access_token claims:');
      console.log(JSON.stringify(payload, null, 2));
    }
  }
}

main().catch((e) => {
  console.error('\n[OIDC] FAILED:', e.message);
  process.exit(1);
});

// Bayan auth RUNNER — runs on a box with access to the Bayan website.
//
// Responsibility (single privilege: Bayan access, NO database access):
//   - On startup, on a 30-min self-tick, and whenever a refresh trigger arrives, run the Puppeteer
//     IAM+OTP login (getAuth) to obtain a fresh access token + cookie.
//   - Publish the credentials END-TO-END ENCRYPTED and RETAINED to the broker. The broker is a
//     public relay and only ever sees ciphertext; only the updater (same key) can decrypt.
//
// Run:  node mqttRunner.js   (or: npm run runner)
// Config: see .env / .env.example (MQTT_* and BAYAN_CRED_KEY).

import 'dotenv/config';
import { readFileSync } from 'node:fs';
import mqtt from 'mqtt';
import { getAuth } from './authService.js';
import { encryptCred, loadKey } from './credCrypto.js';

const log = (...a) => console.log('[Runner]', ...a);

const BROKER_URL = process.env.MQTT_BROKER_URL || 'mqtt://127.0.0.1:1883';
const TOKEN_TOPIC = process.env.MQTT_TOKEN_TOPIC || 'aldrees/bayan/auth/token';
const REFRESH_TOPIC = process.env.MQTT_REFRESH_TOPIC || 'aldrees/bayan/auth/refresh';
const STATUS_TOPIC = process.env.MQTT_STATUS_TOPIC || 'aldrees/bayan/auth/status';
const REFRESH_INTERVAL_MS = Number(process.env.RUNNER_REFRESH_INTERVAL_MS || 0) || 30 * 60 * 1000;

const KEY = loadKey(process.env.BAYAN_CRED_KEY);

const connectOptions = {
  clientId: process.env.MQTT_CLIENT_ID || 'bayan-auth-runner',
  username: process.env.MQTT_USERNAME || undefined,
  password: process.env.MQTT_PASSWORD || undefined,
  reconnectPeriod: 5000,
  connectTimeout: 30000,
  // TLS (mqtts://): provide the broker CA for a self-signed cert, or set REJECT_UNAUTHORIZED=false.
  rejectUnauthorized: process.env.MQTT_TLS_REJECT_UNAUTHORIZED !== 'false',
  ...(process.env.MQTT_CA_PATH ? { ca: readFileSync(process.env.MQTT_CA_PATH) } : {}),
};

let refreshing = false;
let lastEnvelope = null;
let timer = null;

/** Extract JWT exp (ms epoch) without verifying signature; null if not decodable. */
function jwtExpMs(token) {
  try {
    const part = String(token || '').split('.')[1];
    if (!part) return null;
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const exp = JSON.parse(json).exp;
    return typeof exp === 'number' ? exp * 1000 : null;
  } catch {
    return null;
  }
}

function publishStatus(client, obj) {
  try {
    client.publish(STATUS_TOPIC, JSON.stringify(obj), { qos: 0, retain: true });
  } catch {
    /* status is best-effort */
  }
}

async function refreshAndPublish(client, reason) {
  if (refreshing) {
    log(`refresh already in progress — skipping (${reason})`);
    return;
  }
  refreshing = true;
  const startedAt = new Date().toISOString();
  try {
    log(`refresh start (${reason})`);
    const auth = await getAuth(); // { accessToken, cookieHeader, cookie, ... }
    const accessToken = auth?.accessToken || '';
    const cookieHeader = auth?.cookieHeader || auth?.cookie || '';
    if (!accessToken && !cookieHeader) {
      throw new Error('getAuth returned neither an access token nor a cookie');
    }

    const expMs = jwtExpMs(accessToken) ?? Date.now() + 60 * 60 * 1000;
    const plaintext = JSON.stringify({
      accessToken,
      cookieHeader,
      expiresAtUtc: new Date(expMs).toISOString(),
      issuedAt: startedAt,
    });
    lastEnvelope = encryptCred(plaintext, KEY);

    client.publish(TOKEN_TOPIC, lastEnvelope, { qos: 1, retain: true }, (err) => {
      if (err) log('publish error:', err.message);
      else log(`published encrypted creds → ${TOKEN_TOPIC} (exp ${new Date(expMs).toISOString()})`);
    });
    publishStatus(client, { ok: true, at: startedAt, expiresAtUtc: new Date(expMs).toISOString(), reason });
  } catch (e) {
    log('refresh FAILED:', e?.message);
    // Leave the previous retained token in place; just report the failure.
    publishStatus(client, { ok: false, at: startedAt, error: String(e?.message || e), reason });
  } finally {
    refreshing = false;
  }
}

function main() {
  log(`connecting to ${BROKER_URL} (client ${connectOptions.clientId}) …`);
  const client = mqtt.connect(BROKER_URL, connectOptions);

  client.on('connect', () => {
    log('connected');
    client.subscribe(REFRESH_TOPIC, { qos: 1 }, (err) =>
      err ? log('subscribe error:', err.message) : log(`subscribed → ${REFRESH_TOPIC}`)
    );

    // First connect: do a full login. Reconnects: just re-assert the last retained token (cheap),
    // so a flapping broker connection never triggers repeated Puppeteer logins.
    if (!lastEnvelope) {
      refreshAndPublish(client, 'startup');
    } else {
      client.publish(TOKEN_TOPIC, lastEnvelope, { qos: 1, retain: true });
      log('re-published last creds after reconnect');
    }

    if (!timer) {
      timer = setInterval(() => refreshAndPublish(client, 'interval'), REFRESH_INTERVAL_MS);
      log(`self-tick every ${Math.round(REFRESH_INTERVAL_MS / 60000)} min`);
    }
  });

  client.on('message', (topic) => {
    if (topic === REFRESH_TOPIC) {
      log('refresh trigger received');
      refreshAndPublish(client, 'trigger');
    }
  });

  client.on('error', (e) => log('mqtt error:', e?.message));
  client.on('reconnect', () => log('reconnecting…'));
  client.on('close', () => log('connection closed'));

  const shutdown = () => {
    log('shutting down');
    if (timer) clearInterval(timer);
    client.end(true, () => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main();

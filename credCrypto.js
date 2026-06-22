// End-to-end encryption for Bayan credentials carried over MQTT.
//
// The broker is a public relay and must never see the plaintext token/cookie. The runner encrypts
// here; only the updater (which holds the same key) can decrypt. AES-256-GCM with a random 96-bit
// nonce per message; the envelope is interop-compatible with the .NET updater (System.Security.
// Cryptography.AesGcm): {v, alg, iv, tag, ct} all base64.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALG = 'AES-256-GCM';

/**
 * Decode and validate the shared key from its base64 env value.
 * @param {string|undefined} envValue base64 of exactly 32 bytes
 * @returns {Buffer} 32-byte key
 */
export function loadKey(envValue) {
  if (!envValue) throw new Error('BAYAN_CRED_KEY is not set (base64 of 32 bytes; generate: openssl rand -base64 32)');
  const key = Buffer.from(envValue, 'base64');
  if (key.length !== 32) {
    throw new Error(`BAYAN_CRED_KEY must decode to 32 bytes, got ${key.length}. Generate: openssl rand -base64 32`);
  }
  return key;
}

/**
 * Encrypt a UTF-8 string into a self-describing JSON envelope (string).
 * @param {string} plaintext
 * @param {Buffer} key 32 bytes
 * @returns {string} JSON envelope
 */
export function encryptCred(plaintext, key) {
  const iv = randomBytes(12); // 96-bit nonce, standard for GCM
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return JSON.stringify({
    v: 1,
    alg: ALG,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: ct.toString('base64'),
  });
}

/**
 * Decrypt a JSON envelope produced by encryptCred (or the .NET side). Throws on tamper/wrong key.
 * Provided for symmetry and local testing (the .NET updater is the real consumer).
 * @param {string|object} envelope
 * @param {Buffer} key 32 bytes
 * @returns {string} plaintext
 */
export function decryptCred(envelope, key) {
  const env = typeof envelope === 'string' ? JSON.parse(envelope) : envelope;
  const iv = Buffer.from(env.iv, 'base64');
  const tag = Buffer.from(env.tag, 'base64');
  const ct = Buffer.from(env.ct, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

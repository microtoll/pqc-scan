// An ECIES-style seal to a recipient's P-256 key: an ephemeral key pair,
// ECDH, HKDF to an AES-256-GCM key. The parameters come from params.js.
import { SEAL_CURVE, AEAD_BITS, KDF_HASH, PQ_KEM } from './params.js';

const subtle = globalThis.crypto.subtle;
const IV_BYTES = 12;

async function deriveSealKey(sharedSecret, info) {
  const baseKey = await subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: KDF_HASH, salt: new Uint8Array(0), info },
    baseKey,
    { name: 'AES-GCM', length: AEAD_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function sealToRecipient(recipientPublicKey, plaintext) {
  const ephemeral = await subtle.generateKey({ name: 'ECDH', namedCurve: SEAL_CURVE }, true, ['deriveBits']);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: recipientPublicKey }, ephemeral.privateKey, 256);
  const key = await deriveSealKey(shared, new Uint8Array(0));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const params = plaintext.length ? { name: 'AES-GCM', iv } : { name: 'AES-GCM', iv, additionalData: new Uint8Array(0) };
  return subtle.encrypt(params, key, plaintext);
}

export async function sealHybrid(publicKey) {
  return subtle.encapsulateBits({ name: PQ_KEM }, publicKey);
}

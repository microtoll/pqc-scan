// Web Crypto call shapes seen in real TypeScript code.
const { subtle } = globalThis.crypto;
const LEGACY_HASH: string = 'SHA-1';

export async function fingerprint(data: Uint8Array): Promise<ArrayBuffer> {
  return window.crypto.subtle.digest(LEGACY_HASH, data);
}

export async function makeTransportKeys() {
  // A session key pair for the transport handshake.
  return crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  );
}

export async function signReceipt(key: CryptoKey, data: Uint8Array) {
  return subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' } }, key, data);
}

export async function shortKey() {
  return subtle.generateKey({ name: 'AES-CBC', length: 128 } as AesKeyGenParams, true, ['encrypt']);
}

export async function weakStretch(key: CryptoKey, salt: Uint8Array) {
  return subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 10_000, hash: 'SHA-256' }, key, 256);
}

export async function wrapAndUnwrap(key: CryptoKey, kek: CryptoKey, rsaPrivate: CryptoKey, wrapped: ArrayBuffer) {
  await subtle.wrapKey('raw', key, kek, 'AES-KW');
  return subtle.unwrapKey('raw', wrapped, rsaPrivate, { name: 'RSA-OAEP' }, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

export async function postQuantum(data: Uint8Array) {
  const kem = await subtle.generateKey({ name: 'X25519MLKEM768' }, true, ['encapsulateBits']);
  const dsa = await subtle.generateKey('ML-DSA-65', false, ['sign']);
  return [kem, dsa];
}

export async function fromConfig(algorithmFromConfig: AlgorithmIdentifier, key: CryptoKey, data: Uint8Array) {
  return subtle.encrypt(algorithmFromConfig, key, data);
}

export function nonce() {
  return crypto.getRandomValues(new Uint8Array(16));
}

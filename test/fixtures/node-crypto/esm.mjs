// node:crypto through a default import, as a server keeps it.
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

export function etag(body) {
  return crypto.createHash('md5').update(body).digest('hex');
}

export function signCookie(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

export function legacyEncrypt(key, iv, data) {
  const a = crypto.createCipheriv('aes-128-cbc', key, iv);
  const b = crypto.createCipheriv('des-ede3-cbc', key, iv);
  const c = crypto.createCipheriv('aes-256-ecb', key, null);
  return [a, b, c];
}

export function keys() {
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const wallet = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const signer = crypto.generateKeyPairSync('ed25519');
  return { rsa, wallet, signer };
}

export function signRelease(privateKey, data) {
  return crypto.createSign('RSA-SHA256').update(data).sign(privateKey);
}

export function agree(peerPublic) {
  const ecdh = crypto.createECDH('prime256v1');
  const dh = crypto.getDiffieHellman('modp14');
  return [ecdh.computeSecret(peerPublic), dh];
}

export function encryptForArchive(publicKeyPem, backup) {
  return crypto.publicEncrypt(publicKeyPem, backup);
}

export function stretch(password, salt) {
  const a = crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha1');
  const b = crypto.scryptSync(password, salt, 64, { N: 16384 });
  const c = crypto.hkdfSync('sha512', password, salt, 'info', 32);
  return [a, b, c];
}

export function ids() {
  return [crypto.randomBytes(32), crypto.randomUUID(), crypto.webcrypto.getRandomValues(new Uint8Array(8))];
}

export function checkSignature(data, key, sig) {
  return crypto.verify(null, data, key, sig);
}

export function certificate() {
  return new crypto.X509Certificate(readFileSync('cert.pem'));
}

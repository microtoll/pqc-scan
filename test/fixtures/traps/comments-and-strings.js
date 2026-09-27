// Every algorithm here is a mention, never a call. None may be reported.
import crypto from 'node:crypto';

// We used to call crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data) here.
/* crypto.createCipheriv('rc4', key, null) was removed in 2024.
   crypto.createHash('md5') too. */
const help = "Call crypto.createHash('md5') to get an etag.";
const doc = 'crypto.subtle.sign(\'Ed25519\', key, data) signs data';
const note = `it's crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }) — don't`;
const pattern = /crypto\.createHash\('md5'\)/;
const pattern2 = /'/; const after = "crypto.createHmac('sha1', k)";

export function describe() {
  return [help, doc, note, pattern, pattern2, after, typeof crypto].join('\n');
}

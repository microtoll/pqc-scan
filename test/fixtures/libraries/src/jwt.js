// JSON Web Tokens with two libraries: algorithms read from their literals.
import { SignJWT, jwtVerify } from 'jose';
const jwt = require('jsonwebtoken');

export async function issue(payload, privateKey) {
  return new SignJWT(payload).setProtectedHeader({ alg: 'ES256' }).sign(privateKey);
}

export async function check(token, key) {
  return jwtVerify(token, key);
}

export function legacySession(payload, secret) {
  return jwt.sign(payload, secret);
}

export function serviceToken(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'RS256', expiresIn: '1h' });
}

export function accept(token, key) {
  return jwt.verify(token, key, { algorithms: ['none', 'EdDSA'] });
}

// Not a JWT algorithm: CSS.
export const hidden = { display: 'none' };

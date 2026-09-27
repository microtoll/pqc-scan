// Password hashing and a legacy crypto-js path.
import CryptoJS from 'crypto-js';
const bcrypt = require('bcrypt');

export async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

export function legacyChecksum(text) {
  return CryptoJS.MD5(text).toString();
}

export function legacyEncrypt(text, key) {
  return CryptoJS.AES.encrypt(text, key).toString();
}

export function legacyKey(password, salt) {
  return CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
}

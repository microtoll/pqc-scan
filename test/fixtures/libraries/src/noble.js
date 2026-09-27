// The noble libraries through named imports from subpaths.
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

export function signIt(message, secretKey) {
  return ed25519.sign(message, secretKey);
}

export function agreeForSession(mine, theirs) {
  return x25519.getSharedSecret(mine, theirs);
}

export function signP256(hash, secretKey) {
  return p256.sign(hash, secretKey);
}

export function encapsulate(publicKey) {
  return ml_kem768.encapsulate(publicKey);
}

export function tag(key, message) {
  return bytesToHex(hmac(sha256, key, message));
}

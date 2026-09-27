// tweetnacl through its default export.
import nacl from 'tweetnacl';

export function sealForStorage(message, nonce, theirPublicKey, mySecretKey) {
  return nacl.box(message, nonce, theirPublicKey, mySecretKey);
}

export function signMessage(message, secretKey) {
  return nacl.sign.detached(message, secretKey);
}

export function lock(message, nonce, key) {
  return nacl.secretbox(message, nonce, key);
}

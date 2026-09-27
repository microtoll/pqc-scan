// Signing a release: Ed25519, a Medium.
export async function signRelease(privateKey, bytes) {
  return crypto.subtle.sign('Ed25519', privateKey, bytes);
}

// Sealing a backup to a recipient's key: classical ECDH, a High.
export async function sealBackup(recipientPublicKey) {
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'ECDH', public: recipientPublicKey }, ephemeral.privateKey, 384);
}

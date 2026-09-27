// A server turning a COSE public key into a Node key. The file name and the
// function name are the only context, as they were in the real application
// where this was reported as a High; it is a Medium.
const crypto = require('node:crypto');

function coseToPublicKey(cose) {
  const x = cose.get(-2), y = cose.get(-3);
  return crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url') }, format: 'jwk' });
}

module.exports = { coseToPublicKey };

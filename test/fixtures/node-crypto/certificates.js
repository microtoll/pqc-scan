const crypto = require('crypto');

function install() {
  // Generate certificates
  const certs = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  return certs;
}

module.exports = { install };

// A server making the RSA key pair that signs its tokens, with "Generate
// certificates" as the only nearby words. On a public wiki this was a High
// ("no context words"); a certificate is a signing artefact, so "cert" and
// "certificate" are signing words and the key is Medium (DESIGN.md §8.4,
// §8.12). This comment sits below the call, outside the window it reads.

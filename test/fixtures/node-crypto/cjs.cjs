// node:crypto through require: destructured, renamed, inline, and a second
// namespace name.
const { createHash, randomBytes: rb } = require('crypto');
const c = require('node:crypto');

function legacyId(s) {
  return createHash('sha1').update(s).digest('hex');
}

function token() {
  return rb(16).toString('hex');
}

function mac(k, m) {
  return require('crypto').createHmac('sha512', k).update(m).digest();
}

function modern(m) {
  return c.createHash('sha3-256').update(m).digest();
}

module.exports = { legacyId, token, mac, modern };

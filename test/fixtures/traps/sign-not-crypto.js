// `.sign(`, `.verify(`, `.randomBytes(` and `createHash(` on things that are
// not node:crypto or Web Crypto. None may be reported.
import { createCryptoHelpers } from './helpers.js';

const cc = createCryptoHelpers();
const nonce = cc.randomBytes(32);

class Contract {
  sign(signer) { this.signedBy = signer; return this; }
  verify(expected) { return this.signedBy === expected; }
  createHash(label) { return `${label}#${nonce.length}`; }
}

const deal = new Contract().sign('RSA-SHA256');
deal.verify('ECDSA');

// A local function that shares a node:crypto name.
function createHash(kind) { return { kind }; }
createHash('md5');

// Unbound: without an import of node:crypto, `crypto` here is the Web
// Crypto global, which has no createHash; not reported.
export const legacy = () => crypto.createHash('md5');

export { deal };

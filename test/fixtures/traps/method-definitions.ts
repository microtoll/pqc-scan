// A class whose methods share names with node:crypto imports. The method
// definitions are not calls; the one real call inside is.
import { sign, createHash } from 'node:crypto';

export class Signer {
  constructor(key) { this.key = key; }

  sign(data) {
    return sign(null, data, this.key);
  }

  createHash(): string {
    return 'not a hash';
  }

  async verify(data, signature) {
    return data.length === signature.length;
  }
}

export const pick = (flag) => (flag ? createHash('sha256') : { digest: () => '' });

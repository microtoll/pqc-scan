// TypeScript's CommonJS import form.
import crypto = require('crypto');

export function sum(data: Buffer): string {
  return crypto.createHash('sha384').update(data).digest('hex');
}

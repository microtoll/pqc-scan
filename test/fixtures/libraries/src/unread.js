// A catalogued library used through a computed member: its algorithm
// cannot be read, so the import is pointed at as dynamic.
import * as nacl from 'tweetnacl';

export function run(name, ...args) {
  return nacl[name](...args);
}

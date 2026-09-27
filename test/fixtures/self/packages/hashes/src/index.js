// A workspace package's own code. Another file importing '@noble/hashes'
// would be importing this tree, not a dependency; the use is still a use.
import { sha256 } from '@noble/hashes/sha256';
export const digest = (d) => sha256(d);

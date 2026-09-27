// Named parameters (DESIGN.md §8.8): a module-level constant whose name says
// it is a PBKDF2 iteration count, such as `PBKDF2_ITERATIONS = 310000`.
//
// Why: an iteration count usually reaches the PBKDF2 call through a
// function parameter (`deriveKey(password, salt, iterations)`), which a
// tokenizer can never follow, so the call reports the count as not written
// there. The constant is where the count is written down. The finding
// says where it is declared and does not claim it reaches any call.
import { describe } from '../catalogue.js';
import { makeFinding } from './finding.js';

// Both words must be in the name: PBKDF2 and an iteration word.
const PBKDF2_NAME = /pbkdf2/i;
const ITERATION_NAME = /iter|rounds/i;

/**
 * @param {import('../source.js').SourceFile} src
 */
export function detectParameters(src) {
  const findings = [];
  for (const d of src.declarations) {
    if (!d.name || d.kind !== 'const' || d.depth !== 0 || !d.init) continue;
    if (!PBKDF2_NAME.test(d.name) || !ITERATION_NAME.test(d.name)) continue;
    const v = src.readValue(d.init[0], d.init[1]);
    if (v.kind !== 'number') continue;
    const algo = describe({ family: 'PBKDF2', parameters: { iterations: v.value }, noteCodes: ['declared-here'] });
    findings.push(makeFinding(src, d.index, algo, { iface: 'constant', operation: 'iteration count' }));
  }
  return findings;
}

// One finding: an algorithm use at a place in a file, with its class,
// priority and notes (DESIGN.md §3.1, §4). Every detector builds its
// findings here, so that every finding has the same shape (the JSON schema
// in schema/pqc-scan.schema.json).
import { prioritise } from '../catalogue.js';

/**
 * @param {import('../source.js').SourceFile} src
 * @param {number} at     the token the finding points at (its line and column)
 * @param {import('../catalogue.js').Algorithm} algo
 * @param {{ iface: string, operation: string, notes?: {code: string, text: string}[] }} how
 */
export function makeFinding(src, at, algo, { iface, operation, notes = [] }) {
  const t = src.tokens[at] ?? src.tokens[src.tokens.length - 1];
  const line = t ? t.line : 1;
  const column = t ? t.col : 1;
  // Only quantum-vulnerable public-key uses get a priority (DESIGN.md §4
  // item 3); the words near the call decide which.
  const p = algo.class === 'public-key' ? prioritise(algo.kind, src.wordsNear(line)) : null;
  const seen = new Set();
  const allNotes = [...algo.notes, ...notes].filter((n) => (seen.has(n.code) ? false : seen.add(n.code)));
  return {
    algorithm: algo.algorithm,
    family: algo.family,
    class: algo.class,
    kind: algo.kind,
    quantumVulnerable: algo.class === 'public-key',
    keySize: algo.keySize,
    curve: algo.curve,
    hash: algo.hash,
    parameters: algo.parameters,
    interface: iface,
    operation,
    file: src.path,
    line,
    column,
    evidence: src.evidence(line),
    dynamic: algo.dynamic,
    priority: p ? p.priority : null,
    priorityReason: p ? p.reason : null,
    replacement: p ? p.replacement : null,
    notes: allNotes,
    inTest: src.inTest,
  };
}

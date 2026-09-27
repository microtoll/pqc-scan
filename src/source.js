// Reading one JavaScript or TypeScript file through its tokens: matching
// brackets, call sites and their arguments, object-literal fields,
// constants (DESIGN.md §8.1), imports and requires, and the words near a
// line (§8.4). The detectors ask questions of a SourceFile; none of them
// looks at raw text.
import { tokenize, splitLines } from './tokenize.js';
import { splitWords } from './catalogue.js';

const OPENERS = { '(': ')', '[': ']', '{': '}' };
const CLOSERS = { ')': '(', ']': '[', '}': '{' };

// Identifiers followed by `(` that are not calls.
const NOT_CALLEES = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'typeof', 'await', 'new',
  'yield', 'void', 'delete', 'in', 'of', 'instanceof', 'else', 'do', 'super', 'import', 'with', 'case', 'throw',
]);

// Keywords that start a new statement: a re-export's `from` is never past one.
const STATEMENT_KEYWORDS = new Set(['import', 'export', 'const', 'let', 'var', 'function', 'class']);

// How far above a call the priority heuristic looks (DESIGN.md §8.4).
const WORD_WINDOW_LINES = 8;
const EVIDENCE_MAX = 200;
// `test-d` is tsd's directory for type tests: found unmarked on a public
// library (DESIGN.md §8.7, §8.12). scan.js reads the same set.
export const TEST_DIRS = new Set(['test', 'tests', '__tests__', 'spec', 'specs', 'test-d']);

/**
 * @typedef {{ kind: 'string', value: string } | { kind: 'number', value: number } | { kind: 'null' }
 *   | { kind: 'boolean' } | { kind: 'object', start: number, end: number }
 *   | { kind: 'array', start: number, end: number } | { kind: 'ident', name: string }
 *   | { kind: 'unknown', text: string }} Value
 *   `object` and `array` hold token ranges in the file that produced them.
 */

/**
 * @typedef {object} Call
 * @property {number} at       index of the callee's last identifier (its line is the call's line)
 * @property {number} open     index of the `(`
 * @property {string[]} chain  the callee as names: `a.b.c(` → ['a','b','c']
 * @property {string|null} rootModule  set when the chain starts at require('m') or import('m')
 * @property {[number, number]|null} rootGroup  set when it starts at a bracketed expression
 * @property {boolean} isNew
 */

export class SourceFile {
  /**
   * @param {string} path  relative to the scanned root, with forward slashes
   * @param {string} text
   * @param {{ importedConstant?: (fromPath: string, specifier: string, name: string) => Value|null }} [env]
   */
  constructor(path, text, env = {}) {
    this.path = path;
    this.env = env;
    const { tokens, comments } = tokenize(text);
    this.tokens = tokens;
    this.comments = comments;
    this.lines = splitLines(text);
    const segments = path.split('/');
    const base = segments[segments.length - 1];
    // The scan passes its own answer when the caller named extra test-file
    // texts (§8.13); alone, a SourceFile applies the standard rule.
    this.inTest = env.inTest ?? (segments.slice(0, -1).some((s) => TEST_DIRS.has(s)) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(base));
    this.baseWords = splitWords(base.replace(/\.[^.]*$/, ''));
    this.match = matchBrackets(tokens);
    this._declarations = null;
    this._imports = null;
    this._calls = null;
  }

  // -------------------------------------------------------------------------
  // Token helpers

  /** @returns {boolean} whether token i is the punctuator `value` */
  isPunct(i, value) {
    const t = this.tokens[i];
    return Boolean(t && t.type === 'punct' && t.value === value);
  }

  isIdent(i, value) {
    const t = this.tokens[i];
    return Boolean(t && t.type === 'ident' && (value === undefined || t.value === value));
  }

  isMemberDot(i) {
    return this.isPunct(i, '.') || this.isPunct(i, '?.');
  }

  /** The source line, trimmed and cut to EVIDENCE_MAX characters. */
  evidence(line) {
    const text = (this.lines[line - 1] ?? '').trim();
    return text.length > EVIDENCE_MAX ? `${text.slice(0, EVIDENCE_MAX - 1)}…` : text;
  }

  /** The source text of tokens [start, end). */
  textOf(start, end) {
    if (start >= end) return '';
    return this.tokens.slice(start, end).map((t) => t.raw).join(' ').replace(/\s*([.()[\]{},:])\s*/g, '$1');
  }

  /**
   * Where an expression starting at `start` ends (exclusive): at a `;` or
   * `,` outside brackets, at a bracket that closes something opened before
   * `start`, or at a line break where automatic semicolon insertion would
   * end the statement (a value on one line, a new statement on the next).
   */
  expressionEnd(start) {
    let depth = 0;
    const n = this.tokens.length;
    for (let j = start; j < n; j++) {
      const t = this.tokens[j];
      if (isOpener(t)) { depth++; continue; }
      if (isCloser(t)) { if (depth === 0) return j; depth--; continue; }
      if (depth !== 0) continue;
      if (t.type === 'punct' && (t.value === ';' || t.value === ',')) return j;
      if (j > start && t.nl && endsValue(this.tokens[j - 1]) && startsStatement(t)) return j;
    }
    return n;
  }

  // -------------------------------------------------------------------------
  // Arguments and values

  /**
   * The top-level argument ranges of the call whose `(` is at `open`.
   * @returns {[number, number][]}
   */
  args(open) {
    const close = this.match[open];
    if (close < 0) return [];
    const out = [];
    let start = open + 1;
    let depth = 0;
    for (let j = open + 1; j < close; j++) {
      const t = this.tokens[j];
      if (isOpener(t)) depth++;
      else if (isCloser(t)) depth--;
      else if (depth === 0 && t.type === 'punct' && t.value === ',') { out.push([start, j]); start = j + 1; }
    }
    if (start < close) out.push([start, close]);
    return out;
  }

  /**
   * Reads the value of the expression in [start, end), following constants
   * by the rules of DESIGN.md §8.1 and nothing else.
   * @returns {Value}
   */
  readValue(start, end, seen = new Set()) {
    let s = start;
    let e = end;
    // TypeScript's `x as const`, `x as Algorithm`, `x satisfies T` do not
    // change the value: cut them off.
    for (let j = s; j < e; j++) {
      const t = this.tokens[j];
      if (isOpener(t)) { j = Math.max(j, this.match[j]); continue; }
      if (t.type === 'ident' && (t.value === 'as' || t.value === 'satisfies') && j > s) { e = j; break; }
    }
    // Wrapping brackets: `('P-256')`.
    while (e - s >= 2 && this.isPunct(s, '(') && this.match[s] === e - 1) { s++; e--; }
    if (e <= s) return { kind: 'unknown', text: '' };
    const t = this.tokens[s];
    if (e - s === 1) {
      if (t.type === 'string' || t.type === 'template') return { kind: 'string', value: String(t.value) };
      if (t.type === 'number' && typeof t.value === 'number') return { kind: 'number', value: t.value };
      if (t.type === 'ident') {
        if (t.value === 'null' || t.value === 'undefined') return { kind: 'null' };
        if (t.value === 'true' || t.value === 'false') return { kind: 'boolean' };
        return this.resolve(String(t.value), s, seen);
      }
    }
    if (e - s === 2 && this.isPunct(s, '-') && this.tokens[s + 1].type === 'number') {
      return { kind: 'number', value: -Number(this.tokens[s + 1].value) };
    }
    if (this.isPunct(s, '{') && this.match[s] === e - 1) return { kind: 'object', start: s, end: e - 1 };
    if (this.isPunct(s, '[') && this.match[s] === e - 1) return { kind: 'array', start: s, end: e - 1 };
    // A conditional `c ? A : B` is read only when both branches say the
    // same algorithm (DESIGN.md §8.1): `ad ? { name: 'AES-GCM', iv, ad } :
    // { name: 'AES-GCM', iv }`.
    const q = this.topLevel(s, e, '?');
    if (q > 0) {
      const colon = this.topLevel(q + 1, e, ':');
      if (colon > 0) {
        const a = this.readValue(q + 1, colon, seen);
        const b = this.readValue(colon + 1, e, seen);
        if (sameAlgorithm(this, a, b)) return a;
      }
    }
    return { kind: 'unknown', text: this.textOf(s, e) };
  }

  /** Index of the first top-level punctuator `value` in [s, e), or -1. */
  topLevel(s, e, value) {
    for (let j = s; j < e; j++) {
      const t = this.tokens[j];
      if (isOpener(t)) { j = Math.max(j, this.match[j]); continue; }
      if (t.type === 'punct' && t.value === value) return j;
    }
    return -1;
  }

  /**
   * The fields of an object literal value, as key → token range. Shorthand
   * `{ iterations }` maps to the identifier itself; computed keys, spreads
   * and methods are skipped.
   * @returns {Map<string, [number, number]>}
   */
  fields(obj) {
    const out = new Map();
    if (!obj || obj.kind !== 'object') return out;
    const src = obj.src ?? this;
    let j = obj.start + 1;
    while (j < obj.end) {
      const entryEnd = src.entryEnd(j, obj.end);
      const k = src.tokens[j];
      if (k && (k.type === 'ident' || k.type === 'string' || k.type === 'number')) {
        if (src.isPunct(j + 1, ':')) out.set(String(k.value), [j + 2, entryEnd]);
        else if (k.type === 'ident' && j + 1 === entryEnd) out.set(String(k.value), [j, j + 1]);
      }
      j = entryEnd + 1;
    }
    return out;
  }

  entryEnd(j, limit) {
    for (let x = j; x < limit; x++) {
      const t = this.tokens[x];
      if (isOpener(t)) { x = Math.max(x, this.match[x]); continue; }
      if (t.type === 'punct' && t.value === ',') return x;
    }
    return limit;
  }

  /** The value of one field of an object value, or undefined when absent. */
  field(obj, key) {
    const range = this.fields(obj).get(key);
    return range ? this.readValue(range[0], range[1]) : undefined;
  }

  /** A field read as a string, or as `{ name: '…' }` (Web Crypto's hash). */
  fieldString(obj, key) {
    const v = this.field(obj, key);
    if (!v) return undefined;
    if (v.kind === 'string') return v.value;
    if (v.kind === 'object') {
      const inner = this.field(v, 'name');
      if (inner && inner.kind === 'string') return inner.value;
    }
    return null;
  }

  fieldNumber(obj, key) {
    const v = this.field(obj, key);
    if (!v) return undefined;
    return v.kind === 'number' ? v.value : null;
  }

  /** Item ranges of an array literal value. */
  items(arr) {
    if (!arr || arr.kind !== 'array') return [];
    const out = [];
    let j = arr.start + 1;
    while (j < arr.end) {
      const end = this.entryEnd(j, arr.end);
      if (end > j) out.push([j, end]);
      j = end + 1;
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Constants (DESIGN.md §8.1)

  /**
   * Every simple declaration: `const|let|var NAME [: Type] [= init]`, and
   * destructuring patterns (kept for the Web Crypto alias rule).
   */
  get declarations() {
    if (this._declarations) return this._declarations;
    const out = [];
    const toks = this.tokens;
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (t.type !== 'ident' || (t.value !== 'const' && t.value !== 'let' && t.value !== 'var')) continue;
      if (this.isMemberDot(i - 1)) continue;
      let j = i + 1;
      for (;;) {
        const d = toks[j];
        if (!d) break;
        let name = null;
        let pattern = null;
        let k;
        if (d.type === 'ident') { name = String(d.value); k = j + 1; }
        else if (this.isPunct(j, '{') || this.isPunct(j, '[')) { pattern = [j, this.match[j]]; k = this.match[j] + 1; if (k <= 0) break; }
        else break;
        // TypeScript: a type annotation or a definite-assignment `!` before `=`.
        if (this.isPunct(k, '!')) k++;
        if (this.isPunct(k, ':')) {
          let x = k + 1;
          for (; x < toks.length; x++) {
            const tx = toks[x];
            if (isOpener(tx)) { x = Math.max(x, this.match[x]); continue; }
            if (tx.type === 'punct' && (tx.value === '=' || tx.value === ';' || tx.value === ',' || isCloser(tx))) break;
            if (tx.nl && x > k + 1 && endsValue(toks[x - 1]) && startsStatement(tx) && !this.isPunct(x - 1, ':')) break;
          }
          k = x;
        }
        let init = null;
        let end = k;
        if (this.isPunct(k, '=')) { end = this.expressionEnd(k + 1); init = [k + 1, end]; }
        out.push({ name, pattern, kind: String(t.value), index: name ? j : pattern[0], depth: toks[j].depth, init });
        if (this.isPunct(end, ',')) { j = end + 1; continue; }
        break;
      }
    }
    this._declarations = out;
    return out;
  }

  /**
   * The value of identifier `name` as seen at token `at`: the innermost
   * declaration of that name whose block encloses `at`, if it is a `const`
   * with an initialiser; else a relative named import, one hop. Anything
   * else is unknown.
   * @returns {Value}
   */
  resolve(name, at, seen = new Set()) {
    const unknown = { kind: 'unknown', text: name };
    if (seen.has(name) || seen.size > 8) return unknown;
    const nextSeen = new Set(seen).add(name);
    let best = null;
    for (const d of this.declarations) {
      if (d.name !== name) continue;
      // A module-level declaration is in scope everywhere in the file, and
      // a module-level `const` is initialised before any function that
      // uses it can run, so order does not matter at depth 0. A nested one
      // must come before the call, in a block still open at the call.
      if (d.depth > 0 && (d.index >= at || !this.encloses(d, at))) continue;
      if (!best || d.depth > best.depth) best = d;
    }
    if (best) {
      if (best.kind !== 'const' || !best.init) return unknown;
      return this.readValue(best.init[0], best.init[1], nextSeen);
    }
    const b = this.imports.bindings.get(name);
    if (b && b.path.length === 1 && b.module.startsWith('.') && this.env.importedConstant) {
      const v = this.env.importedConstant(this.path, b.module, b.path[0]);
      if (v) return v;
    }
    return unknown;
  }

  /** Whether the block in which declaration d sits is still open at `at`. */
  encloses(d, at) {
    for (let k = d.index; k <= at && k < this.tokens.length; k++) {
      if (this.tokens[k].depth < d.depth) return false;
    }
    return true;
  }

  /**
   * Module-level constants with a literal value (string or number), for
   * other files' imports (DESIGN.md §8.1 step 2).
   * @returns {Map<string, Value>}
   */
  moduleConstants() {
    const out = new Map();
    for (const d of this.declarations) {
      if (!d.name || d.kind !== 'const' || d.depth !== 0 || !d.init) continue;
      const v = this.readValue(d.init[0], d.init[1]);
      if (v.kind === 'string' || v.kind === 'number') out.set(d.name, v);
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Imports and requires

  /**
   * @returns {{ sites: {module: string, line: number, index: number}[],
   *   bindings: Map<string, {module: string, path: string[], line: number}> }}
   *   `path` is the member path from the module object: a default or
   *   namespace import is [], `{ createHash }` is ['createHash'],
   *   `require('elliptic').ec` is ['ec'].
   */
  get imports() {
    if (this._imports) return this._imports;
    const sites = [];
    const bindings = new Map();
    const toks = this.tokens;
    const bind = (local, module, path, line) => { if (local) bindings.set(local, { module: normaliseModule(module), path, line }); };

    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (t.type !== 'ident' || this.isMemberDot(i - 1)) continue;

      // ES import declarations (not `import(` and not `import.meta`).
      if (t.value === 'import' && !this.isPunct(i + 1, '(') && !this.isMemberDot(i + 1)) {
        const first = toks[i + 1];
        if (!first) continue;
        if (first.type === 'string') { sites.push({ module: normaliseModule(first.value), line: t.line, index: i }); continue; }
        // `import type { … }` loads nothing at run time.
        if (first.type === 'ident' && first.value === 'type' && !this.isPunct(i + 2, ',') && !this.isIdent(i + 2, 'from')) continue;
        let j = i + 1;
        const locals = [];
        while (j < Math.min(toks.length, i + 400) && !(this.isIdent(j, 'from') && toks[j + 1]?.type === 'string')) {
          const tj = toks[j];
          if (tj.type === 'punct' && tj.value === ';') break;
          if (tj.type === 'punct' && tj.value === '=') break; // `import x = require(…)` is read below
          if (this.isPunct(j, '*') && this.isIdent(j + 1, 'as') && this.isIdent(j + 2)) { locals.push([String(toks[j + 2].value), []]); j += 3; continue; }
          if (this.isPunct(j, '{')) {
            const close = this.match[j];
            if (close < 0) break;
            let x = j + 1;
            while (x < close) {
              const end = this.entryEnd(x, close);
              const entry = toks.slice(x, end).filter((e) => !(e.type === 'ident' && e.value === 'type' && end - x > 1));
              if (entry.length === 1) locals.push([String(entry[0].value), [String(entry[0].value)]]);
              else if (entry.length === 3 && entry[1].value === 'as') {
                const imported = String(entry[0].value);
                locals.push([String(entry[2].value), imported === 'default' ? [] : [imported]]);
              }
              x = end + 1;
            }
            j = close + 1;
            continue;
          }
          if (tj.type === 'ident' && j === i + 1) locals.push([String(tj.value), []]); // the default import
          j++;
        }
        if (this.isIdent(j, 'from') && toks[j + 1]?.type === 'string') {
          const module = String(toks[j + 1].value);
          sites.push({ module: normaliseModule(module), line: t.line, index: i });
          for (const [local, path] of locals) bind(local, module, path, t.line);
        }
        continue;
      }

      // Re-exports: `export { x } from 'm'`, `export * from 'm'`.
      if (t.value === 'export' && (this.isPunct(i + 1, '{') || this.isPunct(i + 1, '*') || this.isIdent(i + 1, 'type'))) {
        for (let j = i + 1; j < Math.min(toks.length, i + 400); j++) {
          if (this.isPunct(j, ';') || (j > i + 1 && STATEMENT_KEYWORDS.has(String(toks[j].value)) && toks[j].type === 'ident')) break;
          if (this.isIdent(j, 'from') && toks[j + 1]?.type === 'string') {
            sites.push({ module: normaliseModule(toks[j + 1].value), line: t.line, index: i });
            break;
          }
        }
        continue;
      }

      // require('m') and import('m'), with a string literal only: a module
      // name held in a variable is not followed (DESIGN.md §3.2).
      if ((t.value === 'require' || t.value === 'import') && this.isPunct(i + 1, '(')
        && toks[i + 2]?.type === 'string' && this.isPunct(i + 3, ')')) {
        const module = String(toks[i + 2].value);
        sites.push({ module: normaliseModule(module), line: t.line, index: i });
        // Members read straight off it: require('elliptic').ec
        let k = i + 4;
        const members = [];
        while (this.isMemberDot(k) && this.isIdent(k + 1)) { members.push(String(toks[k + 1].value)); k += 2; }
        if (this.isPunct(k, '(') || this.isPunct(k, '[')) continue; // used inline; the call site reads it
        let b = i - 1;
        if (this.isIdent(b, 'await')) b--;
        if (!this.isPunct(b, '=')) continue;
        const target = b - 1;
        if (this.isIdent(target) && !this.isMemberDot(target - 1)) {
          bind(String(toks[target].value), module, members, t.line);
        } else if (this.isPunct(target, '}')) {
          const open = findOpener(this.match, target);
          if (open >= 0) for (const [local, key] of this.patternEntries(open, target)) bind(local, module, [...members, key], t.line);
        }
      }
    }
    this._imports = { sites, bindings };
    return this._imports;
  }

  /**
   * The simple entries of an object destructuring pattern `{ a, b: c, d = 1 }`
   * → [['a','a'], ['c','b'], ['d','d']]. Nested patterns are skipped.
   * @returns {[string, string][]} [local, key]
   */
  patternEntries(open, close) {
    const out = [];
    let x = open + 1;
    while (x < close) {
      const end = this.entryEnd(x, close);
      const k = this.tokens[x];
      if (k && k.type === 'ident' && !this.isPunct(x - 1, '...')) {
        if (this.isPunct(x + 1, ':') && this.isIdent(x + 2) && (x + 3 === end || this.isPunct(x + 3, '='))) out.push([String(this.tokens[x + 2].value), String(k.value)]);
        else if (x + 1 === end || this.isPunct(x + 1, '=')) out.push([String(k.value), String(k.value)]);
      }
      x = end + 1;
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Call sites

  /** @returns {Call[]} */
  get calls() {
    if (this._calls) return this._calls;
    const out = [];
    const toks = this.tokens;
    for (let p = 0; p < toks.length; p++) {
      if (!this.isPunct(p, '(')) continue;
      let q = p - 1;
      if (this.isPunct(q, '?.')) q--; // f?.(x)
      const callee = toks[q];
      if (!callee || callee.type !== 'ident' || NOT_CALLEES.has(String(callee.value))) continue;
      if (!this.isMemberDot(q - 1)) {
        // `function sign(…)`, and class or object methods `sign(data) { … }`,
        // are definitions, not calls: a `sign(` that is not cryptography
        // must never be reported (a test fixture holds each shape).
        if (this.isIdent(q - 1, 'function')) continue;
        if (this.looksLikeDefinition(q, p)) continue;
      }
      const chain = [String(callee.value)];
      let k = q - 1;
      let rootModule = null;
      let rootGroup = null;
      let start = q;
      while (this.isMemberDot(k)) {
        const before = toks[k - 1];
        if (before && before.type === 'ident') { chain.unshift(String(before.value)); start = k - 1; k -= 2; continue; }
        if (before && before.type === 'punct' && before.value === ')') {
          const open = findOpener(this.match, k - 1);
          if (open > 0 && (this.isIdent(open - 1, 'require') || this.isIdent(open - 1, 'import'))
            && toks[open + 1]?.type === 'string' && open + 2 === k - 1) {
            rootModule = normaliseModule(toks[open + 1].value);
            start = open - 1;
          } else if (open >= 0) {
            rootGroup = [open, k - 1];
            start = open;
          }
          break;
        }
        chain.unshift('[]'); // a computed member: the root is not followed
        break;
      }
      out.push({ at: q, open: p, chain, rootModule, rootGroup, isNew: this.isIdent(start - 1, 'new'), start });
    }
    this._calls = out;
    return out;
  }

  /**
   * `name(params) {` or `name(params): Type {` — a method or function body
   * follows, so this is a definition. `cond ? f(x) : { … }` is still a
   * call: a definition never follows `?`, `:`, `=`, `(`, `return` or an
   * operator.
   */
  looksLikeDefinition(nameIndex, open) {
    const close = this.match[open];
    if (close < 0) return false;
    const prev = this.tokens[nameIndex - 1];
    if (prev && prev.type === 'punct' && !['{', '}', ';', ',', ')', '*'].includes(String(prev.value))) return false;
    if (prev && prev.type === 'ident' && ['return', 'typeof', 'await', 'yield', 'case', 'throw', 'new', 'void', 'in', 'of'].includes(String(prev.value))) return false;
    if (this.isPunct(close + 1, '{')) return true;
    if (this.isPunct(close + 1, ':')) {
      // A TypeScript return type, then the body.
      for (let x = close + 2; x < Math.min(this.tokens.length, close + 60); x++) {
        const t = this.tokens[x];
        if (t.type === 'punct' && t.value === '{') return true;
        if (isOpener(t)) { x = Math.max(x, this.match[x]); continue; }
        if (t.type === 'punct' && (t.value === ';' || t.value === ',' || t.value === '=>' || t.value === ')' || t.value === '=')) return false;
      }
    }
    return false;
  }

  /**
   * The module and member path a call reaches through an import or a
   * require, or null when its root is not bound to a module.
   * @param {Call} call
   * @returns {{ module: string, path: string[] } | null}
   */
  resolveCall(call) {
    if (call.rootModule) return { module: call.rootModule, path: call.chain };
    if (call.rootGroup || call.chain[0] === '[]') return null;
    const b = this.imports.bindings.get(call.chain[0]);
    if (!b) return null;
    return { module: b.module, path: [...b.path, ...call.chain.slice(1)] };
  }

  // -------------------------------------------------------------------------
  // Words near a line (DESIGN.md §8.4)

  /** Identifiers and comment words on `line` and the lines above it, then the file name's words. */
  wordsNear(line) {
    const from = Math.max(1, line - WORD_WINDOW_LINES);
    const words = [];
    // Nearest lines first, so the reason names the closest word.
    const byLine = new Map();
    // Tokens are in line order: find the first on line `from` by bisection.
    let lo = 0;
    let hi = this.tokens.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.tokens[mid].line < from) lo = mid + 1; else hi = mid;
    }
    for (let x = lo; x < this.tokens.length; x++) {
      const t = this.tokens[x];
      if (t.line > line) break;
      if (t.type !== 'ident') continue;
      if (!byLine.has(t.line)) byLine.set(t.line, []);
      byLine.get(t.line).push(...splitWords(String(t.value)));
    }
    for (const c of this.comments) {
      if (c.endLine < from || c.line > line) continue;
      const l = Math.min(line, Math.max(from, c.line));
      if (!byLine.has(l)) byLine.set(l, []);
      byLine.get(l).push(...splitWords(c.text));
    }
    for (let l = line; l >= from; l--) words.push(...(byLine.get(l) ?? []));
    words.push(...this.baseWords);
    return words;
  }
}

/** 'node:crypto' → 'crypto'; other specifiers unchanged. */
export function normaliseModule(specifier) {
  const s = String(specifier);
  return s.startsWith('node:') ? s.slice(5) : s;
}

function isOpener(t) {
  return Boolean(t) && ((t.type === 'punct' && t.value in OPENERS) || t.type === 'template-head');
}

function isCloser(t) {
  return Boolean(t) && ((t.type === 'punct' && t.value in CLOSERS) || t.type === 'template-tail');
}

// A token that can end an expression, and one that can start a statement:
// together, with a line break between them, the statement has ended.
function endsValue(t) {
  if (!t) return false;
  if (t.type === 'ident') return !['return', 'typeof', 'new', 'await', 'yield', 'void', 'delete', 'in', 'of', 'instanceof', 'case'].includes(String(t.value));
  if (t.type === 'punct') return t.value === ')' || t.value === ']' || t.value === '}' || t.value === '++' || t.value === '--';
  return true; // literals, templates, regular expressions
}

function startsStatement(t) {
  if (t.type === 'ident' || t.type === 'string' || t.type === 'number' || t.type === 'template' || t.type === 'template-head' || t.type === 'regex') {
    // `as`, `satisfies`, `in`, `of`, `instanceof` continue an expression.
    return !(t.type === 'ident' && ['as', 'satisfies', 'in', 'of', 'instanceof'].includes(String(t.value)));
  }
  return t.type === 'punct' && (t.value === '{' || t.value === '@' || t.value === '++' || t.value === '--' || t.value === '!');
}

/**
 * The matching bracket of every opener and closer, -1 where there is none.
 * Mismatched input (TypeScript generics are not brackets here; broken
 * files happen) is tolerated: a closer that does not match the innermost
 * opener closes the nearest opener of its own kind, if there is one close.
 */
function matchBrackets(tokens) {
  const match = new Array(tokens.length).fill(-1);
  const stack = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (isOpener(t)) { stack.push(i); continue; }
    if (t.type === 'template-middle') continue;
    if (!isCloser(t)) continue;
    const want = t.type === 'template-tail' ? 'template-head' : CLOSERS[t.value];
    for (let s = stack.length - 1; s >= Math.max(0, stack.length - 4); s--) {
      const o = tokens[stack[s]];
      const kind = o.type === 'template-head' ? 'template-head' : o.value;
      if (kind === want) {
        match[stack[s]] = i;
        match[i] = stack[s];
        stack.length = s;
        break;
      }
    }
  }
  return match;
}

function findOpener(match, closeIndex) {
  return match[closeIndex];
}

/** Two values name the same algorithm: equal strings, or objects with equal `name` fields. */
function sameAlgorithm(src, a, b) {
  if (a.kind === 'string' && b.kind === 'string') return a.value === b.value;
  if (a.kind === 'number' && b.kind === 'number') return a.value === b.value;
  if (a.kind === 'object' && b.kind === 'object') {
    const na = src.fieldString(a, 'name');
    const nb = src.fieldString(b, 'name');
    return typeof na === 'string' && na === nb;
  }
  return false;
}

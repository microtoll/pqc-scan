// A tokenizer for JavaScript and TypeScript, deep enough to tell code from
// strings, template literals, regular expressions and comments, and no
// deeper. It never builds a syntax tree and never evaluates anything
// (DESIGN.md §3.1: "a tokenizer, not a parser and not a grep").
//
// Why a tokenizer at all: a regular expression over raw text reports
// `// we used to call crypto.subtle.encrypt('RSA-OAEP')` as a call. Here a
// comment is a comment, a string is a string, and only code tokens are
// matched by the detectors.
//
// Resilience over strictness: the input may be TypeScript, JSX, or simply
// broken. An unterminated string ends at the end of its line, an
// unterminated block comment at the end of the file; nothing throws.

/**
 * @typedef {object} Token
 * @property {'ident'|'string'|'template'|'template-head'|'template-middle'|'template-tail'|'number'|'regex'|'punct'} type
 *   `template` is a template literal with no `${…}`; one with substitutions
 *   is split into head, middle(s) and tail, and the code inside each
 *   substitution is tokenized as ordinary code (it is code).
 * @property {string|number} value  identifier or punctuator text; a string's
 *   contents with simple escapes applied; a number's numeric value.
 * @property {string} raw     the source text of the token
 * @property {number} start   offset of the first character
 * @property {number} end     offset after the last character
 * @property {number} line    1-based line of the first character
 * @property {number} col     1-based column of the first character
 * @property {boolean} nl     a line break comes between this token and the previous one
 * @property {number} depth   braces `{…}` open around the token (see computeDepths)
 */

/**
 * @typedef {object} Comment
 * @property {string} text
 * @property {number} line
 * @property {number} endLine
 */

// After these keywords an expression starts, so `/` begins a regular
// expression, not a division: `return /x/.test(s)`, `typeof /x/`.
const KEYWORDS_BEFORE_EXPRESSION = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
  'throw', 'case', 'do', 'else', 'yield', 'await',
]);

// Multi-character punctuators, longest first so that `>>>=` is not read as
// `>>` then `>=`. `?.` is handled separately (see below).
const PUNCTUATORS = [
  '>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '++', '--', '+=', '-=', '*=',
  '%=', '&=', '|=', '^=', '**', '<<', '>>',
];

const IDENT_START = /[A-Za-z_$\u0080-\uffff]/;
const IDENT_REST = /[\w$\u0080-\uffff]/;
// Hex, octal, binary, decimal with fraction and exponent, numeric separators
// (`310_000`), and BigInt's `n`.
const NUMBER = /(?:0[xX][\da-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?)n?/y;

const SIMPLE_ESCAPES = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', v: '\v', 0: '\0' };

/**
 * Tokenizes source text.
 * @param {string} source
 * @returns {{ tokens: Token[], comments: Comment[] }}
 */
export function tokenize(source) {
  const text = String(source);
  const len = text.length;
  /** @type {Token[]} */
  const tokens = [];
  /** @type {Comment[]} */
  const comments = [];
  // What each open `{` belongs to, so that a `}` knows whether it closes a
  // block or object (a punctuator) or a template substitution (the template
  // literal resumes).
  /** @type {('brace'|'template')[]} */
  const braces = [];

  let i = 0;
  let line = 1;
  let lineStart = 0;
  let sawNewline = true;

  if (text.charCodeAt(0) === 0xfeff) i = 1; // a byte-order mark
  // A hashbang line (`#!/usr/bin/env node`) is not JavaScript.
  if (text.startsWith('#!', i)) while (i < len && !isLineBreak(text, i)) i++;

  const push = (type, value, start, startLine, startCol) => {
    tokens.push({
      type, value, raw: text.slice(start, i), start, end: i,
      line: startLine, col: startCol, nl: sawNewline, depth: 0,
    });
    sawNewline = false;
  };

  // Advances past one line break at `i` (\n, \r\n, lone \r, U+2028, U+2029),
  // keeping the line count. The same set splitLines() uses.
  const newline = () => {
    if (text[i] === '\r' && text[i + 1] === '\n') i += 2; else i += 1;
    line++;
    lineStart = i;
  };

  // Reads template characters from `i` up to the closing backtick or the
  // next `${`. Returns which one ended it.
  const scanTemplate = () => {
    let value = '';
    while (i < len) {
      const c = text[i];
      if (c === '`') { i++; return { value, ended: 'end' }; }
      if (c === '$' && text[i + 1] === '{') { i += 2; return { value, ended: 'subst' }; }
      if (c === '\\') {
        const r = readEscape();
        value += r;
        continue;
      }
      if (isLineBreak(text, i)) { value += '\n'; newline(); continue; }
      value += c;
      i++;
    }
    return { value, ended: 'eof' };
  };

  // Reads one escape sequence at `i` (which is a backslash). Line
  // continuations keep the line count right.
  const readEscape = () => {
    i++; // the backslash
    if (i >= len) return '';
    const c = text[i];
    if (isLineBreak(text, i)) { newline(); return ''; }
    if (c in SIMPLE_ESCAPES) { i++; return SIMPLE_ESCAPES[c]; }
    if (c === 'x' && /^[\da-fA-F]{2}$/.test(text.slice(i + 1, i + 3))) {
      const v = String.fromCharCode(parseInt(text.slice(i + 1, i + 3), 16));
      i += 3;
      return v;
    }
    if (c === 'u') {
      const braced = /^\{([\da-fA-F]{1,6})\}/.exec(text.slice(i + 1, i + 10));
      if (braced) { i += 1 + braced[0].length; return safeCodePoint(parseInt(braced[1], 16)); }
      if (/^[\da-fA-F]{4}$/.test(text.slice(i + 1, i + 5))) {
        const v = String.fromCharCode(parseInt(text.slice(i + 1, i + 5), 16));
        i += 5;
        return v;
      }
    }
    i++;
    return c;
  };

  while (i < len) {
    const c = text[i];

    if (isLineBreak(text, i)) { newline(); sawNewline = true; continue; }
    if (c === ' ' || c === '\t' || c === '\f' || c === '\v' || c === '\u00a0' || c === '\ufeff') { i++; continue; }

    const startLine = line;
    const startCol = i - lineStart + 1;
    const start = i;

    // Comments. Kept apart from the tokens: the detectors never match inside
    // them, but the priority heuristic reads their words (DESIGN.md §8.4).
    if (c === '/' && text[i + 1] === '/') {
      while (i < len && !isLineBreak(text, i)) i++;
      comments.push({ text: text.slice(start + 2, i), line: startLine, endLine: startLine });
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < len && !(text[i] === '*' && text[i + 1] === '/')) {
        if (isLineBreak(text, i)) { newline(); sawNewline = true; } else i++;
      }
      const body = text.slice(start + 2, Math.min(i, len));
      if (i < len) i += 2; // unterminated: the rest of the file is the comment
      comments.push({ text: body, line: startLine, endLine: line });
      continue;
    }

    // Strings. A quote inside a string of the other kind, or inside a
    // template, never ends anything: `"it's"`, `` `it's` ``.
    if (c === '"' || c === "'") {
      i++;
      let value = '';
      while (i < len && text[i] !== c) {
        if (text[i] === '\\') { value += readEscape(); continue; }
        // An unescaped line break ends an unterminated string (resilience:
        // one broken line must not swallow the rest of the file).
        if (isLineBreak(text, i)) break;
        value += text[i];
        i++;
      }
      if (text[i] === c) i++;
      push('string', value, start, startLine, startCol);
      continue;
    }

    if (c === '`') {
      i++;
      const t = scanTemplate();
      if (t.ended === 'subst') {
        push('template-head', t.value, start, startLine, startCol);
        braces.push('template');
      } else {
        push('template', t.value, start, startLine, startCol);
      }
      continue;
    }

    if (c === '{') {
      i++;
      braces.push('brace');
      push('punct', '{', start, startLine, startCol);
      continue;
    }
    if (c === '}') {
      i++;
      const owner = braces.pop();
      if (owner === 'template') {
        // The `}` closing `${…}`: the template literal carries on.
        const t = scanTemplate();
        if (t.ended === 'subst') {
          push('template-middle', t.value, start, startLine, startCol);
          braces.push('template');
        } else {
          push('template-tail', t.value, start, startLine, startCol);
        }
      } else {
        push('punct', '}', start, startLine, startCol);
      }
      continue;
    }

    // Numbers, including `.5`.
    if (isDigit(c) || (c === '.' && isDigit(text[i + 1]))) {
      NUMBER.lastIndex = i;
      const m = NUMBER.exec(text);
      const raw = m ? m[0] : c;
      i += raw.length;
      const cleaned = raw.replace(/_/g, '').replace(/n$/, '');
      const value = Number(cleaned);
      push('number', Number.isNaN(value) ? cleaned : value, start, startLine, startCol);
      continue;
    }

    // Identifiers and keywords (the detectors tell them apart by value),
    // and `#private` class members.
    if (IDENT_START.test(c) || (c === '#' && IDENT_START.test(text[i + 1] ?? ''))) {
      i++;
      while (i < len && IDENT_REST.test(text[i])) i++;
      push('ident', text.slice(start, i), start, startLine, startCol);
      continue;
    }

    // A slash: a regular expression or a division. The classic rule: a
    // regular expression can only start where an expression can start,
    // which the previous token decides.
    if (c === '/') {
      if (regexAllowedAfter(tokens[tokens.length - 1])) {
        const endOfRegex = scanRegex(text, i);
        if (endOfRegex > 0) {
          i = endOfRegex;
          push('regex', text.slice(start, i), start, startLine, startCol);
          continue;
        }
      }
      i += text[i + 1] === '=' ? 2 : 1;
      push('punct', text.slice(start, i), start, startLine, startCol);
      continue;
    }

    // Optional chaining `?.` — but `a?.5:b` is a conditional with `.5`.
    if (c === '?' && text[i + 1] === '.' && !isDigit(text[i + 2])) {
      i += 2;
      push('punct', '?.', start, startLine, startCol);
      continue;
    }

    const p = PUNCTUATORS.find((op) => text.startsWith(op, i));
    i += p ? p.length : 1;
    push('punct', p ?? c, start, startLine, startCol);
  }

  computeDepths(tokens);
  return { tokens, comments };
}

/**
 * Splits text into lines at exactly the line breaks tokenize() counts, so
 * that `lines[token.line - 1]` is the token's line.
 * @param {string} source
 * @returns {string[]}
 */
export function splitLines(source) {
  return String(source).split(/\r\n|\n|\r|\u2028|\u2029/);
}

/**
 * Brace depth of each token: the number of `{…}` open around it. For `{`
 * itself, the depth outside it; for `}`, the depth after it closes. A
 * template substitution `${…}` counts as a brace, so the numbers stay
 * balanced. Used to tell whether a `const` is still in scope at a call
 * (DESIGN.md §8.1).
 * @param {Token[]} tokens
 */
function computeDepths(tokens) {
  let depth = 0;
  for (const t of tokens) {
    if (t.type === 'punct' && t.value === '{') { t.depth = depth; depth++; continue; }
    if (t.type === 'template-head') { t.depth = depth; depth++; continue; }
    if ((t.type === 'punct' && t.value === '}') || t.type === 'template-tail') {
      depth = Math.max(0, depth - 1);
      t.depth = depth;
      continue;
    }
    if (t.type === 'template-middle') { t.depth = Math.max(0, depth - 1); continue; }
    t.depth = depth;
  }
}

/**
 * @param {Token|undefined} prev the previous token
 * @returns {boolean} whether a `/` here starts a regular expression
 */
function regexAllowedAfter(prev) {
  if (!prev) return true;
  if (prev.type === 'ident') return KEYWORDS_BEFORE_EXPRESSION.has(/** @type {string} */ (prev.value));
  if (prev.type === 'number' || prev.type === 'string' || prev.type === 'template'
    || prev.type === 'template-tail' || prev.type === 'regex') return false;
  if (prev.type === 'template-head' || prev.type === 'template-middle') return true;
  // After `)`, `]` or `}` a slash is taken as division. This misreads
  // `if (x) /re/.test(s)` and a regular expression starting a statement
  // after a block; both are rare, and the cost is one missed call site, not
  // a false report.
  return !(prev.value === ')' || prev.value === ']' || prev.value === '}' || prev.value === '++' || prev.value === '--');
}

/**
 * Scans a regular expression literal starting at `start` (a slash). A slash
 * inside a character class `[/]` does not end it. Returns the offset after
 * the flags, or -1 when a line break or the end of the text comes first —
 * then it was not a regular expression after all.
 */
function scanRegex(text, start) {
  let i = start + 1;
  let inClass = false;
  while (i < text.length) {
    const c = text[i];
    if (isLineBreak(text, i)) return -1;
    if (c === '\\') { i += 2; continue; }
    if (c === '[') inClass = true;
    else if (c === ']') inClass = false;
    else if (c === '/' && !inClass) {
      i++;
      while (i < text.length && IDENT_REST.test(text[i])) i++;
      return i;
    }
    i++;
  }
  return -1;
}

function isLineBreak(text, i) {
  const c = text[i];
  return c === '\n' || c === '\r' || c === '\u2028' || c === '\u2029';
}

function isDigit(c) {
  return c !== undefined && c >= '0' && c <= '9';
}

function safeCodePoint(n) {
  try { return String.fromCodePoint(n); } catch { return ''; }
}

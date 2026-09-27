// The tokenizer: code told apart from strings, templates, regular
// expressions and comments (DESIGN.md §3.1). Every case here is a way a
// grep would have reported a call that is not one, or missed one that is.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tokenize, splitLines } from '../src/index.js';

const kinds = (src) => tokenize(src).tokens.map((t) => [t.type, t.value]);
const idents = (src) => tokenize(src).tokens.filter((t) => t.type === 'ident').map((t) => t.value);

test('a mention in a line or block comment is not code', () => {
  const src = "// crypto.subtle.encrypt('RSA-OAEP')\n/* createHash('md5') */ x();";
  const { tokens, comments } = tokenize(src);
  assert.deepEqual(tokens.map((t) => t.value), ['x', '(', ')', ';']);
  assert.equal(comments.length, 2);
  assert.match(comments[0].text, /subtle\.encrypt/);
  assert.equal(comments[1].line, 2);
});

test('a mention in a string is one string token', () => {
  assert.deepEqual(kinds("log('call subtle.sign(key) now');"), [
    ['ident', 'log'], ['punct', '('], ['string', 'call subtle.sign(key) now'], ['punct', ')'], ['punct', ';'],
  ]);
});

test("a ' inside a template literal never ends a string", () => {
  const src = "const s = `it's ${name}'s key`; subtle.digest('SHA-256', d);";
  const t = tokenize(src).tokens;
  assert.deepEqual(t.slice(3, 7).map((x) => [x.type, x.value]), [
    ['template-head', "it's "], ['ident', 'name'], ['template-tail', "'s key"], ['punct', ';'],
  ]);
  assert.ok(idents(src).includes('subtle'));
  assert.ok(t.some((x) => x.type === 'string' && x.value === 'SHA-256'));
});

test('code inside ${…} is tokenized as code, with nested templates and braces', () => {
  const src = '`a ${ `b ${ {k: 1}.k } c` } d ${ f("x") } e`';
  const t = tokenize(src).tokens;
  assert.deepEqual(t.map((x) => x.type), [
    'template-head', 'template-head', 'punct', 'ident', 'punct', 'number', 'punct', 'punct', 'ident',
    'template-tail', 'template-middle', 'ident', 'punct', 'string', 'punct', 'template-tail',
  ]);
  assert.equal(t[t.length - 1].value, ' e');
});

test('a template with no substitution is one template token with its text', () => {
  assert.deepEqual(kinds('f(`AES-GCM`)'), [['ident', 'f'], ['punct', '('], ['template', 'AES-GCM'], ['punct', ')']]);
});

test('regular expressions: quotes and slashes inside them are not strings or comments', () => {
  const src = "const r = /'[^/]*\\/\\/x/g; const q = /\"/; call();";
  const t = tokenize(src).tokens;
  const regexes = t.filter((x) => x.type === 'regex').map((x) => x.value);
  assert.deepEqual(regexes, ["/'[^/]*\\/\\/x/g", '/"/']);
  assert.ok(idents(src).includes('call'));
  assert.equal(tokenize(src).comments.length, 0);
});

test('division is not a regular expression', () => {
  const t = tokenize('const x = a / b / c; const y = (a) / 2; const z = arr[0] / 3;').tokens;
  assert.equal(t.filter((x) => x.type === 'regex').length, 0);
  assert.equal(t.filter((x) => x.value === '/').length, 4);
});

test('a regular expression after return, typeof and an opening bracket', () => {
  const t = tokenize("return /a'b/.test(s); f(/x\"y/); typeof /z/;").tokens;
  assert.equal(t.filter((x) => x.type === 'regex').length, 3);
  assert.equal(t.filter((x) => x.type === 'string').length, 0);
});

test('escapes in strings are applied; the raw text is kept', () => {
  const [t] = tokenize("'SHA\\x2d256\\u0021\\n'").tokens;
  assert.equal(t.value, 'SHA-256!\n');
  assert.equal(t.raw, "'SHA\\x2d256\\u0021\\n'");
});

test('an unterminated string ends at its line; the next line is still code', () => {
  const t = tokenize("const a = 'broken\ncrypto.createHash('sha1');").tokens;
  assert.equal(t[3].type, 'string');
  assert.equal(t[3].value, 'broken');
  assert.deepEqual(t.slice(4, 8).map((x) => x.value), ['crypto', '.', 'createHash', '(']);
  assert.equal(t[4].line, 2);
  assert.equal(t[4].nl, true);
});

test('an unterminated block comment runs to the end of the file', () => {
  const { tokens, comments } = tokenize('a(); /* never closed\n subtle.sign()');
  assert.deepEqual(tokens.map((t) => t.value), ['a', '(', ')', ';']);
  assert.equal(comments.length, 1);
});

test('lines and columns, across \\n, \\r\\n and a lone \\r', () => {
  const t = tokenize('a\r\n  b\rc\n\n   d').tokens;
  assert.deepEqual(t.map((x) => [x.value, x.line, x.col]), [['a', 1, 1], ['b', 2, 3], ['c', 3, 1], ['d', 5, 4]]);
  assert.deepEqual(splitLines('a\r\n  b\rc\n\n   d'), ['a', '  b', 'c', '', '   d']);
});

test('line counting stays right through multi-line templates and comments', () => {
  const t = tokenize('`one\ntwo\n${x}\nthree`\n/* a\nb */\nlast').tokens;
  const last = t[t.length - 1];
  assert.equal(last.value, 'last');
  assert.equal(last.line, 7);
});

test('numbers: separators, hex, exponent, BigInt and a leading dot', () => {
  const nums = tokenize('310_000 0xff 1e3 10n .5 2048').tokens.map((t) => t.value);
  assert.deepEqual(nums, [310000, 255, 1000, 10, 0.5, 2048]);
});

test('optional chaining is one punctuator; a?.5:b is not', () => {
  assert.deepEqual(tokenize('crypto?.subtle?.digest').tokens.map((t) => t.value), ['crypto', '?.', 'subtle', '?.', 'digest']);
  assert.deepEqual(tokenize('a?.5:b').tokens.map((t) => t.value), ['a', '?', 0.5, ':', 'b']);
});

test('a hashbang line and a byte-order mark are skipped', () => {
  assert.deepEqual(tokenize('\ufeff#!/usr/bin/env node\nrun();').tokens.map((t) => t.value), ['run', '(', ')', ';']);
});

test('private class members and decorators', () => {
  assert.deepEqual(tokenize('@dec class A { #key = 1 }').tokens.map((t) => t.value), ['@', 'dec', 'class', 'A', '{', '#key', '=', 1, '}']);
});

test('brace depth: tokens know how many blocks enclose them', () => {
  const t = tokenize('const a = 1; function f() { const b = { c: 2 }; } x;').tokens;
  const depthOf = (v) => t.find((x) => x.value === v).depth;
  assert.equal(depthOf('a'), 0);
  assert.equal(depthOf('b'), 1);
  assert.equal(depthOf('c'), 2);
  assert.equal(depthOf('x'), 0);
});

test('TypeScript shapes tokenize without surprises', () => {
  const src = "const k: Record<string, Array<number>> = { a: [1] } as const;\nlet x = <T,>(v: T): T => v;\nimport type { A } from './a';";
  const t = tokenize(src).tokens;
  assert.ok(t.some((x) => x.value === '>>'));
  assert.equal(t.filter((x) => x.type === 'string').length, 1);
  assert.equal(t.filter((x) => x.type === 'regex').length, 0);
});

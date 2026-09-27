// TLS configuration where it is written down (DESIGN.md §3.1, §8.6):
// nginx, Apache and Caddy files, and Node's tls/https/http2 options.
// For each: the protocols, the ciphers, the key-exchange groups, and
// whether a post-quantum hybrid group is among them.
import { TLS_LOW } from '../catalogue.js';

// A group name that carries a post-quantum component: the hybrids
// (X25519MLKEM768, SecP256r1MLKEM768, X-Wing, the Kyber drafts) and pure
// ML-KEM groups (MLKEM768).
const PQ_GROUP = /mlkem|kyber|x-?wing/i;

// Protocol versions RFC 8996 deprecates, and SSL.
const OLD_PROTOCOL = /^(\+|-)?(sslv2|sslv3|tlsv1|tlsv1\.0|tlsv1\.1|tls1\.0|tls1\.1|tls1|tlsv1_method|tlsv1_1_method)$/i;
// Cipher-string elements that are weak on classical grounds, when enabled
// (not preceded by `!` or `-`).
const WEAK_CIPHER = /(^|[-_])(rc4|3des|des-cbc3?|des|md5|null|export|exp|anull|enull)($|[-_])/i;

const NOTE = {
  groupsUnstated: {
    code: 'groups-unstated',
    text: 'No key-exchange groups are listed, so the TLS library\'s defaults apply: OpenSSL 3.5 and later offer X25519MLKEM768 by default, older versions do not. Check the server\'s OpenSSL version.',
  },
  caddyUnstated: {
    code: 'groups-unstated',
    text: 'No curves are listed, so Caddy\'s defaults apply: releases built with Go 1.24 or later offer X25519MLKEM768 by default. Check the Caddy version.',
  },
  nodeUnstated: {
    code: 'groups-unstated',
    text: 'No ecdhCurve is set, so Node\'s OpenSSL defaults apply: OpenSSL 3.5 and later offer X25519MLKEM768 by default. Check the Node version\'s OpenSSL (process.versions.openssl).',
  },
  hybridNeedsTls13: { code: 'hybrid-needs-tls13', text: 'A hybrid group is listed but TLS 1.3 is not enabled; hybrid groups are only negotiated in TLS 1.3.' },
  oldProtocol: { code: 'old-protocol', text: 'SSL, TLS 1.0 or TLS 1.1 is enabled: turn them off (RFC 8996), on classical grounds.' },
  weakCiphers: { code: 'weak-ciphers', text: 'The cipher list enables RC4, DES, 3DES, MD5, NULL or export ciphers: remove them, on classical grounds.' },
  dynamic: { code: 'options-not-literal', text: 'The TLS options are not written here: check them by hand.' },
};

/**
 * @typedef {object} TlsEntry
 * @property {string} file
 * @property {number} line
 * @property {'nginx'|'apache'|'caddy'|'node'} server
 * @property {string|null} setting        for Node, the call (`https.createServer`)
 * @property {string[]|null} protocols
 * @property {string|null} ciphers
 * @property {string[]|null} groups
 * @property {string[]} hybridGroups
 * @property {'hybrid'|'classical-only'|'mixed'|'unstated'|'dynamic'} keyExchange
 * @property {'low'|null} priority
 * @property {string|null} priorityReason
 * @property {string|null} replacement
 * @property {{code: string, text: string}[]} notes
 * @property {string} evidence
 * @property {boolean} inTest
 */

/** Whether a file name is one the scanner reads as possible TLS configuration. */
export function isTlsCandidate(name) {
  return /\.conf(\.[\w-]+)?$/i.test(name) || /^(nginx|httpd|apache2?|ssl)([.\w-]*)$/i.test(name)
    || /^caddyfile([.\w-]*)$/i.test(name) || /\.caddyfile$/i.test(name);
}

/**
 * Reads one configuration file. Returns no entry when the file holds no TLS
 * settings (most .conf files are not web servers').
 * @returns {TlsEntry[]}
 */
export function readTlsConfigFile(path, text, inTest = false) {
  const base = path.split('/').pop();
  if (/^caddyfile/i.test(base) || /\.caddyfile$/i.test(base)) return readCaddy(path, text, inTest);
  if (/^\s*SSL(Engine|Protocol|CipherSuite|OpenSSLConfCmd|CertificateFile)\b/im.test(text)) return readApache(path, text, inTest);
  return readNginx(path, text, inTest);
}

// ---------------------------------------------------------------------------
// nginx

/** nginx statements: words up to `;` or `{`, with `#` comments and quotes handled. */
export function nginxStatements(text) {
  const out = [];
  let words = [];
  let word = '';
  let quote = null;
  let line = 1;
  let startLine = null;
  const endWord = () => { if (word) { words.push(word); word = ''; } };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\n') line++;
    if (quote) {
      if (c === '\\' && i + 1 < text.length) { word += text[++i]; continue; }
      if (c === quote) { quote = null; continue; }
      word += c;
      continue;
    }
    if (c === '#') { while (i + 1 < text.length && text[i + 1] !== '\n') i++; continue; }
    if (c === '"' || c === "'") { quote = c; if (startLine === null) startLine = line; continue; }
    if (c === ';' || c === '{' || c === '}') {
      endWord();
      if (words.length) out.push({ words, line: startLine ?? line, block: c === '{' });
      words = [];
      startLine = null;
      continue;
    }
    if (/\s/.test(c)) { endWord(); continue; }
    if (startLine === null) startLine = line;
    word += c;
  }
  return out;
}

function readNginx(path, text, inTest) {
  const statements = nginxStatements(text);
  const lines = text.split(/\r?\n/);
  const isTls = statements.some((s) => /^ssl_/.test(s.words[0]) || (s.words[0] === 'listen' && s.words.includes('ssl')));
  if (!isTls) return [];
  let protocols = null;
  let ciphers = null;
  const groupSettings = [];
  let firstLine = null;
  for (const s of statements) {
    const [d, ...rest] = s.words;
    if (/^ssl_/.test(d) || d === 'listen') firstLine ??= s.line;
    if (d === 'ssl_protocols') protocols = [...new Set([...(protocols ?? []), ...rest])];
    else if (d === 'ssl_ciphers') ciphers = rest.join(' ');
    else if (d === 'ssl_ecdh_curve' && rest[0] && rest[0].toLowerCase() !== 'auto') groupSettings.push({ groups: rest.join(':').split(':'), line: s.line });
    else if (d === 'ssl_conf_command' && /^(groups|curves)$/i.test(rest[0] ?? '') && rest[1]) groupSettings.push({ groups: rest.slice(1).join(':').split(':'), line: s.line });
  }
  return [entry({ path, lines, inTest, server: 'nginx', protocols, ciphers, groupSettings, line: firstLine ?? 1, unstatedNote: NOTE.groupsUnstated })];
}

// ---------------------------------------------------------------------------
// Apache httpd (mod_ssl)

function readApache(path, text, inTest) {
  const lines = text.split(/\r?\n/);
  let protocols = null;
  let ciphers = null;
  const groupSettings = [];
  let firstLine = null;
  // Join `\`-continued lines, keeping the first line's number.
  const logical = [];
  for (let i = 0; i < lines.length; i++) {
    let l = lines[i];
    const n = i + 1;
    while (/\\\s*$/.test(l) && i + 1 < lines.length) l = l.replace(/\\\s*$/, ' ') + lines[++i];
    logical.push({ text: l, line: n });
  }
  for (const { text: l, line } of logical) {
    const trimmed = l.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const words = trimmed.split(/\s+/).map((w) => w.replace(/^"|"$/g, ''));
    const d = words[0].toLowerCase();
    if (/^ssl/.test(d)) firstLine ??= line;
    if (d === 'sslprotocol') protocols = words.slice(1);
    else if (d === 'sslciphersuite') ciphers = words[words.length - 1];
    else if (d === 'sslopensslconfcmd' && /^(curves|groups)$/i.test(words[1] ?? '') && words[2]) groupSettings.push({ groups: words.slice(2).join(':').split(':'), line });
  }
  if (firstLine === null) return [];
  return [entry({ path, lines, inTest, server: 'apache', protocols, ciphers, groupSettings, line: firstLine, unstatedNote: NOTE.groupsUnstated })];
}

// ---------------------------------------------------------------------------
// Caddy (Caddyfile)

function readCaddy(path, text, inTest) {
  const lines = text.split(/\r?\n/);
  let protocols = null;
  let ciphers = null;
  const groupSettings = [];
  let depth = 0;
  let tlsDepth = null;
  let tlsLine = null;
  let siteLine = null;
  for (let i = 0; i < lines.length; i++) {
    const noComment = lines[i].replace(/(^|\s)#.*$/, '');
    const words = noComment.trim().split(/\s+/).filter(Boolean);
    if (!words.length) continue;
    if (depth === 0 && words[words.length - 1] === '{' && siteLine === null) siteLine = i + 1;
    if (tlsDepth !== null && depth === tlsDepth + 1) {
      if (words[0] === 'protocols') protocols = words.slice(1).filter((w) => w !== '{' && w !== '}');
      if (words[0] === 'curves') groupSettings.push({ groups: words.slice(1).filter((w) => w !== '{' && w !== '}'), line: i + 1 });
      if (words[0] === 'ciphers') ciphers = words.slice(1).join(' ');
    }
    if (words[0] === 'tls' && words[words.length - 1] === '{') { tlsDepth = depth; tlsLine ??= i + 1; }
    for (const w of words) {
      if (w === '{') depth++;
      if (w === '}') { depth--; if (tlsDepth !== null && depth === tlsDepth) tlsDepth = null; }
    }
  }
  // Every Caddyfile serves HTTPS by default, so one entry either way.
  return [entry({ path, lines, inTest, server: 'caddy', protocols, ciphers, groupSettings, line: tlsLine ?? siteLine ?? 1, unstatedNote: NOTE.caddyUnstated })];
}

// ---------------------------------------------------------------------------
// Node: tls, https, http2 options

// Servers are always reported: they are where the key exchange is set.
const NODE_SERVERS = new Set(['tls.createServer', 'tls.createSecureContext', 'https.createServer', 'http2.createSecureServer']);
// Clients only when they write a TLS field.
const NODE_CLIENTS = new Set(['tls.connect', 'https.request', 'https.get', 'https.Agent', 'http2.connect']);
const NODE_TLS_FIELDS = ['minVersion', 'maxVersion', 'ciphers', 'ecdhCurve', 'secureProtocol'];

/**
 * @param {import('../source.js').SourceFile} src
 * @returns {TlsEntry[]}
 */
export function detectNodeTls(src) {
  const out = [];
  for (const call of src.calls) {
    const r = src.resolveCall(call);
    if (!r || !['tls', 'https', 'http2'].includes(r.module)) continue;
    const setting = [r.module, ...r.path].join('.');
    const isServer = NODE_SERVERS.has(setting);
    if (!isServer && !NODE_CLIENTS.has(setting)) continue;
    // The options object: the first argument that is (or resolves to) an
    // object literal.
    let opts = null;
    let unread = false;
    for (const [s, e] of src.args(call.open)) {
      const v = src.readValue(s, e);
      if (v.kind === 'object') { opts = v; break; }
      if (v.kind === 'unknown' && src.isIdent(s) && e - s === 1) unread = true;
    }
    const t = src.tokens[call.at];
    const read = (key) => {
      const v = opts ? src.field(opts, key) : undefined;
      return v && v.kind === 'string' ? v.value : (v === undefined ? undefined : null);
    };
    const fields = Object.fromEntries(NODE_TLS_FIELDS.map((k) => [k, read(k)]));
    const written = Object.values(fields).some((v) => v !== undefined);
    if (!isServer && !written) continue;
    if (!opts && unread) {
      out.push(finish({
        file: src.path, line: t.line, server: 'node', setting, protocols: null, ciphers: null, groups: null,
        hybridGroups: [], keyExchange: 'dynamic', notes: [NOTE.dynamic], evidence: src.evidence(t.line), inTest: src.inTest,
      }));
      continue;
    }
    const protocols = [fields.minVersion && `min ${fields.minVersion}`, fields.maxVersion && `max ${fields.maxVersion}`, fields.secureProtocol].filter(Boolean);
    const groupSettings = typeof fields.ecdhCurve === 'string' && fields.ecdhCurve.toLowerCase() !== 'auto'
      ? [{ groups: fields.ecdhCurve.split(':'), line: t.line }] : [];
    const e = entry({
      path: src.path, lines: src.lines, inTest: src.inTest, server: 'node', protocols: protocols.length ? protocols : null,
      ciphers: typeof fields.ciphers === 'string' ? fields.ciphers : null, groupSettings, line: t.line, unstatedNote: NOTE.nodeUnstated,
      nodeVersions: { min: fields.minVersion, max: fields.maxVersion },
    });
    e.setting = setting;
    if (fields.ecdhCurve === null) { e.keyExchange = 'dynamic'; e.notes.unshift(NOTE.dynamic); finishPriority(e); }
    out.push(e);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Common

function entry({ path, lines, inTest, server, protocols, ciphers, groupSettings, line, unstatedNote, nodeVersions }) {
  const groups = groupSettings.length ? [...new Set(groupSettings.flatMap((g) => g.groups))] : null;
  const hybridGroups = (groups ?? []).filter((g) => PQ_GROUP.test(g));
  let keyExchange;
  if (!groupSettings.length) keyExchange = 'unstated';
  else {
    const withPq = groupSettings.filter((g) => g.groups.some((x) => PQ_GROUP.test(x))).length;
    keyExchange = withPq === groupSettings.length ? 'hybrid' : withPq === 0 ? 'classical-only' : 'mixed';
  }
  const at = groupSettings.length ? groupSettings[0].line : line;
  const notes = [];
  if (keyExchange === 'unstated') notes.push(unstatedNote);
  if (hybridGroups.length && !enablesTls13(server, protocols, nodeVersions)) notes.push(NOTE.hybridNeedsTls13);
  if (enablesOldProtocol(server, protocols, nodeVersions)) notes.push(NOTE.oldProtocol);
  if (ciphers && ciphers.split(/[:\s]+/).some((c) => c && !/^[!-]/.test(c) && WEAK_CIPHER.test(c))) notes.push(NOTE.weakCiphers);
  return finish({
    file: path, line: at, server, setting: null, protocols, ciphers, groups, hybridGroups, keyExchange, notes,
    evidence: (lines[at - 1] ?? '').trim().slice(0, 200), inTest,
  });
}

function finish(e) {
  finishPriority(e);
  return e;
}

// Classical-only key exchange, and mixed configurations, are Low: the
// exposure is the session (DESIGN.md §4 item 3). Unstated and dynamic
// configurations get no priority until a person has looked.
function finishPriority(e) {
  const low = e.keyExchange === 'classical-only' || e.keyExchange === 'mixed';
  e.priority = low ? TLS_LOW.priority : null;
  e.priorityReason = low ? TLS_LOW.reason : null;
  e.replacement = low ? TLS_LOW.replacement : null;
}

function enablesTls13(server, protocols, nodeVersions) {
  if (server === 'node') return !nodeVersions?.max || /1\.3/.test(nodeVersions.max);
  if (!protocols) return true; // the defaults of current servers include TLS 1.3
  if (server === 'apache') return protocols.some((p) => /^(\+)?(all|tlsv1\.3)$/i.test(p)) && !protocols.some((p) => /^-tlsv1\.3$/i.test(p));
  return protocols.some((p) => /(tlsv1\.3|tls1\.3)$/i.test(p));
}

function enablesOldProtocol(server, protocols, nodeVersions) {
  if (server === 'node') return Boolean(nodeVersions?.min && /^TLSv1(\.1)?$/i.test(nodeVersions.min));
  if (!protocols) return false;
  if (server === 'apache') {
    // `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`: `all` enables what is not removed.
    const removed = new Set(protocols.filter((p) => p.startsWith('-')).map((p) => p.slice(1).toLowerCase()));
    const hasAll = protocols.some((p) => /^\+?all$/i.test(p));
    const added = protocols.filter((p) => !p.startsWith('-')).map((p) => p.replace(/^\+/, '').toLowerCase());
    const old = ['sslv3', 'tlsv1', 'tlsv1.1'];
    return old.some((o) => !removed.has(o) && (hasAll || added.includes(o)));
  }
  return protocols.some((p) => OLD_PROTOCOL.test(p));
}

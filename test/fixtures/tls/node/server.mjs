// Node TLS options, as servers write them.
import https from 'node:https';
import tls from 'tls';
import { readFileSync } from 'node:fs';

const key = readFileSync('key.pem');
const cert = readFileSync('cert.pem');

export const web = https.createServer({ key, cert, minVersion: 'TLSv1.2', ecdhCurve: 'X25519MLKEM768:X25519' }, (req, res) => res.end());

const internalOptions = { key, cert, ecdhCurve: 'P-256:X25519' };
export const internal = tls.createServer(internalOptions);

export function fromCaller(options) {
  return https.createServer(options);
}

// A client call with no TLS fields is not a configuration.
export const ping = () => https.get('https://example.org/health', () => {});

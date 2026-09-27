// Variables named `subtle` that are not Web Crypto. None may be reported.

// A test double with the same method names.
const subtle = { digest: (algorithm, data) => data.length, sign: () => 0 };
subtle.digest('SHA-1', new Uint8Array(4));
subtle.sign('Ed25519', null, null);

// A design token, not a crypto object.
const theme = { subtle: { encrypt: (x) => x } };
theme.subtle.encrypt('RSA-OAEP');

// A parameter that happens to be called subtle.
export function fade(subtle) {
  return subtle.encrypt({ name: 'AES-CBC' }, null, null);
}

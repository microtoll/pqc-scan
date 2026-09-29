// Look-alikes that must not be read as loading node:crypto (DESIGN.md §8.16).
// A plain check for require, which hands nothing back:
const hasRequire = typeof require !== "undefined";
// A loader of some other kind, called with the same string:
const cache = { crypto: { createHash: () => null } };
const load = (name) => cache[name];
load("crypto").createHash("md5");
// A helper that tests for require but returns something else:
var pick = (x) => typeof require !== "undefined" ? x : null;
pick("crypto").createHash("md5");
export { hasRequire };

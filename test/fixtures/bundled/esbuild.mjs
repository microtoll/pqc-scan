// The shape esbuild writes when it bundles CommonJS code into an ES module
// (DESIGN.md §8.16): a __require helper, then modules loaded through it.
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});

// src/vault.js
var crypto3 = __require("crypto");
function openSealed(key, nonce, data, tag) {
  const aesgcm = crypto3.createDecipheriv("aes-256-gcm", key, nonce);
  aesgcm.setAuthTag(tag);
  return Buffer.concat([aesgcm.update(data), aesgcm.final()]);
}
var { createHash } = __require("node:crypto");
function fingerprint(buf) {
  return createHash("sha256").update(buf).digest("hex");
}
export { openSealed, fingerprint };

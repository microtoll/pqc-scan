// A call inside a template substitution is code, and is found; the text
// around it is not.
export async function label(data) {
  return `digest: ${hex(await crypto.subtle.digest('SHA-512', data))} (not crypto.subtle.digest('MD5'))`;
}

function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

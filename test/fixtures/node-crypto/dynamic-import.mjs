// A dynamic import, and an algorithm held in a variable: found, and
// reported as dynamic rather than guessed.
export async function digest(algo, data) {
  const { createHash } = await import('node:crypto');
  return createHash(algo).update(data).digest();
}

// A library's type tests import the library by its own name (a package
// self-reference): `jose` here is this tree, not a dependency of it. The
// `test-d` directory is tsd's convention for type tests, so this is test code.
import * as jose from 'jose';
export const alg: jose.JWSAlgorithm = 'ES256';

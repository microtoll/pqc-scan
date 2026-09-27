// Reading a token without checking it, and picking the token out of a
// request: neither is cryptography, so neither is a use to point at. On a
// public wiki both drew a "could not be read" pointer (DESIGN.md §8.12).
import jwt from 'jsonwebtoken';
const passportJWT = require('passport-jwt');

export const claims = (token) => jwt.decode(token);
export const extractor = passportJWT.ExtractJwt.fromExtractors([passportJWT.ExtractJwt.fromAuthHeaderAsBearerToken()]);

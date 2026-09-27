// SAML sign-in and two-factor codes, as a public wiki does them: the
// identity provider's certificate verifies the assertion's signature, an
// encrypted assertion is RSA key transport, a code is an HMAC. None of the
// three libraries was catalogued before the review (DESIGN.md §8.12).
const SamlStrategy = require('passport-saml').Strategy;
const xmlenc = require('xml-encryption');
const tfa = require('node-2fa');

exports.strategy = new SamlStrategy({ cert: process.env.IDP_CERT, signatureAlgorithm: 'sha256' }, (profile, done) => done(null, profile));

exports.openAssertion = (assertion, key) => xmlenc.decrypt(assertion, { key }, () => {});

exports.checkCode = (secret, code) => tfa.verifyToken(secret, code);

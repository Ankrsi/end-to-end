'use strict';
// Node entry point (selected automatically via the "node" export condition): same API as
// the portable build, but with Node's native OpenSSL for the curve operations.
const lib = require('./index');

lib.setCryptoBackend(lib.createNodeCryptoBackend(require('crypto')));

module.exports = lib;

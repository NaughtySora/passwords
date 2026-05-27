'use strict';

const { Scrypt } = require('./lib/scrypt.js');
const { Argon2 } = require('./lib/argon2.js');
const { prehash, } = require('./lib/util.js');
const bcrypt = require('./lib/bcrypt.js');
const pepper = require('./lib/pepper.js');

module.exports = {
  Argon2,
  Scrypt,
  pepper,
  bcrypt,
  prehash,
};

/**
 * @next
 * 1. more tests
 * 2. reduce hash size of argon2, memory -> m, ...etc
 */

'use strict';

const { compare, hash, } = require('bcrypt');
const { createHmac, timingSafeEqual } = require('node:crypto');

const ENCODING = 'base64url';
const PREHASH_ALGO = "sha256";

class Bcrypt {
  #options = null;

  constructor({ rounds } = {}) {
    if (!Number.isInteger(rounds) || rounds < 1) {
      throw new Error('Rounds have to be a positive integer');
    }
    this.#options = { rounds };
  }

  #prehash(password) {
    return createHmac(PREHASH_ALGO, password)
      .digest()
      .toString(ENCODING);
  }

  async hash(password, prehash = false) {
    return await hash(
      prehash ? this.#prehash(password) : password,
      this.#options.rounds,
    );
  }

  async compare(password, hash) {
    const salt = this.extractSalt(hash);
    return timingSafeEqual(
      Buffer.from(await hash(password, salt), ENCODING),
      Buffer.from(hash, ENCODING),
    );
  }

  #extractSalt(hash) {

  }
}
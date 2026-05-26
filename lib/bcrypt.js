'use strict';

// const {
//   compare, genSalt, hash,
//   compareSync, genSaltSync, hashSync,
//   getRounds,
// } = require('bcrypt');

const { createHmac, getHashes } = require('node:crypto');

// get version of hash: check or whatever
// pepper versioning

// console.log(getHashes());

const PEPPER_DELIMITER = ':';

class Pepper {
  #version = 1;
  #secret = null;
  #pepperVersion;

  // version - number, >0
  // secret - string, length in range [x, y]
  constructor(secret, version) {
    this.#secret = Buffer.from(secret, 'base64url');
    this.#pepperVersion = version;
  }

  digest(value) {
    return createHmac("sha256", this.#secret)
      .digest(value).toString("base64url");
  }

  toMCF(hash) {
    return `${this.#version}\
${PEPPER_DELIMITER}\
${this.#pepperVersion}\
${PEPPER_DELIMITER}\
${hash}\
`;
  }

  get version() {
    return this.#version;
  }

  get pepperVersion() {
    return this.#pepperVersion;
  }

  static parse(value) {
    const components = value.split(PEPPER_DELIMITER, 3);
    return {
      version: parseInt(components[0], 10),
      pepperVersion: parseInt(components[1], 10),
      hash: components[2],
    };
  }
}

const pepper = new Pepper('abc', 2);
const hash = pepper.digest('11111');
const mcf = pepper.toMCF(hash);
const components = Pepper.parse(mcf);
console.log(components);
'use strict';

const { string, misc, iterator, adapters } = require('naughty-util');
const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');

const { timingSafeEqual } = crypto;
const { freeze } = Object;

const BUFFER_ENCODING = 'base64url';

const HASH_COMPONENTS = 4;
const HASH_COMPONENT_DELIMITER = '$';
const COMPONENT_PAIR_DELIMITED = '=';
const COMPONENT_DELIMITED = ',';

const SALT_LEN = 16;
const KEY_LEN = 64;
const MAX_INPUT_LENGTH = 1024;

const scrypt = adapters.promisify(crypto.scrypt);
const randomBytes = adapters.promisify(crypto.randomBytes);

const KEYS = new Set(['N', 'r', 'p',]);
const RANGES = {
  N: [Math.pow(2, 14), Math.pow(2, 20)],
  p: [1, 32],
  r: [8, 32],
  salt: [16, 64],
  hash: [32, 128],
  key: [16, 128],
};

const toBase64 = buffer =>
  buffer.toString(BUFFER_ENCODING);

const fromBase64 = string =>
  Buffer.from(string, BUFFER_ENCODING);

class ScryptOptions {
  #value = null;
  #name = 'scrypt:v1';
  #maxmem;

  constructor({ N, p, r, maxmem } = {}) {
    const options = { N, p, r };
    this.#validate(options);
    this.#value = options;
    this.#maxmem = maxmem;
    freeze(this.#value);
    freeze(this);
  }

  #validate(options) {
    const iter = iterator.object.entries(options);
    for (const { 0: key, 1: value } of iter) {
      if (!KEYS.has(key)) {
        throw new Error(`Unexpected key ${key}`);
      }
      ScryptOptions.#inRange(key, value);
    }
  }

  get N() {
    return this.#value.N;
  }

  get r() {
    return this.#value.r;
  }

  get p() {
    return this.#value.p;
  }

  get maxmem() {
    return this.#maxmem;
  }

  toString() {
    const components = [
      ['N', this.#value.N],
      ['r', this.#value.r],
      ['p', this.#value.p],
    ];
    let options = '';
    for (const entries of iterator.enumerate(components)) {
      const pair = entries[0].join(COMPONENT_PAIR_DELIMITED);
      const delimiter = entries[1] !== components.length - 1 ?
        COMPONENT_DELIMITED : "";
      options += `${pair}${delimiter}`;
    }
    return options;
  }

  get asArguments() {
    return {
      N: this.#value.N,
      r: this.#value.r,
      p: this.#value.p,
      maxmem: this.#maxmem,
    };
  }

  get name() {
    return this.#name;
  }

  static extract(string) {
    const options = {};
    const components = string.split(COMPONENT_DELIMITED);
    for (const component of components) {
      const entity = component.split(COMPONENT_PAIR_DELIMITED, 2);
      const key = entity[0];
      if (!KEYS.has(key)) throw new Error(`Invalid key ${key}`);
      const value = parseInt(entity[1], 10);
      ScryptOptions.#inRange(key, value);
      options[key] = value;
    }
    return options;
  }

  static #inRange(key, value) {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`Invalid value of ${key}`);
    }
    const ranges = RANGES[key];
    if (!misc.inRange(value, ranges[0], ranges[1])) {
      throw new RangeError(`Option ${key} is out of range`);
    }
  }
}

class Scrypt {
  #options = null;

  constructor(options) {
    this.#options = new ScryptOptions(options);
  }

  #composeMCF(components) {
    return components.join(HASH_COMPONENT_DELIMITER);
  }

  #decomposeMCF(value) {
    return value.split(
      HASH_COMPONENT_DELIMITER,
      HASH_COMPONENTS + 1,
    );
  }

  #serialize(hash, salt) {
    return this.#composeMCF([
      this.#options.name,
      this.#options.toString(),
      toBase64(salt),
      toBase64(hash),
    ]);
  }

  #deserialize(mcf) {
    if (!string.valid(mcf)) {
      throw new TypeError('MCF has to be a valid string');
    }
    this.#reasonableLength(mcf);
    const components = this.#decomposeMCF(mcf);
    if (components.length !== HASH_COMPONENTS) {
      throw new Error('Hash is malformed');
    }
    if (components[0] !== this.#options.name) {
      throw new Error('Incompatible algorithm / version');
    }
    const salt = fromBase64(components[2], BUFFER_ENCODING);
    this.#validateSalt(salt.byteLength);
    const hash = fromBase64(components[3], BUFFER_ENCODING);
    this.#validateHash(hash.byteLength);
    return {
      options: ScryptOptions.extract(components[1]),
      salt,
      hash,
    };
  }

  #reasonableLength(value) {
    if (!misc.inRange(value.length, 1, MAX_INPUT_LENGTH)) {
      throw new RangeError('Value is too long');
    }
  }

  #validate(password) {
    if (!string.valid(password)) {
      throw new TypeError('Password has to be a valid string');
    }
  }

  #validateSalt(length) {
    if (!misc.inRange(length, RANGES.salt[0], RANGES.salt[1])) {
      throw new RangeError('Salt has to be al least 16 bytes');
    }
  }

  #validateHash(length) {
    if (!misc.inRange(length, RANGES.hash[0], RANGES.hash[1])) {
      throw new RangeError('Hash length is out of range');
    }
  }

  #validateKey(length) {
    if (!misc.inRange(length, RANGES.key[0], RANGES.key[1])) {
      throw new RangeError('Key length is out of range');
    }
  }

  async hash(password, params = {}) {
    this.#validate(password);
    const { saltLength = SALT_LEN, keyLength = KEY_LEN, } = params;
    this.#validateSalt(saltLength);
    this.#validateKey(keyLength);
    const salt = await randomBytes(saltLength);
    const derived = await scrypt(toBase64(password), salt,
      keyLength, this.#options.asArguments);
    return this.#serialize(derived, salt);
  }

  async compare(password, mcf) {
    this.#validate(password);
    this.#reasonableLength(mcf);
    const { options, hash, salt } = this.#deserialize(mcf);
    this.#validateSalt(salt.length);
    this.#validateHash(hash.length);
    const derived = await scrypt(
      toBase64(password),
      salt,
      hash.byteLength,
      {
        N: options.N,
        r: options.r,
        p: options.p,
        maxmem: this.#options.maxmem,
      },
    );
    return timingSafeEqual(derived, hash);
  }
}

module.exports = { Scrypt };

'use strict';

const { string, misc, iterator, adapters } = require('naughty-util');
const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const {
  fromBase64,
  toBase64,
  reasonableLength,
  validatePassword,
  randomBytes,
} = require('./util.js');

const { timingSafeEqual } = crypto;
const { freeze } = Object;

const argon2 = adapters.promisify(crypto.argon2);

const COMPONENTS = 4;
const COMPONENT_DELIMITER = '$';
const COMPONENT_OPTION_DELIMITED = '=';
const COMPONENT_DELIMITED = ',';

const INPUT_ENCODING = "utf-8";

const ALGO = "argon2id";

const TAG_LEN = 64;
const SALT_LEN = 16;
const KEYS = new Set(["memory", "passes", "parallelism"]);
const OPTIONS_MAPPING = new Map([
  ["memory", "m"],
  ["passes", "p"],
  ["parallelism", "c"],
  ["m", "memory"],
  ["p", "passes"],
  ["c", "parallelism"], // c - concurrency
]);
const RANGES = {
  memory: [8, 512],
  passes: [1, 32],
  parallelism: [1, 16],
  salt: [16, 64],
  hash: [16, 128],
  secret: [16, 128],
};

class Argon2Options {
  #value = null;
  #name = 'argon2id:v1';

  constructor(options) {
    this.#validate(options);
    this.#value = options;
    freeze(this.#value);
    freeze(this);
  }

  #validate(options) {
    const iter = iterator.object.entries(options);
    for (const { 0: key, 1: value } of iter) {
      if (!KEYS.has(key)) {
        throw new Error(`Unexpected key ${key}`);
      }
      Argon2Options.#inRange(key, value);
    }
  }

  get memory() {
    return this.#value.memory;
  }

  get passes() {
    return this.#value.passes;
  }

  get parallelism() {
    return this.#value.parallelism;
  }

  get name() {
    return this.#name;
  }

  toString() {
    let options = '';
    const iter = iterator.object.entries(this.#value);
    for (const entries of iter) {
      const key = OPTIONS_MAPPING.get(entries[0]);
      const option = `${key}${COMPONENT_OPTION_DELIMITED}${entries[1]}`;
      options += `${option}${COMPONENT_DELIMITED}`;
    }
    return options.substring(0, options.length - 1);
  }

  static extract(string) {
    const options = {};
    const components = string.split(COMPONENT_DELIMITED);
    for (const component of components) {
      const entries = component.split(COMPONENT_OPTION_DELIMITED, 2);
      const key = OPTIONS_MAPPING.get(entries[0]);
      if (!KEYS.has(key)) throw new Error(`Invalid key ${key}`);
      const value = parseInt(entries[1], 10);
      Argon2Options.#inRange(key, value);
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

class Argon2 {
  #options = null;

  constructor(options) {
    this.#options = new Argon2Options(options);
  }

  #composeMCF(components) {
    return components.join(COMPONENT_DELIMITER);
  }

  #decomposeMCF(value) {
    return value.split(
      COMPONENT_DELIMITER,
      COMPONENTS + 1,
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
    reasonableLength(mcf);
    const components = this.#decomposeMCF(mcf);
    if (components.length !== COMPONENTS) {
      throw new Error('MCF is malformed');
    }
    if (components[0] !== this.#options.name) {
      throw new Error('Incompatible algorithm / version');
    }
    const salt = fromBase64(components[2]);
    this.#validateSalt(salt.byteLength);
    const hash = fromBase64(components[3]);
    this.#validateHash(hash.byteLength);
    return {
      options: Argon2Options.extract(components[1]),
      salt,
      hash,
    };
  }

  #validateSalt(length) {
    if (!misc.inRange(length, RANGES.salt[0], RANGES.salt[1])) {
      throw new RangeError('Salt has to be at least 16 bytes');
    }
  }

  #validateHash(length) {
    if (!misc.inRange(length, RANGES.hash[0], RANGES.hash[1])) {
      throw new RangeError('Hash has to be at least 16 bytes');
    }
  }

  async hash(password, params = {}) {
    validatePassword(password);
    const { saltLength = SALT_LEN, tagLength = TAG_LEN } = params;
    this.#validateSalt(saltLength);
    this.#validateHash(tagLength);
    const salt = await randomBytes(saltLength);
    const derived = await argon2(ALGO, {
      message: Buffer.from(password, INPUT_ENCODING),
      nonce: salt,
      tagLength,
      memory: this.#options.memory,
      parallelism: this.#options.parallelism,
      passes: this.#options.passes,
    });
    return this.#serialize(derived, salt);
  }

  async compare(password, mcf) {
    validatePassword(password);
    const { options, hash, salt } = this.#deserialize(mcf);
    const derived = await argon2(ALGO, {
      message: Buffer.from(password, INPUT_ENCODING),
      nonce: salt,
      tagLength: hash.byteLength,
      memory: options.memory,
      parallelism: options.parallelism,
      passes: options.passes,
    }
    );
    return timingSafeEqual(derived, hash);
  }
}

module.exports = { Argon2 };

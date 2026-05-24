'use strict';

const { string, misc, iterator } = require('naughty-util');
const { randomBytes, scrypt, timingSafeEqual } = require('node:crypto');
const { Buffer } = require('node:buffer');

const { isBuffer, from } = Buffer;
const { freeze } = Object;

const BUFFER_ENCODING = 'base64url';

const HASH_COMPONENTS = 5;

const SALT_LEN = 16;
const KEY_LEN = 64;
const MAX_INPUT_LENGTH = 256;

const KEYS = new Set(['N', 'r', 'p',]);
const RANGES = {
  N: [Math.pow(2, 14), Math.pow(2, 20)],
  p: [1, 32],
  r: [8, 32],
  salt: [16, 64],
  hash: [32, 128],
  key: [16, 128],
};

const base64 = buffer =>
  buffer.toString(BUFFER_ENCODING);

class ScryptOptions {
  #options = null;
  #name = 'scrypt';
  #version;
  #maxmem;

  constructor({ N, p, r, maxmem, version = 1 } = {}) {
    const options = { N, p, r };
    this.#validate(options);
    this.#options = options;
    this.#version = version;
    this.#maxmem = maxmem;
    freeze(this.#options);
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
    return this.#options.N;
  }

  get r() {
    return this.#options.r;
  }

  get p() {
    return this.#options.p;
  }

  get maxmem() {
    return this.#maxmem;
  }

  get options() {
    return {
      N: this.#options.N,
      r: this.#options.r,
      p: this.#options.p,
      maxmem: this.#maxmem,
    };
  }

  get name() {
    return this.#name;
  }

  get version() {
    return this.#version;
  }

  toString() {
    const { N, r, p, maxmem, version, name } = this;
    return `${name}$v${version}$N=${N},r=${r},p=${p}$`;
  }

  static parse(string) {
    const options = {};
    const parts = string.split(',');
    for (const part of parts) {
      const entity = part.split('=');
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

  #serialize(hash, salt) {
    return `${this.#options.toString()}${base64(salt)}$${base64(hash)}`;
  }

  #deserialize(payload) {
    if (!string.valid(payload)) {
      throw new TypeError('Invalid format');
    }
    const components = payload.split('$', 5);
    if (components[0] !== this.#options.name) {
      throw new Error('Unsupported algorithm');
    }
    this.#reasonableLength(components[3]);
    this.#reasonableLength(components[4]);
    if (components.length !== HASH_COMPONENTS) {
      throw new Error('Invalid format');
    }
    const salt = from(components[3], BUFFER_ENCODING);
    this.#validateSalt(salt.byteLength);
    const hash = from(components[4], BUFFER_ENCODING);
    this.#validateHash(hash.byteLength);
    return {
      options: ScryptOptions.parse(components[2]),
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
    if (!isBuffer(password)) {
      throw new TypeError('Password has to be a buffer');
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

  hash(password, params = {}) {
    this.#validate(password);
    const { saltLength = SALT_LEN, keyLength = KEY_LEN, } = params;
    this.#validateSalt(saltLength);
    this.#validateKey(keyLength);
    const { promise, resolve, reject } = Promise.withResolvers();
    randomBytes(saltLength, (err, salt) => {
      if (err) return void reject(err);
      scrypt(password, salt, keyLength, this.#options.options,
        (err, derived) => {
          if (err) return void reject(err);
          resolve(this.#serialize(derived, salt));
        },
      );
    });
    return promise;
  }

  compare(password, hashed) {
    this.#validate(password);
    const { options, salt, hash } = this.#deserialize(hashed);
    this.#validateSalt(salt.length);
    this.#validateHash(hash.length);
    const { promise, resolve, reject } = Promise.withResolvers();
    scrypt(
      password,
      salt,
      hash.byteLength,
      Object.assign({ maxmem: this.#options.maxmem }, options,),
      (err, derived) => {
        if (err) return void reject(err);
        resolve(timingSafeEqual(derived, hash));
      });
    return promise;
  }
}

module.exports = { Scrypt };

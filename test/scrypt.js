'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { Scrypt, ScryptOptions } = require('../lib/scrypt.js');

const SCRYPT_PARAMS = {
  N: 32768, r: 8, p: 1,
  maxmem: 64 * 1024 * 1024, version: 2
};

describe('Hashing algos', async () => {
  await describe('scrypt', async () => {
    await it('hash - compare - positive', async () => {
      const password = Buffer.from('abcA1234567');
      const scrypt = new Scrypt(SCRYPT_PARAMS);
      const hash = await scrypt.hash(password);
      const valid = await scrypt.compare(password, hash);
      assert.ok(valid);
    });

    await it('hash - compare - positive', async () => {
      const password = Buffer.from('abcA1234567');
      const scrypt = new Scrypt(SCRYPT_PARAMS);
      const hash = await scrypt.hash(password);
      const valid = await scrypt.compare(Buffer.from('abcA1234566'), hash);
      assert.ok(!valid);
    });
  });
});
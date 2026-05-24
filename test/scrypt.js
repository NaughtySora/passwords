'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { Scrypt, ScryptOptions } = require('../lib/scrypt.js');

const SCRYPT_PARAMS = {
  N: 32768, r: 8, p: 1,
  maxmem: 64 * 1024 * 1024, version: 2
};

const { maxmem, ...options } = SCRYPT_PARAMS;

describe('Hashing algos', async () => {
  await describe('scrypt', async () => {
    await it('hash - compare - positive', async () => {
      const password = Buffer.from('abcA1234567');
      const scrypt = new Scrypt(SCRYPT_PARAMS);
      const hash = await scrypt.hash(password);
      const result = await scrypt.compare(password, hash);
      assert.ok(result.valid);
      assert.deepEqual(result.options, options);
    });

    await it('hash - compare - negative', async () => {
      const password = Buffer.from('abcA1234567');
      const scrypt = new Scrypt(SCRYPT_PARAMS);
      const hash = await scrypt.hash(password);
      const result = await scrypt.compare(Buffer.from('abcA1234566'), hash);
      assert.ok(!result.valid);
      assert.deepEqual(result.options, options);
    });
  });
});
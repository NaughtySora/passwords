'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { Scrypt, ScryptOptions } = require('../lib/scrypt.js');

const SCRYPT_PARAMS = {
  N: 32768, r: 8, p: 1,
  maxmem: 64 * 1024 * 1024,
};

describe('Scrypt', async () => {
  it('invalid MCF string', () => {
    const scrypt = new Scrypt(SCRYPT_PARAMS);
    assert.rejects(scrypt.compare.bind(scrypt, 'abc', ''), {
      message: 'MCF has to be a valid string'
    });
    assert.rejects(scrypt.compare.bind(scrypt, 'abc', 'a'.repeat(1025)), {
      message: 'Value is out of range'
    });
  });

  it('invalid version', () => {
    const scrypt = new Scrypt(SCRYPT_PARAMS);
    const mcf = 'scrypt:v2$N=32768,p=1,r=8$VXGo0PJqbZHnzz_Ne2TX7A$KMVYeUiasdnifL8ERVlaH1XBWuiIfnb4XIdUKW1g4TbkskFN8way3-6-h1-gl-xFqNuTj8AbKFPScsU9iu7SnQ';
    assert.rejects(scrypt.compare.bind(scrypt, 'abc', mcf), {
      message: 'Incompatible algorithm / version'
    });
  });

  it('malformed MCF', () => {
    const scrypt = new Scrypt(SCRYPT_PARAMS);
    assert.rejects(scrypt.compare.bind(scrypt, 'abc', '$1$1$14$!$123$'), {
      message: 'MCF is malformed'
    });
  });

  it('invalid options', () => {
    assert.throws(() => new Scrypt({ N: 0 }), {
      message: 'Option N is out of range'
    });
    assert.throws(() => new Scrypt({ N: Infinity }), {
      message: 'Invalid value of N'
    });
  });

  it('invalid salt / hash', async () => {
    const scrypt = new Scrypt(SCRYPT_PARAMS);
    assert.rejects(
      scrypt.hash.bind(scrypt, 'abcA1234567', { saltLength: 7 }),
      { message: 'Salt has to be at least 16 bytes' },
    );
    assert.rejects(
      scrypt.hash.bind(scrypt, 'abcA1234567', { keyLength: 5 }),
      { message: 'Hash has to be at least 16 bytes' },
    );
  });

  await it('hash - compare - positive', async () => {
    const password = 'abcA1234567';
    const scrypt = new Scrypt(SCRYPT_PARAMS);
    const hash = await scrypt.hash(password);
    const valid = await scrypt.compare(password, hash);
    assert.ok(valid);
  });

  await it('hash - compare - negative', async () => {
    const password = 'abcA1234567';
    const scrypt = new Scrypt(SCRYPT_PARAMS);
    const hash = await scrypt.hash(password);
    const valid = await scrypt.compare('abcA1234566', hash);
    assert.ok(!valid);
  });
});

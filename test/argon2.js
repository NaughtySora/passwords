'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const { Argon2 } = require('../lib/argon2.js');

const OPTIONS = {
  memory: 64,
  passes: 3,
  parallelism: 4,
};

describe('Argon2', async () => {
  it('invalid MCF string', () => {
    const argon2 = new Argon2(OPTIONS);
    assert.rejects(argon2.compare.bind(argon2, 'abc', ''), {
      message: 'MCF has to be a valid string'
    });
    assert.rejects(argon2.compare.bind(argon2, 'abc', 'a'.repeat(1025)), {
      message: 'Value is out of range'
    });
  });

  it('invalid options', () => {
    assert.throws(() => new Argon2({ test: 1 }), {
      message: 'Unexpected key test',
    });
    assert.throws(() => new Argon2({ parallelism: 0 }), {
      message: 'Option parallelism is out of range'
    });
    assert.throws(() => new Argon2({ parallelism: Infinity }), {
      message: 'Invalid value of parallelism'
    });
  });

  it('malformed MCF', () => {
    const argon2 = new Argon2(OPTIONS);
    assert.rejects(argon2.compare.bind(argon2, 'abc', '$1$1$14$!$123$'), {
      message: 'MCF is malformed'
    });
  });

  it('invalid version', () => {
    const argon2 = new Argon2(OPTIONS);
    const mcf = 'argon2id:v2$memory=64,passes=3,parallelism=4$HlCnMegkXFfP9Jr5lpA43g$x5u8Z0jYq91-JqRLcgQikqqG9A-Mdv2ISrHBY4cv-F8TxS5GOpnSRl0YcxzcWABdfPLjxO4yIHtHR46GYXZQPQ';
    assert.rejects(argon2.compare.bind(argon2, 'abc', mcf), {
      message: 'Incompatible algorithm / version'
    });
  });

  it('invalid salt / hash', () => {
    const argon2 = new Argon2(OPTIONS);
    assert.rejects(argon2.hash('abc', { saltLength: 7 }), {
      message: 'Salt has to be at least 16 bytes',
    });
    assert.rejects(argon2.hash('abc', { tagLength: 5 }), {
      message: 'Hash has to be at least 16 bytes',
    });
  });

  await it('simple', async () => {
    const pass0 = '123456';
    const pass1 = '123457';
    const argon2 = new Argon2(OPTIONS);
    const mcf = await argon2.hash(pass0);
    const valid = await argon2.compare(pass0, mcf);
    const invalid = await argon2.compare(pass1, mcf);
    assert.ok(valid);
    assert.ok(!invalid);
  });
});
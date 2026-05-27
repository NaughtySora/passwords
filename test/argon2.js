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
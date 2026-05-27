'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const { deserialize, digest, serialize } = require('../lib/pepper.js');

describe.skip('Pepper', async () => {
  await it('test', async () => {
    const secrets = ['1', '2', '3'];
    const pass = '1234abc';
    const hash = digest(pass, secrets.v1);
    const mcf = serialize(hash, 1);
    const components = deserialize(mcf);
  });
});
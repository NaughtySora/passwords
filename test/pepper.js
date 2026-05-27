'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const { deserialize, digest, serialize } = require('../lib/pepper.js');

describe('Pepper', async () => {
  it('Malformed input', () => {
    assert.throws(deserialize.bind(null, '$1$$123$123$$123$'), {
      message: 'Input is malformed'
    })
  });

  await it('interface', async () => {
    const secrets = ['1', '2', '3'];
    const pass = '1234abc';

    const hash0 = digest(pass, secrets[0]);
    const mcf0 = serialize(hash0, 1);
    const components0 = deserialize(mcf0);
    assert.deepEqual(components0, {
      version: 1,
      app: 1,
      hash: hash0
    });

    const hash1 = digest(pass, secrets[1]);
    const mcf1 = serialize(hash1, 2);
    const components1 = deserialize(mcf1);
    assert.deepEqual(components1, {
      version: 2,
      app: 1,
      hash: hash1
    });
  });
});
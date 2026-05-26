'use strict';

const { deserialize, digest, serialize } = require('../lib/pepper.js');

describe('Pepper', async () => {
  await it('test', async () => {
    // test, rotation
    const secrets = {
      v1: '1',
      v2: '2',
      v3: '3',
    };
    const pass = '1234abc';
    const hash = digest(pass, secrets.v1);
    const mcf = serialize(hash, 1);
    const components = deserialize(mcf);
    console.dir({ mcf, components, hash, });
  });
});
'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const { compare, derive } = require('../lib/bcrypt.js');
const { hash, digest, serialize, deserialize } = require('../lib/pepper.js');

describe('Bcrypt', async () => {
  await it('raw input', async () => {
    const pass0 = '1234567';
    const pass1 = '1234568';
    const h0 = await derive(pass0, 10);
    const h1 = await derive(pass1, 10);
    const t = await compare(pass0, h0);
    const f = await compare(pass0, h1);
    assert.ok(t);
    assert.ok(!f);
  });

  await it('prehashed input', async () => {
    const pass0 = hash('1234567');
    const pass1 = hash('1234568');
    const h0 = await derive(pass0, 10);
    const h1 = await derive(pass1, 10);
    const t = await compare(pass0, h0);
    const f = await compare(pass0, h1);
    assert.ok(t);
    assert.ok(!f);
  });

  await it('pepper', async () => {
    // app secret
    const secret = '1234567';
    // peppered
    const pass0 = digest('1234567', secret);
    const pass1 = digest('1234568', secret);
    // bcrypt output
    const h0 = await derive(pass0, 10);
    const h1 = await derive(pass1, 10);
    // this we put into db
    // format [app_version][secret_version][hash]
    const s0 = serialize(h0, 1);
    const s1 = serialize(h1, 1);
    // we get this before comparing
    // { app: int, version: int, hash: string }
    const d0 = deserialize(s0);
    const d1 = deserialize(s1);
    // use only bcrypt hash
    // compare uses safe time compare
    const t = await compare(pass0, d0.hash);
    const f = await compare(pass0, d1.hash);
    assert.ok(t);
    assert.ok(!f);
  });
});
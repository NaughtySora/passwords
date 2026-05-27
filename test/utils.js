'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const { reasonableLength, validatePassword } = require('../lib/util.js');

describe('Pepper', async () => {
  it('reasonable length', () => {
    assert.throws(reasonableLength.bind(null, "a".repeat(1025)), {
      message: 'Value is out of range',
    });
    assert.throws(reasonableLength.bind(null, ""), {
      message: 'Value is out of range',
    });
  });

  it('validate password', () => {
    assert.throws(validatePassword.bind(null, ""), {
      message: 'Password has to be a valid string',
    });
    assert.throws(validatePassword.bind(null, true), {
      message: 'Password has to be a valid string',
    });
    assert.throws(validatePassword.bind(null, {}), {
      message: 'Password has to be a valid string',
    });
  });
});
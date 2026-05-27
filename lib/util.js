'use strict';

const { misc, string } = require('naughty-util');
const { createHmac } = require('node:crypto');
const { Buffer } = require('node:buffer');

const ENCODING_IN = 'utf8';
const ENCODING_OUT = 'base64url';
const ALGO = 'sha256';

const prehash = value =>
  createHmac(ALGO, Buffer.from(value, ENCODING_IN))
    .digest(ENCODING_OUT);

const MAX_INPUT_LENGTH = 1024;

const reasonableLength = value => {
  if (!misc.inRange(value.length, 1, MAX_INPUT_LENGTH)) {
    throw new RangeError('Value is too long');
  }
};

const validatePassword = password => {
  if (!string.valid(password)) {
    throw new TypeError('Password has to be a valid string');
  }
};

const BUFFER_ENCODING = 'base64url';

const toBase64 = buffer =>
  buffer.toString(BUFFER_ENCODING);

const fromBase64 = string =>
  Buffer.from(string, BUFFER_ENCODING);

module.exports = {
  prehash,
  reasonableLength,
  validatePassword,
  toBase64,
  fromBase64,
};

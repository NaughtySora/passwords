'use strict';

const bcrypt = require('bcrypt');
const { misc, string } = require('naughty-util');
const { timingSafeEqual } = require('node:crypto');

const ENCODING = 'base64url';
const PREHASH_ALGO = "sha256";
const SALT_LEN = 29;
const MAX_INPUT_LENGTH = 1024;

const ROUNDS = [4, 31];

const validateRounds = rounds => {
  if (!misc.inRange(rounds, ROUNDS[0], ROUNDS[1])) {
    throw new Error('Rounds have to be a positive integer');
  }
};

const reasonableLength = value => {
  if (!misc.inRange(value.length, 1, MAX_INPUT_LENGTH)) {
    throw new RangeError('Value is too long');
  }
};

const validate = password => {
  if (!string.valid(password)) {
    throw new TypeError('Password has to be a valid string');
  }
};

const extractSalt = hash => hash.substring(0, SALT_LEN);

const derive = async (password, rounds) => {
  validate(password);
  validateRounds(rounds);
  return await bcrypt.hash(password, rounds);
};

const compare = async (password, mcf) => {
  validate(password);
  reasonableLength(mcf);
  return timingSafeEqual(
    Buffer.from(await bcrypt.hash(password, extractSalt(mcf))),
    Buffer.from(mcf),
  );
};

module.exports = { derive, compare };

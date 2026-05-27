'use strict';

const bcrypt = require('bcrypt');
const { misc } = require('naughty-util');
const { reasonableLength, validatePassword } = require('./util');

const ROUNDS = [4, 31];

const validateRounds = rounds => {
  if (!misc.inRange(rounds, ROUNDS[0], ROUNDS[1])) {
    throw new RangeError('Rounds are out of range, expect 4 to 31');
  }
};

const derive = async (password, rounds) => {
  validatePassword(password);
  reasonableLength(password);
  validateRounds(rounds);
  return await bcrypt.hash(password, rounds);
};

const compare = async (password, mcf) => {
  validatePassword(password);
  reasonableLength(mcf);
  reasonableLength(password);
  return await bcrypt.compare(password, mcf);
};

module.exports = { derive, compare };

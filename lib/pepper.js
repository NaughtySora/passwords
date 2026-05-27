'use strict';

const { createHmac } = require('node:crypto');

const DELIMITER = ':';
const APP_VERSION = 1;
const ENCODING_IN = 'utf8';
const ENCODING_OUT = 'base64url';
const ALGO = 'sha256';
const COMPONENTS = 3;

const digest = (value, secret) =>
  createHmac(ALGO, Buffer.from(secret, ENCODING_IN))
    .update(value)
    .digest(ENCODING_OUT);

const serialize = (hash, version) =>
  `${APP_VERSION}${DELIMITER}${version}${DELIMITER}${hash}`;

const deserialize = mcf => {
  const components = mcf.split(DELIMITER, COMPONENTS + 1);
  if (components.length !== COMPONENTS) {
    throw new Error("Input is malformed");
  }
  return {
    app: parseInt(components[0], 10),
    version: parseInt(components[1], 10),
    hash: components[2],
  };
};

module.exports = {
  digest,
  serialize,
  deserialize,
};

'use strict';

const { createHmac } = require('node:crypto');

const DELIMITER = ':';
const APP_VERSION = 1;
const ENCODING = 'base64url';
const ALGO = 'sha256';
const COMPONENTS = 3;

const hash = value =>
  createHmac(ALGO, Buffer.from(value))
    .digest(ENCODING);

const digest = (value, nonce) =>
  createHmac(ALGO, Buffer.from(nonce))
    .update(value)
    .digest(ENCODING);

const serialize = (hash, version) =>
  `${APP_VERSION}${DELIMITER}${version}${DELIMITER}${hash}`;

const deserialize = mcf => {
  const components = mcf.split(DELIMITER, COMPONENTS);
  return {
    version: parseInt(components[0], 10),
    app: parseInt(components[1], 10),
    hash: components[2],
  };
};

module.exports = {
  hash,
  digest,
  serialize,
  deserialize,
};

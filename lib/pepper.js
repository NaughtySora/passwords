'use strict';

const { createHmac } = require('node:crypto');

const DELIMITER = ':';
const ENCODING = 'base64url';

const digest = (value, nonce) =>
  createHmac("sha256", Buffer.from(nonce, ENCODING))
    .digest(value)
    .toString(ENCODING);

const serialize = (hash, version) =>
  `${version}${DELIMITER}${hash}`;

const deserialize = mcf => {
  const components = mcf.split(DELIMITER, 2);
  return {
    version: parseInt(components[0], 10),
    hash: components[1],
  };
};

module.exports = {
  digest,
  serialize,
  deserialize,
};

'use strict';

const { string, misc, iterator, adapters } = require('naughty-util');
const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');

const { timingSafeEqual } = crypto;
const { freeze } = Object;

// external pepper is better, if you want to rotate it.

// salt
// | Length   | Meaning             |
// | -------- | ------------------- |
// | 16 bytes | standard            |
// | 24 bytes | more than enough    |
// | 32 bytes | very common         |
// | >32      | usually unnecessary |

// tag length
// | Length   | Use                 |
// | -------- | ------------------- |
// | 16 bytes | minimum sane        |
// | 32 bytes | common              |
// | 64 bytes | very common         |
// | >64      | usually unnecessary |


// memory
// | Memory   | Meaning       |
// | -------- | ------------- |
// | 8 MiB    | low           |
// | 32 MiB   | decent        |
// | 64 MiB   | strong/common |
// | 128 MiB  | strong        |
// | 256+ MiB | high security |

// passes
// | Passes | Meaning         |
// | ------ | --------------- |
// | 1      | minimal         |
// | 2-3    | common baseline |
// | 4-6    | strong          |
// | 8+     | expensive       |

// parallelism
// | Value | Meaning             |
// | ----- | ------------------- |
// | 1     | simplest/common     |
// | 2-4   | multicore aware     |
// | >8    | usually unnecessary |

// pepper
// | Length   | Meaning       |
// | -------- | ------------- |
// | 16 bytes | minimum sane  |
// | 32 bytes | strong/common |
// | 64 bytes | plenty        |

// salt: 16-64
// tagLength: 16-64
// passes: 1-10
// parallelism: 1-8
// memory: 8192-262144

// good enough
// {
//   memory: 65536, 
//   passes: 2 or 3,
//   parallelism: 1,
//   tagLength: 32
//   nonce: 16
//   taglength: 32 or 64
// }

// memory: 65536 * 100 concurrent logins = ~6.4 GiB or memory

// store name:version$memory,passes,parallelism,salt,hash

crypto.argon2("argon2id", {
  message: 'asdf', // password, use buffer | base64url 3/4 * length
  nonce: crypto.randomBytes(),// salt, random, stored
  passes: 8, // time cost, How many times Argon2 traverses/reprocesses memory.
  parallelism: 1, // how many lanes/threads Argon2 internally uses.
  memory: 32, // memory cost, KiB, this allocates working memory for the algorithm

  tagLength: 16, // output derived key length 16 - 32 - 64

  // database theft alone becomes insufficient, cause needed secret value
  secret: 'a', // paper, not stored with hash, 

  // affects hash
  // Extra authenticated context data, is not secret necessarily
  // domain separation, context binding, metadata coupling
  associatedData: 'not random data'
});
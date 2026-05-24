#### Passwords


Assignment:
- read about password, crypto, algos, cons/prod
- make some interfaces for convenient usage
- node crypto api



## hashing algorithms

#### bcrypt
- old, based on blowfish key schedule, configurable work factor
- simple, battle tested
- cpu-hard, weak memory
- uses 72 bytes, long passwords may be silently truncated
- less flexible
- used in old systems, old languages

#### scrypt
- first major memory hard password hasher
- memory hard, stronger against GPUs than bcrypt
- mature and secure
- flexible, can tune memory/CPU cost, block size, parallelism
- can be misconfigured
#### scrypt notes
- salt at least 16 bytes, details: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
- N - cpu cost/ram cost, has to be ^2, larger -> slower and more secure
- r - block size, internal mixing size, memo scaling ~ 128 * N * r, good default 8,
internally uses salsa20/8, internal structure in blocks
- p - parallelization, higher -> more cpu work, more parallel compute
- maxmem - safety guard, prevents huge memory allocation, OOM and DoS risks
- keyLength - length of derived output, can be any, usually 32 or 64, 64 * 8 = 512 bits - good entropy,
nice hex output, large enough, doesn't influence security, long can hurt performance
- salt and password as buffer only, in general better entropy and no issues with encoding

#### argon2

#### rehashing
- updating hashes during login if hash got old.
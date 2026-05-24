# Passwords

#### general
- salt and input should always be a buffer, better entropy and no issues with encoding
- rehashing is common practice, rehash old password with new parameters on app interaction

## hashing algorithms

#### scrypt
- first major memory hard password hasher
- memory hard, strong against GPUs
- flexible, can tune memory/CPU cost, block size, parallelism
- can be misconfigured
##### properties
- salt at least 16 bytes, details: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
- N - cpu cost/ram cost, has to be ^2, larger -> slower and more secure
- r - block size, internal mixing size, memo scaling ~ 128 * N * r, good default 8,
internally uses salsa20/8, structured in blocks
- p - parallelization, higher -> more cpu work, more parallel compute
- maxmem - safety guard, prevents huge memory allocation, OOM and DoS risks
- output - configurable length, usually 32 or 64 bytes, 64 bytes has good entropy,
nice hex output, large enough, length doesn't influence security, long can hurt performance

#### bcrypt
- old, simple, battle tested
- based on blowfish key schedule
- configurable work factor
- cpu-hard, weak memory
- uses 72 bytes, long passwords may be silently truncated
- lacking flexibility
- used in old systems, old languages

#### argon2
- TBD
# Passwords

#### general
- salt and input should always be a buffer, better entropy and no issues with encoding
- rehashing is common practice, rehash old password with new parameters on app interaction
- prehashing can remove issue with bcrypt 72 bytes input truncation

## algorithms

#### scrypt
- first major memory hard password hasher
- memory hard, strong against GPUs
- flexible, can tune memory/CPU cost, block size, parallelism
- can be misconfigured
##### properties
- salt at least 16 bytes, details: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
- N - cpu cost/ram cost, has to be ^2, larger value will be slower and more secure
- r - block size, internal mixing size, memo scaling ~ 128 * N * r, good default value is 8,
internally uses salsa20/8, structured in blocks
- p - parallelism, higher means more cpu work, more parallel computation
- maxmem - safety guard, prevents huge memory allocation, OOM and DoS risks, should not be stored with hash
- output - configurable length, usually 32 or 64 bytes, 64 bytes has good entropy,
nice hex output, large enough, length doesn't affect security, long can hurt performance

#### bcrypt
- used in old systems, old languages
- based on blowfish key schedule
- configurable work factor
- cpu-hard, weak memory
- uses 72 bytes, long passwords may be silently truncated, 
- lacking flexibility

#### argon2
- more efficient memory filling/reuse than scrypt
- better tunable parameters
- cleaner attack-cost modeling
- better GPU resistance per memory unit
##### properties
- m - how much RAM the algorithm allocates
- p - how many passes are made over memory
- p - how many lanes/threads the work is divided into

#### peppering
- additional security level
- internal app secret key
- prehashing input with secret before deriving
- could be pain to maintain secret rotation
- creates complexity in the system
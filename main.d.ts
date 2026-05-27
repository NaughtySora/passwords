type int = number;

interface ScryptOptions {
  N: int;
  p: int;
  r: int;
  maxmem: int;
}

interface ScryptHashParams {
  saltLength?: int;
  keyLength?: int;
}

export class Scrypt {
  constructor(options: ScryptOptions);
  hash(password: string, params?: ScryptHashParams): Promise<string>;
  compare(password: string, mcf: string): Promise<boolean>;
}

interface Argon2Options {
  memory: int;
  passes: int;
  parallelism: int;
}

interface Argon2HashParams {
  saltLength: int;
  tagLength: int;
}

export class Argon2 {
  constructor(options: Argon2Options);
  hash(password: string, params?: Argon2HashParams): Promise<string>;
  compare(password: string, mcf: string): Promise<boolean>;
}

type Prehash = (value: string) => string;

export const prehash: Prehash;

interface PepperComponents {
  app: int;
  version: int;
  hash: string;
}

interface Pepper {
  digest(value: string, secret: string): string;
  serialize(hash: string, version: int): string;
  deserialize(mcf: string): PepperComponents;
}

export const pepper: Pepper;

interface Bcrypt {
  derive(password: string, rounds: int): Promise<string>;
  compare(password: string, mcf: string): Promise<boolean>;
}

export const bcrypt: Bcrypt;
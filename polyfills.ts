// polyfills.ts
// Hermes (React Native's JS engine) does not ship the Web Crypto API.
// Libraries we use (@scure/bip39 via @noble/hashes, tweetnacl, Supabase Auth)
// expect globalThis.crypto.getRandomValues to exist. This file installs it,
// backed by expo-crypto (the platform-secure RNG). Must be imported FIRST.
import * as Crypto from 'expo-crypto';
import nacl from 'tweetnacl';

const g = globalThis as any;

if (typeof g.crypto !== 'object' || g.crypto === null) {
  g.crypto = {};
}

if (typeof g.crypto.getRandomValues !== 'function') {
  g.crypto.getRandomValues = (array: Uint8Array): Uint8Array =>
    Crypto.getRandomValues(array);
}

if (typeof g.crypto.randomUUID !== 'function') {
  g.crypto.randomUUID = (): string => Crypto.randomUUID();
}

// tweetnacl's official PRNG hook — key generation now draws from the same
// secure source instead of nacl's unseeded default.
nacl.setPRNG((x: Uint8Array, n: number) => {
  const bytes = Crypto.getRandomValues(new Uint8Array(n));
  for (let i = 0; i < n; i++) x[i] = bytes[i];
});

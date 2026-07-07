# crypto-primitives-demo

Hands-on cryptography primitives with Java and BouncyCastle.

I spent years at an e-signature company *using* signing and certificate APIs
in production. This repo is me reopening each black box: one small runnable
demo per primitive, written from scratch, ending at the doorstep of
Bitcoin/Ethereum key derivation.

## Demos

| # | Topic | Status |
|---|-------|--------|
| 01 | Key pairs — RSA vs EC, and why Q = d·G is one-way | ✅ |
| 02 | Digest → sign → verify — why you sign the hash, not the document | ✅ |
| 03 | Certificate chains — what a CA actually vouches for | 🔜 |
| 04 | AES + digital envelope — where symmetric and asymmetric each belong | 🔜 |
| 05 | secp256k1 signature → Bitcoin/Ethereum address derivation | 🔜 |

## Run

```bash
mvn compile exec:java -Dexec.mainClass=io.github.sevenqi27.crypto.d01.KeyPairsDemo
mvn compile exec:java -Dexec.mainClass=io.github.sevenqi27.crypto.d02.DigestDemo
```

Requires Java 17+ and Maven.

## Rules of this repo

- Every demo is a single readable `main` — no framework, no magic.
- Standard library + BouncyCastle only.
- Comments explain the *why*; the code shows the *how*.
- Never roll your own crypto in production. This repo exists to understand
  what the real libraries do, not to replace them.

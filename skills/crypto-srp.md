---
id: crypto-srp
applies-to: [dev/cajeta/crypto/Srp, dev/cajeta/crypto/SrpException]
title: SRP-6a — Cognito USER_SRP_AUTH client and RFC 5054 pieces
description: Run the client side of Amazon Cognito's SRP sign-in (SRP_A, the password key, PASSWORD_CLAIM_SIGNATURE) with dev.cajeta.crypto.Srp, or compute RFC 5054 SRP values for another peer or a test server.
---

# SRP-6a with `dev.cajeta.crypto.Srp`

SRP proves knowledge of a password without sending it. `Srp` covers two uses.

## Cognito sign-in (the instance API)

Cognito's `USER_SRP_AUTH` runs over RFC 3526's 3072-bit group, g = 2, SHA-256,
with Cognito's own padding and an HKDF step. One `Srp` instance is one sign-in
attempt; never reuse it.

```cajeta
import dev.cajeta.crypto.Srp;

Srp srp #= Srp.random();                 // fresh 128-byte secret from SecureRandom
String srpA #= srp.publicHex();          // InitiateAuth AuthParameters.SRP_A

// The PASSWORD_VERIFIER challenge returns USER_ID_FOR_SRP, SALT, SRP_B and
// SECRET_BLOCK (base64). poolName is the pool id after its underscore:
// "us-east-1_AbC123" -> "AbC123".
int8[] key #= srp.passwordKey(poolName, userIdForSrp, password, salt, srpB);
int8[] sig #= Srp.claim(key, poolName, userIdForSrp, block, blockLen, timestamp);
// RespondToAuthChallenge: PASSWORD_CLAIM_SIGNATURE = base64(sig),
// PASSWORD_CLAIM_SECRET_BLOCK = the SECRET_BLOCK string as received,
// TIMESTAMP = the same timestamp string.
```

Rules that matter:

- `userIdForSrp` is the challenge's `USER_ID_FOR_SRP`, not the name the user typed.
- `salt` and `srpB` are passed as the hex strings Cognito sent. Do not reformat
  them: the salt's padding is part of the hash.
- `block` is the **decoded** `SECRET_BLOCK` bytes; the response sends the
  original base64 string back.
- `timestamp` is `EEE MMM d HH:mm:ss UTC yyyy` in UTC with the day **not**
  zero-padded (`Thu Mar 5 07:04:09 UTC 2026`). The same string goes in the
  signature and in `TIMESTAMP`.
- `passwordKey` throws `SrpException` when `SRP_B` is 0 mod N or the scrambler
  is zero. Abort the sign-in; never retry with the same instance.
- Never log the key, the signature input, or the password.

Base64 is not in this library; use `dev.cajeta.codec` for it.

## RFC 5054 pieces (the static API)

For another SRP peer, or a test double of the server side. All values are hex
strings in, minimal lowercase hex out; hashes come back as full digests.

| Call | Computes |
|---|---|
| `rfc5054K(n, g)` | k = SHA1(N \| PAD(g)) |
| `rfc5054X(salt, user, password)` | x = SHA1(s \| SHA1(I ":" P)) |
| `rfc5054U(a, b, n)` | u = SHA1(PAD(A) \| PAD(B)) |
| `modPowHex(base, exp, mod)` | base^exp mod mod (verifier v = g^x, A = g^a) |
| `serverPublicHex(n, g, k, v, b)` | B = k·v + g^b mod N |
| `clientPremasterHex(n, g, k, x, a, u, B)` | (B − k·g^x)^(a + u·x) mod N |
| `serverPremasterHex(n, A, v, u, b)` | (A·v^u)^b mod N |

The premaster calls refuse a peer value of 0 mod N with `SrpException`. The
exponent is treated as secret in every exponentiation (constant-time in
OpenSSL). The hex parsing on the cajeta side is not constant-time.

# SecureRandom

`dev.cajeta.crypto.SecureRandom` draws cryptographically secure random bytes
from OpenSSL's `RAND_bytes`, which OpenSSL seeds from the operating system.
Session ids, challenge handles, salts and signing keys come from here. When
OpenSSL cannot produce entropy, the call throws `UnrecoverableException`
rather than degrading to a weaker generator. `cajeta.math`'s random is a
seeded generator for simulation and is never a substitute.

```cajeta
int8[] salt #= SecureRandom.bytes(16);   // 16 fresh bytes
int8[] buf = heap int8[64];
SecureRandom.fill(buf, 32);              // overwrite the first 32
```

## Methods

| Signature | |
|---|---|
| `static void fill(int8[] out, int64 len)` | Overwrite `out[0..len)` with entropy; `len` past the buffer throws |
| `static #int8[] bytes(int64 n)` | A fresh owned array of `n` random bytes |

## See also

- Source: [`runtime/src/dev/cajeta/crypto/SecureRandom.cajeta`](../../../runtime/src/dev/cajeta/crypto/SecureRandom.cajeta)
- [Pbkdf2](Pbkdf2.md) — salts, [HmacSha256](HmacSha256.md) — keys

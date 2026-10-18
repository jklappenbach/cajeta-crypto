# cajeta-crypto

`dev.cajeta.crypto` holds cryptography for [Cajeta](https://github.com/jklappenbach/cajeta) outside the stdlib, so it ships on its own release cycle. The algorithms are OpenSSL 3's, reached through `@Native` over a small C shim in `native/`. Nothing is vendored, because every Cajeta executable already links `-lssl -lcrypto`.

## Status

0.1.0 is in progress, following the plan in the cajeta repo (`agents/cajeta-crypto-plan.md`, spec `specs/cajeta-crypto-spec.md`).

| Package | Contents | State |
|---|---|---|
| `dev.cajeta.crypto` | `Sha1`, `Sha256`, `MD5`, `Blake3`, `HmacSha1`, `HmacSha256`, `Pbkdf2`, `Totp`, `SecureRandom`, moved from `cajeta.hash` with the same names and APIs | done |
| `dev.cajeta.crypto.sig` | `Jwk`, `Signatures`, `EcKeyPair`, `JwsAlgorithm`, `InvalidKeyException`: RS256 and ES256 verification, ES256 signing, JWK keys | done |
| `dev.cajeta.crypto.tls` | TLS, moving from `cajeta.io.net.tls` | planned |

## Use

```json
"dependencies": { "dev.cajeta.crypto": "0.1.0" }
```

```cajeta
import dev.cajeta.crypto.SecureRandom;
import dev.cajeta.crypto.Sha256;

int8[] salt #= SecureRandom.bytes(16L);
String digest #= Sha256.hashStringHex("the quick brown fox");
```

Code that imported these types from `cajeta.hash` changes only the import: `cajeta.hash.Sha256` becomes `dev.cajeta.crypto.Sha256`. The `cajeta.hash.Hasher` interface, `XXHash3`, `SipHash` and `Hash.constantTimeEquals` stay in the stdlib.

The `.cja` carries the shim's static archive for linux-x64, linux-arm64, macos-arm64 and windows-x64. A program with this library on its classpath links the shim even if it never calls it. The compiler roots every classpath class through its reflection tables (spec 2.4).

## Build and test

```sh
./run-tests.sh            # shim, library, test binary, suite, linkage check
./scripts/ci-checks.sh    # the self-checking tour and the tour-coverage gate
```

`CAJETA=<path>` picks the compiler. The tests need OpenSSL 3 headers (`libssl-dev`, or `openssl@3` on macOS), and a `../cajeta-unit` checkout or network access to Olla for `dev.cajeta.unit`.

## License

Apache-2.0.

# cajeta-crypto

`dev.cajeta.crypto` holds cryptography for [Cajeta](https://github.com/jklappenbach/cajeta) outside the stdlib, so it ships on its own release cycle. The algorithms are OpenSSL 3's, reached through `@Native` over a small C shim in `native/`. Nothing is vendored, because every Cajeta executable already links `-lssl -lcrypto`.

## Status

0.1.0 is in progress, following the plan in the cajeta repo (`agents/cajeta-crypto-plan.md`, spec `specs/cajeta-crypto-spec.md`).

| Package | Contents | State |
|---|---|---|
| `dev.cajeta.crypto` | `SecureRandom` | done |
| `dev.cajeta.crypto` | `Sha1`, `Sha256`, `MD5`, `Blake3`, `HmacSha1`, `HmacSha256`, `Pbkdf2`, `Totp`, moving from `cajeta.hash` | planned |
| `dev.cajeta.crypto.sig` | RS256 and ES256 verification, ES256 signing, JWK keys | planned |
| `dev.cajeta.crypto.tls` | TLS, moving from `cajeta.io.net.tls` | planned |

## Use

```json
"dependencies": { "dev.cajeta.crypto": "0.1.0" }
```

```cajeta
import dev.cajeta.crypto.SecureRandom;

int8[] salt #= SecureRandom.bytes(16L);
```

The `.cja` carries the shim's static archive for linux-x64, linux-arm64, macos-arm64 and windows-x64. A program with this library on its classpath links the shim even if it never calls it. The compiler roots every classpath class through its reflection tables (spec 2.4).

## Build and test

```sh
./run-tests.sh            # shim, library, test binary, suite, linkage check
./scripts/ci-checks.sh    # the self-checking tour and the tour-coverage gate
```

`CAJETA=<path>` picks the compiler. The tests need OpenSSL 3 headers (`libssl-dev`, or `openssl@3` on macOS), and a `../cajeta-unit` checkout or network access to Olla for `dev.cajeta.unit`.

## License

Apache-2.0.

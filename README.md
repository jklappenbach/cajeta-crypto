# cajeta-crypto

`dev.cajeta.crypto` holds cryptography for [Cajeta](https://github.com/jklappenbach/cajeta) outside the stdlib, so it ships on its own release cycle. The algorithms are OpenSSL 3's, reached through `@Native` over a small C shim in `native/`. Nothing is vendored, because every Cajeta executable already links `-lssl -lcrypto`.

## Status

0.1.0 is released; [CHANGELOG.md](CHANGELOG.md) lists what it holds. The work follows the plan in the cajeta repo (`agents/cajeta-crypto-plan.md`, spec `specs/cajeta-crypto-spec.md`).

| Package | Contents | State |
|---|---|---|
| `dev.cajeta.crypto` | `Sha1`, `Sha256`, `MD5`, `Blake3`, `HmacSha1`, `HmacSha256`, `Pbkdf2`, `Totp`, `SecureRandom`, moved from `cajeta.hash` with the same names and APIs | done |
| `dev.cajeta.crypto.sig` | `Jwk`, `Signatures`, `EcKeyPair`, `JwsAlgorithm`, `InvalidKeyException`: RS256 and ES256 verification, ES256 signing, JWK keys | done |
| `dev.cajeta.crypto.tls` | `TlsStream`, `TlsListener`, `TlsConnection`, `TlsException`, `CertificateInvalidException`, moved from `cajeta.io.net.tls`: TLS 1.2+ over the stdlib's sockets, verifying clients, server termination, ALPN | done |

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

Code that imported these types from `cajeta.hash` or `cajeta.io.net.tls` changes only the import: `cajeta.hash.Sha256` becomes `dev.cajeta.crypto.Sha256`, and `cajeta.io.net.tls.TlsStream` becomes `dev.cajeta.crypto.tls.TlsStream`. The `cajeta.hash.Hasher` interface, `XXHash3`, `SipHash` and `Hash.constantTimeEquals` stay in the stdlib.

A program that uses TLS declares the `network` capability, as this library does. The TLS tests and the tour use self-signed fixtures minted by `tools/mint-test-certs.c`; their keys protect nothing.

The `.cja` carries the shim's static archive for linux-x64, linux-arm64, macos-arm64 and windows-x64. A program with this library on its classpath links the shim even if it never calls it. The compiler roots every classpath class through its reflection tables (spec 2.4).

## Build and test

```sh
./run-tests.sh            # shim, library, test binary, suite, linkage check
./scripts/ci-checks.sh    # the self-checking tour and the tour-coverage gate
```

`CAJETA=<path>` picks the compiler. Both scripts also run under MSYS2 MINGW64 on Windows with `CC=gcc`.

A library build bakes the shim from `CAJETA_NATIVE_PATH`, so a local `cajeta install` runs `./native/build.sh` first and sets `CAJETA_NATIVE_PATH=$PWD/native`. The build cache does not key on the native archives yet, so clear `.cajeta/cache` after rebuilding the shim. The tests need OpenSSL 3 headers (`libssl-dev`, or `openssl@3` on macOS), and a `../cajeta-unit` checkout or network access to Olla for `dev.cajeta.unit`.

## License

Apache-2.0.

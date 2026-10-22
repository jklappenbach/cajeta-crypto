# Changelog

## 0.1.1 (2026-10-22)

- The three skills ship. They sat under the package directory, which the packager never reads, and the release build ran the bare compiler without `--skill-root`, so 0.1.0 carried none. `crypto-digesters`, `crypto-Sha256` and `crypto-tls-overview` are now in the archive with an index naming `MD5`, `Sha1`, `Sha256` and `tls`, and CI fails a release whose archive lacks them. No code change.

## 0.1.0 (2026-10-18)

The first release. Cryptography leaves the cajeta stdlib for this library, so it ships on its own clock (cajeta spec `specs/cajeta-crypto-spec.md`). The algorithms are OpenSSL 3's, reached through `@Native` over the `cajeta_crypto` shim in `native/`. The `.cja` carries the shim's static archive for linux-x64, linux-arm64, macos-arm64 and windows-x64, so a consumer links offline. Requires cajeta 0.43.1 or later.

- Moved from `cajeta.hash`, with the same names and APIs: `Sha1`, `Sha256`, `MD5`, `Blake3`, `HmacSha1`, `HmacSha256`, `Pbkdf2`, `Totp`, `SecureRandom`, now in `dev.cajeta.crypto`. A caller changes only the import. The digests' C came with them, renamed `__cajeta_crypto_*`. `SecureRandom` draws from OpenSSL's `RAND_bytes`, and a failure to produce entropy throws `UnrecoverableException`. `cajeta.hash.Hasher`, `XXHash3`, `SipHash` and `Hash.constantTimeEquals` stay in the stdlib.
- New `dev.cajeta.crypto.sig`: JWS signatures. `Signatures.verify` checks RS256 (RSA 2048 bits and up) and ES256 (P-256) and answers `false` rather than throwing on any mismatch. The caller names the algorithm, and a JWK whose `alg` names another answers `false`. `Jwk.parse` reads one RSA or EC public key and refuses symmetric, short and off-curve keys with `InvalidKeyException`. `EcKeyPair.generateP256` issues ES256 tokens and publishes its public JWK.
- Moved from `cajeta.io.net.tls`: `TlsStream`, `TlsListener`, `TlsConnection`, `TlsException` and `CertificateInvalidException`, now in `dev.cajeta.crypto.tls`, with the engine renamed `__cajeta_crypto_tls_*` so it links beside the stdlib's copy until cajeta removes it. A program that uses TLS declares the `network` capability.
- A program with this library on its classpath links the shim even if it calls nothing from it: the compiler roots every classpath class through its reflection tables.

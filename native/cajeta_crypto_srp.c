/*
 * dev.cajeta.crypto.Srp: the SRP-6a group arithmetic over OpenSSL 3 BIGNUMs.
 *
 * Every value is an unsigned big-endian magnitude. The result is written
 * left-padded to the modulus length at `out`, which the caller sizes. Each
 * call builds its BIGNUMs and clears them before returning; secrets (the
 * private exponents a and b, the password key x, the premaster) go through
 * BN_clear_free, and every exponentiation by a secret is
 * BN_mod_exp_mont_consttime with BN_FLG_CONSTTIME on the exponent.
 *
 * ABI: a cajeta `int8[]` reaches an @Native method as a pointer to its
 * header, { int64 count; int8 data[count]; }, so the bytes start 8 past it.
 *
 * Returns 0 on success, 1 when the peer's public value is 0 mod N (SRP-6a
 * requires the receiver to abort), -1 on an OpenSSL failure or a bad length.
 */
#include <stdint.h>
#include <openssl/bn.h>

#define CJ_DATA(hdr) (((const unsigned char *)(hdr)) + 8)
#define CJ_MUT(hdr)  (((unsigned char *)(hdr)) + 8)

static BIGNUM *bn_of(const void *hdr, int64_t len) {
    if (!hdr || len < 0) return NULL;
    return BN_bin2bn(CJ_DATA(hdr), (int) len, NULL);
}

static BIGNUM *secret_of(const void *hdr, int64_t len) {
    BIGNUM *r = bn_of(hdr, len);
    if (r) BN_set_flags(r, BN_FLG_CONSTTIME);
    return r;
}

static int32_t write_out(const BIGNUM *r, void *out, int64_t len) {
    if (!out || BN_bn2binpad(r, CJ_MUT(out), (int) len) < 0) return -1;
    return 0;
}

/* out = base^exp mod mod. The exponent is treated as secret. */
int32_t __cajeta_crypto_srp_modpow(const void *base, int64_t baseLen,
                                   const void *exp, int64_t expLen,
                                   const void *mod, int64_t modLen,
                                   void *out) {
    int32_t rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *b = bn_of(base, baseLen), *e = secret_of(exp, expLen);
    BIGNUM *m = bn_of(mod, modLen), *r = BN_new();
    if (ctx && b && e && m && r && !BN_is_zero(m)) {
        int ok = BN_is_odd(m) ? BN_mod_exp_mont_consttime(r, b, e, m, ctx, NULL)
                              : BN_mod_exp(r, b, e, m, ctx);
        if (ok) rc = write_out(r, out, modLen);
    }
    BN_free(b); BN_clear_free(e); BN_free(m); BN_clear_free(r);
    BN_CTX_free(ctx);
    return rc;
}

/* Client premaster: S = (B - k * g^x) ^ (a + u * x) mod N. */
int32_t __cajeta_crypto_srp_client_premaster(const void *n, int64_t nLen,
                                             const void *g, int64_t gLen,
                                             const void *k, int64_t kLen,
                                             const void *x, int64_t xLen,
                                             const void *a, int64_t aLen,
                                             const void *u, int64_t uLen,
                                             const void *bPub, int64_t bPubLen,
                                             void *out) {
    int32_t rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *N = bn_of(n, nLen), *G = bn_of(g, gLen), *K = bn_of(k, kLen);
    BIGNUM *X = secret_of(x, xLen), *A = secret_of(a, aLen), *U = bn_of(u, uLen);
    BIGNUM *B = bn_of(bPub, bPubLen);
    BIGNUM *gx = BN_new(), *base = BN_new(), *e = BN_new(), *S = BN_new();
    if (!ctx || !N || !G || !K || !X || !A || !U || !B || !gx || !base || !e || !S
            || BN_is_zero(N) || !BN_is_odd(N)) goto done;
    if (!BN_nnmod(base, B, N, ctx)) goto done;
    if (BN_is_zero(base)) { rc = 1; goto done; }
    BN_set_flags(gx, BN_FLG_CONSTTIME);
    BN_set_flags(e, BN_FLG_CONSTTIME);
    BN_set_flags(S, BN_FLG_CONSTTIME);
    if (!BN_mod_exp_mont_consttime(gx, G, X, N, ctx, NULL)
            || !BN_mod_mul(gx, K, gx, N, ctx)
            || !BN_mod_sub(base, base, gx, N, ctx)
            || !BN_mul(e, U, X, ctx)
            || !BN_add(e, e, A)
            || !BN_mod_exp_mont_consttime(S, base, e, N, ctx, NULL)) goto done;
    rc = write_out(S, out, nLen);
done:
    BN_free(N); BN_free(G); BN_free(K); BN_clear_free(X); BN_clear_free(A);
    BN_free(U); BN_free(B); BN_clear_free(gx); BN_clear_free(base);
    BN_clear_free(e); BN_clear_free(S);
    BN_CTX_free(ctx);
    return rc;
}

/* Server public value: B = (k * v + g^b) mod N. */
int32_t __cajeta_crypto_srp_server_public(const void *n, int64_t nLen,
                                          const void *g, int64_t gLen,
                                          const void *k, int64_t kLen,
                                          const void *v, int64_t vLen,
                                          const void *b, int64_t bLen,
                                          void *out) {
    int32_t rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *N = bn_of(n, nLen), *G = bn_of(g, gLen), *K = bn_of(k, kLen);
    BIGNUM *V = bn_of(v, vLen), *Bs = secret_of(b, bLen);
    BIGNUM *kv = BN_new(), *gb = BN_new();
    if (ctx && N && G && K && V && Bs && kv && gb && !BN_is_zero(N) && BN_is_odd(N)
            && BN_mod_mul(kv, K, V, N, ctx)
            && BN_mod_exp_mont_consttime(gb, G, Bs, N, ctx, NULL)
            && BN_mod_add(kv, kv, gb, N, ctx)) {
        rc = write_out(kv, out, nLen);
    }
    BN_free(N); BN_free(G); BN_free(K); BN_free(V); BN_clear_free(Bs);
    BN_free(kv); BN_clear_free(gb);
    BN_CTX_free(ctx);
    return rc;
}

/* Server premaster: S = (A * v^u) ^ b mod N. */
int32_t __cajeta_crypto_srp_server_premaster(const void *n, int64_t nLen,
                                             const void *aPub, int64_t aPubLen,
                                             const void *v, int64_t vLen,
                                             const void *u, int64_t uLen,
                                             const void *b, int64_t bLen,
                                             void *out) {
    int32_t rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *N = bn_of(n, nLen), *A = bn_of(aPub, aPubLen), *V = bn_of(v, vLen);
    BIGNUM *U = bn_of(u, uLen), *Bs = secret_of(b, bLen);
    BIGNUM *base = BN_new(), *S = BN_new();
    if (!ctx || !N || !A || !V || !U || !Bs || !base || !S
            || BN_is_zero(N) || !BN_is_odd(N)) goto done;
    if (!BN_nnmod(base, A, N, ctx)) goto done;
    if (BN_is_zero(base)) { rc = 1; goto done; }
    BN_set_flags(S, BN_FLG_CONSTTIME);
    if (!BN_mod_exp(S, V, U, N, ctx)
            || !BN_mod_mul(base, base, S, N, ctx)
            || !BN_mod_exp_mont_consttime(S, base, Bs, N, ctx, NULL)) goto done;
    rc = write_out(S, out, nLen);
done:
    BN_free(N); BN_free(A); BN_free(V); BN_free(U); BN_clear_free(Bs);
    BN_clear_free(base); BN_clear_free(S);
    BN_CTX_free(ctx);
    return rc;
}

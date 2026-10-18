/*
 * dev.cajeta.crypto.sig: RS256 and ES256 over OpenSSL 3 (spec 4).
 *
 * Stateless: every call builds its EVP_PKEY from raw components and frees it
 * before returning, so no OpenSSL object outlives a call and cajeta holds
 * keys as plain byte arrays.
 *
 * ABI: a cajeta `int8[]` reaches an @Native method as a pointer to its
 * header, { int64 count; int8 data[count]; }, so the bytes start 8 past it.
 * RSA components are big-endian magnitudes as JWK carries them; P-256
 * coordinates and the private scalar are 32-byte big-endian; an ES256
 * signature is the 64-byte r || s of RFC 7518 section 3.4.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#define CJ_DATA(hdr) (((const unsigned char *)(hdr)) + 8)
#define CJ_MUT(hdr)  (((unsigned char *)(hdr)) + 8)

/* An RSA public key from n and e, or NULL. */
static EVP_PKEY *rsa_public(const unsigned char *n, int64_t nlen,
                            const unsigned char *e, int64_t elen) {
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    BIGNUM *bn = BN_bin2bn(n, (int) nlen, NULL);
    BIGNUM *be = BN_bin2bn(e, (int) elen, NULL);
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    if (!bld || !bn || !be
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn)
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be)
            || !(params = OSSL_PARAM_BLD_to_param(bld))
            || !(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL))
            || EVP_PKEY_fromdata_init(ctx) <= 0
            || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    BN_free(bn);
    BN_free(be);
    OSSL_PARAM_BLD_free(bld);
    return pkey;
}

/* A P-256 key from x and y, plus the private scalar d when d is non-NULL, or
 * NULL. A public point is checked to lie on the curve. */
static EVP_PKEY *p256_key(const unsigned char *x, const unsigned char *y,
                          const unsigned char *d) {
    unsigned char point[65];
    point[0] = 0x04;
    memcpy(point + 1, x, 32);
    memcpy(point + 33, y, 32);
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    BIGNUM *bd = d ? BN_bin2bn(d, 32, NULL) : NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ok = bld
        && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0)
        && OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof point)
        && (!d || (bd && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bd)))
        && (params = OSSL_PARAM_BLD_to_param(bld)) != NULL
        && (ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) != NULL
        && EVP_PKEY_fromdata_init(ctx) > 0
        && EVP_PKEY_fromdata(ctx, &pkey, d ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) > 0;
    if (ok) {
        EVP_PKEY_CTX *check = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        ok = check && EVP_PKEY_public_check(check) == 1;
        EVP_PKEY_CTX_free(check);
    }
    if (!ok) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    BN_free(bd);
    OSSL_PARAM_BLD_free(bld);
    return pkey;
}

/* 1 when sig is a valid SHA-256 signature of msg under pkey, else 0. */
static int32_t digest_verify(EVP_PKEY *pkey, const unsigned char *msg, int64_t msglen,
                             const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int32_t ok = mctx
        && EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey) == 1
        && EVP_DigestVerify(mctx, sig, siglen, msg, (size_t) msglen) == 1;
    EVP_MD_CTX_free(mctx);
    return ok ? 1 : 0;
}

/* The modulus size in bits of an RSA key from n and e; -1 when OpenSSL
 * cannot build the key. */
int32_t __cajeta_crypto_rsa_bits(const void *n_hdr, int64_t nlen,
                                 const void *e_hdr, int64_t elen) {
    if (nlen <= 0 || elen <= 0 || nlen > 2048) {
        return -1;
    }
    EVP_PKEY *pkey = rsa_public(CJ_DATA(n_hdr), nlen, CJ_DATA(e_hdr), elen);
    if (!pkey) {
        return -1;
    }
    int32_t bits = (int32_t) EVP_PKEY_get_bits(pkey);
    EVP_PKEY_free(pkey);
    return bits;
}

/* 0 when (x, y) is a point on P-256, -1 otherwise. */
int32_t __cajeta_crypto_p256_check(const void *x_hdr, const void *y_hdr) {
    EVP_PKEY *pkey = p256_key(CJ_DATA(x_hdr), CJ_DATA(y_hdr), NULL);
    if (!pkey) {
        return -1;
    }
    EVP_PKEY_free(pkey);
    return 0;
}

/* RS256: 1 when sig verifies over msg under (n, e), else 0. */
int32_t __cajeta_crypto_rs256_verify(const void *n_hdr, int64_t nlen,
                                     const void *e_hdr, int64_t elen,
                                     const void *msg_hdr, int64_t msglen,
                                     const void *sig_hdr, int64_t siglen) {
    if (siglen <= 0 || siglen != nlen || msglen < 0) {
        return 0;
    }
    EVP_PKEY *pkey = rsa_public(CJ_DATA(n_hdr), nlen, CJ_DATA(e_hdr), elen);
    if (!pkey) {
        return 0;
    }
    int32_t ok = digest_verify(pkey, CJ_DATA(msg_hdr), msglen, CJ_DATA(sig_hdr), (size_t) siglen);
    EVP_PKEY_free(pkey);
    return ok;
}

/* ES256: 1 when the 64-byte r || s verifies over msg under (x, y), else 0. */
int32_t __cajeta_crypto_es256_verify(const void *x_hdr, const void *y_hdr,
                                     const void *msg_hdr, int64_t msglen,
                                     const void *sig_hdr, int64_t siglen) {
    if (siglen != 64 || msglen < 0) {
        return 0;
    }
    const unsigned char *rs = CJ_DATA(sig_hdr);
    ECDSA_SIG *es = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(rs, 32, NULL);
    BIGNUM *s = BN_bin2bn(rs + 32, 32, NULL);
    if (!es || !r || !s || ECDSA_SIG_set0(es, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(es);
        return 0;
    }
    unsigned char *der = NULL;
    int derlen = i2d_ECDSA_SIG(es, &der);
    ECDSA_SIG_free(es);
    if (derlen <= 0) {
        return 0;
    }
    EVP_PKEY *pkey = p256_key(CJ_DATA(x_hdr), CJ_DATA(y_hdr), NULL);
    int32_t ok = pkey ? digest_verify(pkey, CJ_DATA(msg_hdr), msglen, der, (size_t) derlen) : 0;
    EVP_PKEY_free(pkey);
    OPENSSL_free(der);
    return ok;
}

/* A fresh P-256 key pair into d, x and y (32 bytes each); 0 on success. */
int32_t __cajeta_crypto_p256_generate(void *d_hdr, void *x_hdr, void *y_hdr) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (!pkey) {
        return -1;
    }
    unsigned char point[65];
    size_t plen = 0;
    BIGNUM *d = NULL;
    int ok = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof point, &plen) == 1
        && plen == 65 && point[0] == 0x04
        && EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &d) == 1
        && BN_bn2binpad(d, CJ_MUT(d_hdr), 32) == 32;
    if (ok) {
        memcpy(CJ_MUT(x_hdr), point + 1, 32);
        memcpy(CJ_MUT(y_hdr), point + 33, 32);
    }
    BN_clear_free(d);
    OPENSSL_cleanse(point, sizeof point);
    EVP_PKEY_free(pkey);
    return ok ? 0 : -1;
}

/* ES256 signature of msg under the pair (d, x, y) into sig as 64-byte r || s;
 * 0 on success. */
int32_t __cajeta_crypto_es256_sign(const void *d_hdr, const void *x_hdr, const void *y_hdr,
                                   const void *msg_hdr, int64_t msglen, void *sig_hdr) {
    if (msglen < 0) {
        return -1;
    }
    EVP_PKEY *pkey = p256_key(CJ_DATA(x_hdr), CJ_DATA(y_hdr), CJ_DATA(d_hdr));
    if (!pkey) {
        return -1;
    }
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    unsigned char der[80];
    size_t derlen = sizeof der;
    int ok = mctx
        && EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey) == 1
        && EVP_DigestSign(mctx, der, &derlen, CJ_DATA(msg_hdr), (size_t) msglen) == 1;
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    if (!ok) {
        return -1;
    }
    const unsigned char *p = der;
    ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &p, (long) derlen);
    if (!es) {
        return -1;
    }
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    ECDSA_SIG_get0(es, &r, &s);
    unsigned char *out = CJ_MUT(sig_hdr);
    ok = BN_bn2binpad(r, out, 32) == 32 && BN_bn2binpad(s, out + 32, 32) == 32;
    ECDSA_SIG_free(es);
    return ok ? 0 : -1;
}

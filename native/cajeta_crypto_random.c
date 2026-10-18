/*
 * dev.cajeta.crypto.SecureRandom: entropy from OpenSSL's RAND_bytes.
 *
 * ABI: a cajeta `int8[]` reaches an @Native method as a pointer to its
 * header, { int64 count; int8 data[count]; }, so the bytes start 8 past it.
 * Symbols are __cajeta_crypto_*, never the runtime's __cajeta_* names, so the
 * library links beside any toolchain without defining a symbol twice.
 */
#include <stdint.h>
#include <openssl/rand.h>

#define CJ_MUT(hdr) (((unsigned char *)(hdr)) + 8)

/* Test hook: while set, every draw reports failure, so the suite can prove
 * the caller raises rather than handing back unfilled bytes. Bound only from
 * the library's test sources. */
static int32_t force_fail = 0;

int32_t __cajeta_crypto_random_test_fail(int32_t on) {
    int32_t was = force_fail;
    force_fail = on;
    return was;
}

/* Fill out[0..len) from RAND_bytes; 0 on success, -1 when OpenSSL cannot. */
int32_t __cajeta_crypto_random_fill(void *out_hdr, int64_t len) {
    if (len <= 0) {
        return 0;
    }
    if (force_fail) {
        return -1;
    }
    if (len > INT32_MAX) {
        return -1;
    }
    return RAND_bytes(CJ_MUT(out_hdr), (int) len) == 1 ? 0 : -1;
}

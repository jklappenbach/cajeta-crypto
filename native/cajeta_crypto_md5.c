// Copied from cajeta runtime/native/cajeta_rt_hash.c lines 233-467 (the MD5 section) on 2026-10-17 (cajeta-crypto plan Unit 2),
// exported symbols renamed __cajeta_crypto_* so this archive links beside a
// runtime that still carries its own copy. The runtime copy is deleted in the
// cajeta release that removes the stdlib types (plan Unit 7).
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --- cajeta.hash.MD5 --------------------------------------------------------
// RFC 1321 MD5 — broken, kept for ETag / Content-MD5 / cache keys. 16-byte digest.

struct cajeta_md5_state {
    uint32_t s[4];          // A, B, C, D
    uint64_t bits;          // total bytes hashed * 8
    uint8_t  buf[64];       // partial-block buffer
    int32_t  buf_len;
};

// K and S are baked into the unrolled md5_transform, so no runtime tables.

static inline uint32_t md5_rotl(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32u - n));
}

// Fully-unrolled MD5 transform: index, rotate and constant are baked in per round,
// so no data-dependent branch or indexed K/S survives the inner loop.
static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    // memcpy into uint32 lowers to unaligned LE word loads; BE would need a bswap.
    uint32_t M[16];
    memcpy(M, block, 64);
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    #define MD5_F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
    #define MD5_G(x,y,z) ((y) ^ ((z) & ((x) ^ (y))))
    #define MD5_H(x,y,z) ((x) ^ (y) ^ (z))
    #define MD5_I(x,y,z) ((y) ^ ((x) | ~(z)))
    #define MD5_STEP(fn,a,b,c,d,m,k,s) (a) = (b) + md5_rotl((a) + fn(b,c,d) + (m) + (k), s)
    MD5_STEP(MD5_F,a,b,c,d,M[0],0xd76aa478,7);  MD5_STEP(MD5_F,d,a,b,c,M[1],0xe8c7b756,12);
    MD5_STEP(MD5_F,c,d,a,b,M[2],0x242070db,17); MD5_STEP(MD5_F,b,c,d,a,M[3],0xc1bdceee,22);
    MD5_STEP(MD5_F,a,b,c,d,M[4],0xf57c0faf,7);  MD5_STEP(MD5_F,d,a,b,c,M[5],0x4787c62a,12);
    MD5_STEP(MD5_F,c,d,a,b,M[6],0xa8304613,17); MD5_STEP(MD5_F,b,c,d,a,M[7],0xfd469501,22);
    MD5_STEP(MD5_F,a,b,c,d,M[8],0x698098d8,7);  MD5_STEP(MD5_F,d,a,b,c,M[9],0x8b44f7af,12);
    MD5_STEP(MD5_F,c,d,a,b,M[10],0xffff5bb1,17);MD5_STEP(MD5_F,b,c,d,a,M[11],0x895cd7be,22);
    MD5_STEP(MD5_F,a,b,c,d,M[12],0x6b901122,7); MD5_STEP(MD5_F,d,a,b,c,M[13],0xfd987193,12);
    MD5_STEP(MD5_F,c,d,a,b,M[14],0xa679438e,17);MD5_STEP(MD5_F,b,c,d,a,M[15],0x49b40821,22);
    MD5_STEP(MD5_G,a,b,c,d,M[1],0xf61e2562,5);  MD5_STEP(MD5_G,d,a,b,c,M[6],0xc040b340,9);
    MD5_STEP(MD5_G,c,d,a,b,M[11],0x265e5a51,14);MD5_STEP(MD5_G,b,c,d,a,M[0],0xe9b6c7aa,20);
    MD5_STEP(MD5_G,a,b,c,d,M[5],0xd62f105d,5);  MD5_STEP(MD5_G,d,a,b,c,M[10],0x02441453,9);
    MD5_STEP(MD5_G,c,d,a,b,M[15],0xd8a1e681,14);MD5_STEP(MD5_G,b,c,d,a,M[4],0xe7d3fbc8,20);
    MD5_STEP(MD5_G,a,b,c,d,M[9],0x21e1cde6,5);  MD5_STEP(MD5_G,d,a,b,c,M[14],0xc33707d6,9);
    MD5_STEP(MD5_G,c,d,a,b,M[3],0xf4d50d87,14); MD5_STEP(MD5_G,b,c,d,a,M[8],0x455a14ed,20);
    MD5_STEP(MD5_G,a,b,c,d,M[13],0xa9e3e905,5); MD5_STEP(MD5_G,d,a,b,c,M[2],0xfcefa3f8,9);
    MD5_STEP(MD5_G,c,d,a,b,M[7],0x676f02d9,14); MD5_STEP(MD5_G,b,c,d,a,M[12],0x8d2a4c8a,20);
    MD5_STEP(MD5_H,a,b,c,d,M[5],0xfffa3942,4);  MD5_STEP(MD5_H,d,a,b,c,M[8],0x8771f681,11);
    MD5_STEP(MD5_H,c,d,a,b,M[11],0x6d9d6122,16);MD5_STEP(MD5_H,b,c,d,a,M[14],0xfde5380c,23);
    MD5_STEP(MD5_H,a,b,c,d,M[1],0xa4beea44,4);  MD5_STEP(MD5_H,d,a,b,c,M[4],0x4bdecfa9,11);
    MD5_STEP(MD5_H,c,d,a,b,M[7],0xf6bb4b60,16); MD5_STEP(MD5_H,b,c,d,a,M[10],0xbebfbc70,23);
    MD5_STEP(MD5_H,a,b,c,d,M[13],0x289b7ec6,4); MD5_STEP(MD5_H,d,a,b,c,M[0],0xeaa127fa,11);
    MD5_STEP(MD5_H,c,d,a,b,M[3],0xd4ef3085,16); MD5_STEP(MD5_H,b,c,d,a,M[6],0x04881d05,23);
    MD5_STEP(MD5_H,a,b,c,d,M[9],0xd9d4d039,4);  MD5_STEP(MD5_H,d,a,b,c,M[12],0xe6db99e5,11);
    MD5_STEP(MD5_H,c,d,a,b,M[15],0x1fa27cf8,16);MD5_STEP(MD5_H,b,c,d,a,M[2],0xc4ac5665,23);
    MD5_STEP(MD5_I,a,b,c,d,M[0],0xf4292244,6);  MD5_STEP(MD5_I,d,a,b,c,M[7],0x432aff97,10);
    MD5_STEP(MD5_I,c,d,a,b,M[14],0xab9423a7,15);MD5_STEP(MD5_I,b,c,d,a,M[5],0xfc93a039,21);
    MD5_STEP(MD5_I,a,b,c,d,M[12],0x655b59c3,6); MD5_STEP(MD5_I,d,a,b,c,M[3],0x8f0ccc92,10);
    MD5_STEP(MD5_I,c,d,a,b,M[10],0xffeff47d,15);MD5_STEP(MD5_I,b,c,d,a,M[1],0x85845dd1,21);
    MD5_STEP(MD5_I,a,b,c,d,M[8],0x6fa87e4f,6);  MD5_STEP(MD5_I,d,a,b,c,M[15],0xfe2ce6e0,10);
    MD5_STEP(MD5_I,c,d,a,b,M[6],0xa3014314,15); MD5_STEP(MD5_I,b,c,d,a,M[13],0x4e0811a1,21);
    MD5_STEP(MD5_I,a,b,c,d,M[4],0xf7537e82,6);  MD5_STEP(MD5_I,d,a,b,c,M[11],0xbd3af235,10);
    MD5_STEP(MD5_I,c,d,a,b,M[2],0x2ad7d2bb,15); MD5_STEP(MD5_I,b,c,d,a,M[9],0xeb86d391,21);
    #undef MD5_F
    #undef MD5_G
    #undef MD5_H
    #undef MD5_I
    #undef MD5_STEP
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

static void md5_init(struct cajeta_md5_state* s) {
    s->s[0] = 0x67452301;
    s->s[1] = 0xefcdab89;
    s->s[2] = 0x98badcfe;
    s->s[3] = 0x10325476;
    s->bits = 0;
    s->buf_len = 0;
}

static void md5_update(struct cajeta_md5_state* s,
                       const uint8_t* data, size_t len) {
    s->bits += (uint64_t) len * 8u;
    if (s->buf_len > 0) {
        size_t need = (size_t) (64 - s->buf_len);
        size_t take = need < len ? need : len;
        memcpy(s->buf + s->buf_len, data, take);
        s->buf_len += (int32_t) take;
        data += take; len -= take;
        if (s->buf_len == 64) { md5_transform(s->s, s->buf); s->buf_len = 0; }
    }
    // Whole blocks hash straight from the caller's buffer: no per-block memcpy.
    while (len >= 64) {
        md5_transform(s->s, data);
        data += 64; len -= 64;
    }
    // Stash the sub-block tail for next time.
    if (len > 0) {
        memcpy(s->buf, data, len);
        s->buf_len = (int32_t) len;
    }
}

static void md5_finalize(struct cajeta_md5_state* s, uint8_t out[16]) {
    // Append 0x80, pad to 56 mod 64, append the 8-byte LE bit count, transform.
    s->buf[s->buf_len++] = 0x80;
    if (s->buf_len > 56) {
        memset(s->buf + s->buf_len, 0, (size_t)(64 - s->buf_len));
        md5_transform(s->s, s->buf);
        s->buf_len = 0;
    }
    memset(s->buf + s->buf_len, 0, (size_t)(56 - s->buf_len));
    for (int i = 0; i < 8; i++) {
        s->buf[56 + i] = (uint8_t)(s->bits >> (i * 8));
    }
    md5_transform(s->s, s->buf);
    for (int i = 0; i < 4; i++) {
        out[i*4 + 0] = (uint8_t)(s->s[i] >> 0);
        out[i*4 + 1] = (uint8_t)(s->s[i] >> 8);
        out[i*4 + 2] = (uint8_t)(s->s[i] >> 16);
        out[i*4 + 3] = (uint8_t)(s->s[i] >> 24);
    }
}

// --- MD5 C ABI bridges -----------------------------------------------------
// Streaming state, opaque to cajeta; allocator and finalizer pair as the class does.

void* __cajeta_crypto_md5_alloc(void) {
    struct cajeta_md5_state* s = (struct cajeta_md5_state*) malloc(sizeof *s);
    if (!s) return NULL;
    md5_init(s);
    return s;
}

void __cajeta_crypto_md5_free(void* state) {
    if (state) free(state);
}

void __cajeta_crypto_md5_reset(void* state) {
    if (state) md5_init((struct cajeta_md5_state*) state);
}

// `data_hdr` is a cajeta int8[] header, so bytes start at offset 8; `len` is explicit.
void __cajeta_crypto_md5_update(void* state, const void* data_hdr, int64_t len) {
    if (!state || !data_hdr || len <= 0) return;
    const uint8_t* data = ((const uint8_t*) data_hdr) + 8;
    md5_update((struct cajeta_md5_state*) state, data, (size_t) len);
}

// out_hdr is a cajeta int8[16] header; 16 bytes are written at offset 8.
void __cajeta_crypto_md5_finalize_into(void* state, void* out_hdr) {
    if (!state || !out_hdr) return;
    uint8_t* out = ((uint8_t*) out_hdr) + 8;
    md5_finalize((struct cajeta_md5_state*) state, out);
}

// Width-named folders writing little-endian bytes; Hasher's contract pins width.
void __cajeta_crypto_md5_write_i8 (void* state, int8_t  v) {
    if (state) md5_update((struct cajeta_md5_state*) state, (const uint8_t*) &v, 1);
}
void __cajeta_crypto_md5_write_i16(void* state, int16_t v) {
    if (!state) return;
    uint8_t b[2] = { (uint8_t)(v), (uint8_t)(v >> 8) };
    md5_update((struct cajeta_md5_state*) state, b, 2);
}
void __cajeta_crypto_md5_write_i32(void* state, int32_t v) {
    if (!state) return;
    uint8_t b[4];
    for (int i = 0; i < 4; i++) b[i] = (uint8_t)(v >> (i * 8));
    md5_update((struct cajeta_md5_state*) state, b, 4);
}
void __cajeta_crypto_md5_write_i64(void* state, int64_t v) {
    if (!state) return;
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (i * 8));
    md5_update((struct cajeta_md5_state*) state, b, 8);
}
void __cajeta_crypto_md5_write_f32(void* state, float v) {
    if (!state) return;
    uint32_t bits;
    memcpy(&bits, &v, sizeof bits);
    __cajeta_crypto_md5_write_i32(state, (int32_t) bits);
}
void __cajeta_crypto_md5_write_f64(void* state, double v) {
    if (!state) return;
    uint64_t bits;
    memcpy(&bits, &v, sizeof bits);
    __cajeta_crypto_md5_write_i64(state, (int64_t) bits);
}
void __cajeta_crypto_md5_write_bool(void* state, int8_t v) {
    __cajeta_crypto_md5_write_i8(state, v ? 1 : 0);
}

// finish() projection: the first 8 digest bytes as a little-endian int64. This
// FINALIZES the state, so a second finish() is garbage — finish is terminal.
int64_t __cajeta_crypto_md5_finish_int64(void* state) {
    if (!state) return 0;
    uint8_t digest[16];
    md5_finalize((struct cajeta_md5_state*) state, digest);
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= ((uint64_t) digest[i]) << (i * 8);
    }
    return (int64_t) v;
}

// One-shot variants filling the caller's buffer at `out_hdr + 8` (no int8[] return).
void __cajeta_crypto_md5_oneshot_into(const void* data_hdr, int64_t len, void* out_hdr) {
    if (!out_hdr) return;
    struct cajeta_md5_state s;
    md5_init(&s);
    if (data_hdr && len > 0) {
        md5_update(&s, ((const uint8_t*) data_hdr) + 8, (size_t) len);
    }
    md5_finalize(&s, ((uint8_t*) out_hdr) + 8);
}

// Lowercase hex digest into a caller-supplied int8[32] buffer.
void __cajeta_crypto_md5_oneshot_hex_into(const void* data_hdr, int64_t len, void* out_hdr) {
    if (!out_hdr) return;
    struct cajeta_md5_state s;
    md5_init(&s);
    if (data_hdr && len > 0) {
        md5_update(&s, ((const uint8_t*) data_hdr) + 8, (size_t) len);
    }
    uint8_t digest[16];
    md5_finalize(&s, digest);
    static const char HEX[16] = "0123456789abcdef";
    uint8_t* out = ((uint8_t*) out_hdr) + 8;
    for (int i = 0; i < 16; i++) {
        out[i*2 + 0] = (uint8_t) HEX[(digest[i] >> 4) & 0xF];
        out[i*2 + 1] = (uint8_t) HEX[digest[i] & 0xF];
    }
}


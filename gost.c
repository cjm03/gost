// Charlie Moye
// Implementing the GOST 34.11-94 Cryptographic Hash Function in C.
// gost.c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gost.h"

/* lookup tables : each has two rotated 4-bit S-Boxes */

uint32_t gost_sbox_1[256];
uint32_t gost_sbox_2[256];
uint32_t gost_sbox_3[256];
uint32_t gost_sbox_4[256];

/* initialize */

void gostInit(void)
{
    int a, b, i;
    uint32_t ax, bx, cx, dx;

    /* 8x16 S-Box -- Official CryptoPro S-Box (via wikipedia) */

    uint32_t sbox[8][16] = 
    {
        { 10,  4,  5,  6,  8,  1,  3,  7, 13, 12, 14,  0,  9,  2, 11, 15 },
        {  5, 15,  4,  0,  2, 13, 11,  9,  1,  7,  6,  3, 12, 14, 10,  8 },
        {  7, 15, 12, 14,  9,  4,  1,  0,  3, 11,  5,  2,  6, 10,  8, 13 },
        {  4, 10,  7, 12,  0, 15,  2,  8, 14,  1,  6,  5, 13, 11,  9,  3 },
        {  7,  6,  4, 11,  9, 12,  2, 10,  1,  8,  0, 14, 15, 13,  3,  5 },
        {  7,  6,  2,  4, 13,  9, 15,  0, 10,  1,  5, 11,  8, 14, 12,  3 },
        { 13, 14,  4,  1,  7,  0,  5, 10,  3, 12,  8, 15,  6,  2,  9, 11 },
        {  1,  3, 10,  9,  5, 11,  4, 15,  8,  6,  7, 14, 13,  0,  2, 12 },
    };

    /* s-box precomputation */

    i = 0;
    for (a = 0; a < 16; a++) {
        ax = sbox[1][a] << 15;
        bx = sbox[3][a] << 23;
        cx = sbox[5][a];
        cx = (cx >> 1) | (cx << 31);
        dx = sbox[7][a] << 7;

        for (b = 0; b < 16; b++) {
            gost_sbox_1[i] = ax | (sbox[0][b] << 11);
            gost_sbox_2[i] = bx | (sbox[2][b] << 19);
            gost_sbox_3[i] = cx | (sbox[4][b] << 27);
            gost_sbox_4[i++] = dx | (sbox[6][b] << 3);
        }
    }
}

#define GOST_ENCRYPT_ROUND(k1, k2) \
t = (k1) + r; \
l ^= gost_sbox_1[t & 0xff] ^ gost_sbox_2[(t >> 8) & 0xff] ^ \
gost_sbox_3[(t >> 16) & 0xff] ^ gost_sbox_4[t >> 24]; \
t = (k2) + l; \
r ^= gost_sbox_1[t & 0xff] ^ gost_sbox_2[(t >> 8) & 0xff] ^ \
gost_sbox_3[(t >> 16) &0xff] ^ gost_sbox_4[t >> 24]; \

/* encrypt a block with the given key */

#define GOST_ENCRYPT(key) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[7], key[6]) \
GOST_ENCRYPT_ROUND(key[5], key[4]) \
GOST_ENCRYPT_ROUND(key[3], key[2]) \
GOST_ENCRYPT_ROUND(key[1], key[0]) \
t = r; \
r = l; \
l = t;

/* compression */

void gostCompress(uint32_t* h, uint32_t* m)
{
    int i;
    uint32_t l, r, t, key[8], u[8], v[8], w[8], s[8];

    memcpy(u, h, sizeof(u));
    memcpy(v, m, sizeof(u));

    for (i = 0; i < 8; i += 2) {

        w[0] = u[0] ^ v[0];             /* w = u xor v */
        w[1] = u[1] ^ v[1];
        w[2] = u[2] ^ v[2];
        w[3] = u[3] ^ v[3];
        w[4] = u[4] ^ v[4];
        w[5] = u[5] ^ v[5];
        w[6] = u[6] ^ v[6];
        w[7] = u[7] ^ v[7];

        /* P-T */

        key[0] = (w[0] & 0x000000ff) | ((w[2] & 0x000000ff) << 8) | ((w[4] & 0x000000ff) << 16) | ((w[6] & 0x000000ff) << 24);
        key[1] = ((w[0] & 0x0000ff00) >> 8) | (w[2] & 0x0000ff00) | ((w[4] & 0x0000ff00) << 8) | ((w[6] & 0x0000ff00) << 16);
        key[2] = ((w[0] & 0x00ff0000) >> 16) | ((w[2] & 0x00ff0000) >> 8) | (w[4] & 0x00ff0000) | ((w[6] & 0x00ff0000) << 8);
        key[3] = ((w[0] & 0xff000000) >> 24) | ((w[2] & 0xff000000) >> 16) | ((w[4] & 0xff000000) >> 8) | (w[6] & 0xff000000);
        key[4] = (w[1] & 0x000000ff) | ((w[3] & 0x000000ff) << 8) | ((w[5] & 0x000000ff) << 16) | ((w[7] & 0x000000ff) << 24);
        key[5] = ((w[1] & 0x0000ff00) >> 8) | (w[3]  & 0x0000ff00) | ((w[5] & 0x0000ff00) << 8) | ((w[7] & 0x0000ff00) << 16);
        key[6] = ((w[1] & 0x00ff0000) >> 16) | ((w[3] & 0x00ff0000) >> 8) | (w[5] & 0x00ff0000) | ((w[7] & 0x00ff0000) << 8);
        key[7] = ((w[1] & 0xff000000) >> 24) | ((w[3] & 0xff000000) >> 16) | ((w[5] & 0xff000000) >> 8) | (w[7] & 0xff000000);

        r = h[i];                   /* enciphering transformation */
        l = h[i + 1];
        GOST_ENCRYPT(key);

        s[i] = r;
        s[i + 1] = l;

        if (i == 6) {
            break;
        }

        l = u[0] ^ u[2];            /* U = A(U) */
        r = u[1] ^ u[3];
        u[0] = u[2];
        u[1] = u[3];
        u[2] = u[4];
        u[3] = u[5];
        u[4] = u[6];
        u[5] = u[7];
        u[6] = l;
        u[7] = r;

        if (i == 2) {               /* Constant C_3 */
            u[0] ^= 0xff00ff00;
            u[1] ^= 0xff00ff00;
            u[2] ^= 0x00ff00ff;
            u[3] ^= 0x00ff00ff;
            u[4] ^= 0x00ffff00;
            u[5] ^= 0xff0000ff;
            u[6] ^= 0x000000ff;
            u[7] ^= 0xff00ffff;
        }

        l = v[0];                   /* V = A(A(V)) */
        r = v[2];
        v[0] = v[4];
        v[2] = v[6];
        v[4] = l ^ r;
        v[6] = v[0] ^ r;
        l = v[1];
        r = v[3];
        v[1] = v[5];
        v[3] = v[7];
        v[5] = l ^ r;
        v[7] = v[1] ^ r;
    }

  /* 12 rounds of the LFSR computed from a product matrix and xor in M */


    u[0] = m[0] ^ s[6];
    u[1] = m[1] ^ s[7];
    u[2] = m[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff) ^ (s[1] & 0xffff) ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[7] & 0xffff0000) ^ (s[7] >> 16);
    u[3] = m[3] ^ (s[0] & 0xffff) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^ (s[1] << 16) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
    u[4] = m[4] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[1] & 0xffff0000) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[6] << 16) ^ (s[6] >> 16) ^(s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
    u[5] = m[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff0000) ^ (s[1] & 0xffff) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^  (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff0000) ^ (s[7] << 16) ^ (s[7] >> 16);
    u[6] = m[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[3] ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] << 16);
    u[7] = m[7] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^ (s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[4] ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);

  /* 16 * 1 round of the LFSR and xor in H */

    v[0] = h[0] ^ (u[1] << 16) ^ (u[0] >> 16);
    v[1] = h[1] ^ (u[2] << 16) ^ (u[1] >> 16);
    v[2] = h[2] ^ (u[3] << 16) ^ (u[2] >> 16);
    v[3] = h[3] ^ (u[4] << 16) ^ (u[3] >> 16);
    v[4] = h[4] ^ (u[5] << 16) ^ (u[4] >> 16);
    v[5] = h[5] ^ (u[6] << 16) ^ (u[5] >> 16);
    v[6] = h[6] ^ (u[7] << 16) ^ (u[6] >> 16);
    v[7] = h[7] ^ (u[0] & 0xffff0000) ^ (u[0] << 16) ^ (u[7] >> 16) ^ (u[1] & 0xffff0000) ^ (u[1] << 16) ^ (u[6] << 16) ^ (u[7] & 0xffff0000);

  /* 61 rounds of LFSR, mixing up h (computed from a product matrix) */

    h[0] = (v[0] & 0xffff0000) ^ (v[0] << 16) ^ (v[0] >> 16) ^ (v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] >> 16) ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff);
    h[1] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^ (v[1] & 0xffff) ^ v[2] ^ (v[2] >> 16) ^ (v[3] << 16) ^ (v[4] >> 16) ^ (v[5] << 16) ^ (v[6] << 16) ^ v[6] ^ (v[7] & 0xffff0000) ^ (v[7] >> 16);
    h[2] = (v[0] & 0xffff) ^ (v[0] << 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[6] ^ (v[6] >> 16) ^ (v[7] & 0xffff) ^ (v[7] << 16) ^ (v[7] >> 16);
    h[3] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^ (v[1] & 0xffff0000) ^ (v[1] >> 16) ^ (v[2] << 16) ^ (v[2] >> 16) ^ v[2] ^ (v[3] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^ (v[7] & 0xffff) ^ (v[7] >> 16);
    h[4] = (v[0] >> 16) ^ (v[1] << 16) ^ v[1] ^ (v[2] >> 16) ^ v[2] ^ (v[3] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16);
    h[5] = (v[0] << 16) ^ (v[0] & 0xffff0000) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^ v[2] ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^ (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff0000);
    h[6] = v[0] ^ v[2] ^ (v[2] >> 16) ^ v[3] ^ (v[3] << 16) ^ v[4] ^ (v[4] >> 16) ^ (v[5] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ v[7];
    h[7] = v[0] ^ (v[0] >> 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ v[4] ^ (v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16) ^ v[7];
}

/* Clear the state of the given context structure */

void gostHashReset(GostHashCtx* ctx)
{
    memset(ctx->sum, 0, 32);
    memset(ctx->hash, 0, 32);
    memset(ctx->len, 0, 32);
    memset(ctx->partial, 0, 32);
    ctx->partial_bytes = 0;
}

/* mix in a 32 byte chunk ("stage 3") */

void gostHashBytes(GostHashCtx* ctx, const uint8_t* buf, size_t bits)
{
    int i, j;
    uint32_t a, c, m[8];

    /* convert bytes to a long words and compute the sum */

    j = 0;
    c = 0;
    for (i = 0; i < 8; i++) {
        a = ((uint32_t) buf[j]) | (((uint32_t) buf[j + 1]) << 8) | (((uint32_t) buf[j + 2]) << 16) | (((uint32_t) buf[j + 3]) << 24);
        j += 4;
        m[i] = a;
        c = a + c + ctx->sum[i];
        ctx->sum[i] = c;
        c = c < a ? 1 : 0;
    }

    /* compress */

    gostCompress(ctx->hash, m);

    /* a 64 bit counter should do */

    ctx->len[0] += bits;
    if (ctx->len[0] < bits) {
        ctx->len[1]++;
    }
}

/* Mix in len bytes of data for the given buffer */

void gostHashUpdate(GostHashCtx* ctx, const uint8_t* buf, size_t len)
{
    size_t i, j;

    i = ctx->partial_bytes;
    j = 0;
    while (i < 32 && j < len) {
        ctx->partial[i++] = buf[j++];
    }
    if (i < 32) {
        ctx->partial_bytes = i;
        return;
    }
    gostHashBytes(ctx, ctx->partial, 256);

    while ((j + 32) < len) {
        gostHashBytes(ctx, &buf[j], 256);
        j += 32;
    }
    i = 0;
    while (j < len) {
        ctx->partial[i++] = buf[j++];
    }
    ctx->partial_bytes = i;
}

/* compute and save 32-byte digest */

void gostHashFinal(GostHashCtx* ctx, uint8_t* digest)
{
    int i, j;
    uint32_t a;

    /* adjust and mix in the last chunk */

    if (ctx->partial_bytes > 0) {
        memset(&ctx->partial[ctx->partial_bytes], 0, 32 - ctx->partial_bytes);
        gostHashBytes(ctx, ctx->partial, ctx->partial_bytes << 3);
    }

    /* mix in the length and sum */

    gostCompress(ctx->hash, ctx->len);
    gostCompress(ctx->hash, ctx->sum);

    /* convert output to bytes */

    j = 0;
    for (i = 0; i < 8; i++) {
        a = ctx->hash[i];
        digest[j] = (uint8_t) a;
        digest[j + 1] = (uint8_t) (a >> 8);
        digest[j + 2] = (uint8_t) (a >> 16);
        digest[j + 3] = (uint8_t) (a >> 24);
        j += 4;
    }
}



//   GOST R 34.11-94 operates on a 256-bit internal state `H` and uses a Merkle-Damgard construction.
//   Each message goes through a compression function which internally uses GOST 28147-89.
//         --INITIALIZE VARIABLES--
//   `H` (hash state): 256 bits initialized to zeros
//   `L` (sum of all processed message lengths modulo 2^256): 256 bits
//   `Σ` (sum of all message blocks modulo 2^256): 256 bits
//   `C` (internal constants)

// uint8_t H[32] = {0};    // initial hash value
// uint8_t L[32] = {0};    // total msg length mod 2^256
// uint8_t Sum[32] = {0};  // cumulative sum of msg blocks

/*   Compression Function f(H, M)
 *      Step 1: A = H, B = M, C = A XOR B
 *      Step 2: Generate 4 256-bit keys 
 *      Step 3: Encrypt H through 12 rounds of GOST block cipher
 *      Step 4: Apply
 *
 */


/*--------------------------------------------------------*/

int main(void)
{
    int i, j, l;
    clock_t tim;
    GostHashCtx hash;
    uint8_t digest[32], *buf;
    uint8_t msg1[160] = 
    {
        0x54, 0x68, 0x65, 0x20, 0x77, 0x6f, 0x72, 0x6c,
        0x64, 0x20, 0x77, 0x65, 0x20, 0x6c, 0x69, 0x76,
        0x65, 0x20, 0x69, 0x6e, 0x20, 0x69, 0x73, 0x20,
        0x6e, 0x6f, 0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x65,
        0x72, 0x20, 0x77, 0x68, 0x61, 0x74, 0x20, 0x69,
        0x74, 0x20, 0x77, 0x61, 0x73, 0x20, 0x79, 0x65,
        0x73, 0x74, 0x65, 0x72, 0x64, 0x61, 0x79, 0x2c,
        0x20, 0x61, 0x6e, 0x64, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x73, 0x61, 0x6d, 0x65, 0x20, 0x6d, 0x61,
        0x79, 0x20, 0x62, 0x65, 0x20, 0x73, 0x61, 0x69,
        0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x6f,
        0x6d, 0x6f, 0x72, 0x72, 0x6f, 0x77, 0x20, 0x6a,
        0x75, 0x73, 0x74, 0x20, 0x61, 0x73, 0x20, 0x69,
        0x74, 0x20, 0x77, 0x61, 0x73, 0x20, 0x73, 0x61,
        0x69, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x65, 0x6e, 0x74, 0x69, 0x72,
        0x65, 0x74, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x65,
        0x74, 0x65, 0x72, 0x6e, 0x69, 0x74, 0x79, 0x20,
        0x70, 0x72, 0x69, 0x6f, 0x72, 0x20, 0x74, 0x6f,
        0x20, 0x69, 0x74, 0x73, 0x20, 0x72, 0x65, 0x61,
    };

    gostInit();
    // gostHashReset(&hash);
    // gostHashUpdate(&hash, msg1, 160);
    // gostHashFinal(&hash, digest);
    //
    // if (memcmp(digest, msg1, 32) != 0) {
    //     fprintf(stderr, "Test failed.\n");
    //     exit(-1);
    // }

    for (i = 0; i < 1000; i++) {
        gostHashReset(&hash);
        for (j = 0; j < 160; ) {
            l = rand() % 51;
            if (l + j >= 160) {
                l = 160 - j;
            }
            gostHashUpdate(&hash, &msg1[j], l);
            j += l;
        }
        if (memcmp(digest, msg1, 32) != 0) {
            fprintf(stderr, "test failed (iteration %d).\n", i);
            exit(-1);
        }
    }
    printf("test passed");

    return 0;
}

// gost.h
#ifndef GOST_H
#define GOST_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* State Structure */

typedef struct {
    uint32_t sum[8];
    uint32_t hash[8];
    uint32_t len[8];
    uint8_t partial[32];
    size_t partial_bytes;
} GostHashCtx;

/* compute some lookup tables needed by all other functions */

void gostInit(void);

/* clear the state of the given context structure */

void gostHashReset(GostHashCtx* ctx);

/* mix in len bytes of data for the given buffer */

void gostHashUpdate(GostHashCtx* ctx, const uint8_t* buf, size_t len);

/* compute and save the 32-byte digest */

void gostHashFinal(GostHashCtx* ctx, uint8_t* digest);

#endif

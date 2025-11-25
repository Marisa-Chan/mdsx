#ifndef GHASH_H
#define GHASH_H

#include "defines.h"

inline static u32 BSWAP4(u32 d) { return (d >> 24) | ((d & 0xFF00) << 8) | ((d & 0xFF0000) >> 8) | (d << 24); }
inline static u64 BSWAP8(u64 d) { return (d >> 56) | (d << 56) | ((d & 0xFF000000000000) >> 40) | ((d & 0xFF00) << 40) |
                                         ((d & 0xFF0000000000) >> 24) | ((d & 0xFF0000) << 24) |
                                         ((d & 0xFF000000) << 8) | ((d & 0xFF00000000) >> 8) ; }

inline static u8 BITSWAP4(u8 v)
{
    return ((v & 8) >> 3) | ((v & 1) << 3) | ((v & 4) >> 1) | ((v & 2) << 1);
}

typedef struct
{
    u64 table128[16][16][2];
    u32 table64[16][16][2];
} GHash;

void invertBits(u8 *bits, int byteCount);
void ghash_init128(u8 *in, GHash *table);
void ghash_init64(u8 *in, GHash *table);
void ghash128(u8 *in, u64 *out, GHash *table);

#endif

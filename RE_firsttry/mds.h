#ifndef MDS_H
#define MDS_H

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;



#include "aes.h"
#include "ghash.h"

enum CRYPT_TYPE
{
    CRYPT_AES256 = 1,
    CRYPT_AES192 = 2,
    CRYPT_AES128 = 3,
    CRYPT_BLOWFISH = 4,
    CRYPT_CAST5 = 5,
    CRYPT_SERPENT = 6,
    CRYPT_3DES = 7,
    CRYPT_TWOFISH = 8,
    CRYPT_DES = 9
};

typedef struct
{
    int type;
    int digestSize;
    int blksz;
} CryptInfo;

typedef struct
{
    u8 guid[16];
    int cryptSeq[4];
    int mode[4];
} CryptVariant;

typedef struct
{
    int crypt;
    int mode;
    GHash gcm;
    AES_KEY aes_dataKey;
    AES_KEY aes_seqKey;
    u8 dg[256];
} CryptContext;



/* mds.c */

/* decode.c */
extern CryptInfo g_cryptInfos[10];
extern CryptVariant g_cryptVariants[17];


int decode1(u8 *data);
void decode2(u8 *data, u8 *key);

/* edc.c */
u32 getEDC(void *data, u32 num);

/* ripemd.c */
void makeKeyRipemd(u8 *pkey, u32 keysz, u8 *pdata, u32 datasz, u32 iter, u8 *out, u32 outsz);

/* whrlpool.c */
void whrlpool_make1(u8 *pkey, u32 keysz, u8 *pdata, u32 datasz, u32 iter, u8 *out, u32 N);

/* utils.c */
inline static u32 getU32(const void *mem)
{
	const u8 *mem8 = (const u8 *)mem;
	return (u32)(mem8[0] | (mem8[1] << 8) | (mem8[2] << 16) | (mem8[3] << 24));
}

inline static void setU32(void *mem, u32 val)
{
	u8 *mem8 = (u8 *)mem;
	mem8[0] = val & 0xff;
	mem8[1] = (val >> 8) & 0xff;
	mem8[2] = (val >> 16) & 0xff;
	mem8[3] = (val >> 24) & 0xff;
}

u32 freadU32(FILE *f);
void printHex(void *data, int num);

#endif

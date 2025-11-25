#include "mds.h"
#include "whrlpool/whrlpool.h"

void whrlpool_hmac(u8 *pkey, u32 keysz, u8 *pdata, u32 datasz, u8 *out)
{
    u8 genkey[64];
    WHIRLPOOL_CTX ctx;

    if (keysz > 0x40)
    {
        WHIRLPOOL_Init(&ctx);
        WHIRLPOOL_Update(&ctx, pkey, keysz);
        WHIRLPOOL_Final(genkey, &ctx);
        pkey = genkey;
        keysz = 64;
    }

    u8 buf1[0x40];
    u8 buf2[0x40];

    memset(buf1, 0x36, 0x40);
    memset(buf2, 0x5c, 0x40);

    for(int i = 0; i < keysz; i++)
    {
        buf1[i] ^= pkey[i];
        buf2[i] ^= pkey[i];
    }

    WHIRLPOOL_Init(&ctx);
    WHIRLPOOL_Update(&ctx, buf1, 0x40);
    WHIRLPOOL_Update(&ctx, pdata, datasz);
    WHIRLPOOL_Final(out, &ctx);
    WHIRLPOOL_Init(&ctx);
    WHIRLPOOL_Update(&ctx, buf2, 0x40);
    WHIRLPOOL_Update(&ctx, out, 0x40);
    WHIRLPOOL_Final(out, &ctx);
}

void whrlpool_make1(u8 *pkey, u32 keysz, u8 *pdata, u32 datasz, u32 iter, u8 *out, u32 N)
{
    u8 dgt1[0x40];
    u8 dgt2[0x40];
    u8 buf[128 + 4];
    memcpy(buf, pdata, datasz);
    setU32(buf + datasz, N << 24);
    whrlpool_hmac(pkey, keysz, buf, datasz + 4, dgt1);
    memcpy(out, dgt1, 0x40);

    if (iter > 1)
    {
        iter--;
        while(iter > 0)
        {
            whrlpool_hmac(pkey, keysz, dgt1, 0x40, dgt2);
            for (int i = 0; i < 0x40; i++)
            {
                out[i] ^= dgt2[i];
                dgt1[i] = dgt2[i];
            }
            iter--;
        }
    }
}

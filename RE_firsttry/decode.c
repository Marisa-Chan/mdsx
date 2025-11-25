#include "mds.h"
#include "ghash.h"

CryptInfo g_cryptInfos[10] =
{
    {CRYPT_AES256,  0x10, 0x20},
    {CRYPT_AES192,  0x10, 0x18},
    {CRYPT_AES128,  0x10, 0x10},
    {CRYPT_BLOWFISH,  8, 0x38},
    {CRYPT_CAST5,  8, 0x10},
    {CRYPT_DES,  8, 7},
    {CRYPT_SERPENT,  0x10, 0x20},
    {CRYPT_3DES,  8, 0x18},
    {CRYPT_TWOFISH,  0x10, 0x20},
    {0, 0, 0}
};

CryptVariant g_cryptVariants[17] =
{
    {{0}, 0, 0},
    {{0x65, 0x01, 0xf7, 0x41, 0x54, 0x77, 0xf5, 0x45, 0xaa, 0x34, 0xe0, 0x58, 0x83, 0xe2, 0x78, 0x3d},
     {CRYPT_AES256, 0, 0, 0}, {5, 1, 2, 0} },
    {{0xf2, 0x67, 0xc2, 0xdf, 0xe4, 0x28, 0xcd, 0x42, 0xaf, 0x52, 0x79, 0xaa, 0x17, 0x08, 0xb3, 0x1e},
     {CRYPT_AES192, 0, 0, 0}, {5, 1, 2, 0} },
    {{0x18, 0x97, 0x9c, 0x39, 0xb6, 0x5a, 0x92, 0x45, 0x8e, 0xe3, 0x49, 0x3a, 0x96, 0xe6, 0x9f, 0xaa},
     {CRYPT_AES128, 0, 0, 0}, {5, 1, 2, 0} },
    {{0x1c, 0x49, 0xc2, 0x2f, 0xa1, 0x5a, 0xae, 0x4e, 0x8e, 0x34, 0xac, 0x3b, 0x2b, 0xaf, 0xad, 0x57},
     {CRYPT_BLOWFISH, 0, 0, 0}, {1, 2, 0, 0} },
    {{0x28, 0x46, 0xb1, 0x9b, 0x30, 0xd9, 0xa4, 0x44, 0xa1, 0x04, 0xeb, 0x92, 0x8d, 0x7a, 0x10, 0xab},
     {CRYPT_CAST5, 0, 0, 0}, {1, 2, 0, 0} },
    {{0x59, 0x57, 0xf2, 0x6c, 0x5f, 0x19, 0x5d, 0x49, 0x98, 0x59, 0xc4, 0x48, 0x94, 0x39, 0x17, 0x72},
     {CRYPT_SERPENT, 0, 0, 0}, {5, 1, 2, 0} },
    {{0x48, 0xad, 0xa9, 0x33, 0x55, 0xe6, 0xd6, 0x40, 0x92, 0x14, 0xb0, 0xa1, 0x66, 0xb0, 0x5a, 0x33},
     {CRYPT_3DES, 0, 0, 0}, {1, 2, 0, 0} },
    {{0x20, 0x48, 0x54, 0xb7, 0xf0, 0x4c, 0x02, 0x4e, 0x83, 0xf4, 0x8c, 0xb3, 0xe6, 0x20, 0x60, 0x3d},
     {CRYPT_TWOFISH, 0, 0, 0}, {5, 1, 2, 0} },
    {{0x7c, 0x81, 0xc8, 0x9a, 0x8e, 0xfb, 0xbf, 0x49, 0x81, 0x65, 0xa6, 0x22, 0x79, 0x68, 0x24, 0x9b},
     {CRYPT_TWOFISH, CRYPT_AES256, 0, 0}, {5, 1, 3, 0} },
    {{0xfe, 0x08, 0x32, 0x0c, 0x7f, 0xb9, 0x7e, 0x4e, 0x94, 0x39, 0x9b, 0xe2, 0x6f, 0x97, 0xfa, 0x73},
     {CRYPT_SERPENT, CRYPT_TWOFISH, CRYPT_AES256, 0}, {5, 1, 3, 0} },
    {{0x08, 0x3c, 0x1e, 0xe7, 0x69, 0x9a, 0x7d, 0x41, 0x87, 0xc0, 0xcf, 0x1b, 0x11, 0x8b, 0xb9, 0x89},
     {CRYPT_AES256, CRYPT_SERPENT, 0, 0}, {5, 1, 3, 0} },
    {{0xcc, 0x50, 0x3c, 0x1c, 0xeb, 0x7d, 0x3b, 0x46, 0xa4, 0x0b, 0x0b, 0x86, 0x45, 0xd3, 0xb0, 0xb1},
     {CRYPT_AES256, CRYPT_TWOFISH, CRYPT_SERPENT}, {5, 1, 3, 0} },
    {{0xd1, 0x9c, 0x37, 0x79, 0xe6, 0x44, 0xce, 0x42, 0x9d, 0xfc, 0xbb, 0xae, 0x05, 0x62, 0x91, 0x06},
     {CRYPT_SERPENT, CRYPT_TWOFISH, 0, 0}, {5, 1, 3, 0} },
    {{0x41, 0x80, 0x2d, 0x3a, 0x73, 0xaa, 0x78, 0x40, 0xa4, 0x92, 0xb1, 0x71, 0xa2, 0xd2, 0xfb, 0x36},
     {CRYPT_BLOWFISH, CRYPT_AES256, 0, 0}, {4, 0, 0, 0} },
    {{0x40, 0x1f, 0xb5, 0xeb, 0x55, 0x9a, 0xc2, 0x43, 0x87, 0x65, 0x63, 0x9f, 0x06, 0x9e, 0x02, 0x60},
     {CRYPT_SERPENT,CRYPT_BLOWFISH, CRYPT_AES256}, {4, 0, 0, 0} },
    {{0}, 0, 0}
};


void unshuffle1(u8 *data)
{
    u32 val = getEDC(data, 0x40) ^ 0x567372ff;
    for(int i = 0; i < 0x40; i += 4)
    {
        val = (val * 0x35e85a6d) + 0x1548dce9;
        u32 ud = getU32(data + i);
        setU32(data + i, ud ^ val ^ 0xec564717);

        if (data[i] == 0)
            data[i] = 0x5f;
        if (data[i+1] == 0)
            data[i+1] = 0x5f;
        if (data[i+2] == 0)
            data[i+2] = 0x5f;
        if (data[i+3] == 0)
            data[i+3] = 0x5f;
    }
}

CryptInfo *getCryptInfo(u32 ctype)
{
    CryptInfo *inf = g_cryptInfos;
    while(inf->type != 0)
    {
        if (inf->type == ctype)
            return inf;
        inf++;
    }
    return NULL;
}

u32 getVariantBlkSz(u32 variant)
{
    u32 sz = 0;
    for(int i = 0; i < 4; i++)
    {
        u32 ctype = g_cryptVariants[variant].cryptSeq[i];
        if (ctype == 0)
            break;

        sz += getCryptInfo(ctype)->blksz;
    }
    return sz;
}


/* seems it will return 0x78 */
u32 getMaxBlkSize()
{
    u32 sz = 0;
    for(int i = 1; g_cryptVariants[i].cryptSeq[0] != 0; i++)
    {
        u32 csz = getVariantBlkSz(i);
        if (sz < csz)
            sz = csz;
    }
    return sz;
}




int decrypT(u8 *data, u32 datasz, u32 blksz, u32 N, u32 p5, CryptContext *ctx)
{
    u32 datapos = 0;

    if (ctx->mode == 1)
    {
        CryptInfo *cinf = getCryptInfo(ctx->crypt);

        u64 ctr = 1;
        if (p5 & 2)
            ctr = 1 + blksz / 16 * N;

        if (cinf->digestSize == 8)
        {

        }
        else if (cinf->digestSize == 0x10)
        {
            u32 count = datasz / 16;
            while (count > 0)
            {
                u64 nctr = BSWAP8(ctr);
                u64 ctrencr[2];
                ghash128((u8 *)&nctr, ctrencr, &ctx->gcm);

                u64 *qdata = (u64 *)(data + datapos);
                qdata[0] ^= ctrencr[0];
                qdata[1] ^= ctrencr[1];
                AES_decrypt(data + datapos, data + datapos, &ctx->aes_dataKey);
                qdata[0] ^= ctrencr[0];
                qdata[1] ^= ctrencr[1];
                datapos += 16;

                ctr++;
                count--;
            }
        }
    }
    else if (ctx->mode == 2)
    {
        if (p5 & 1)
        {

        }
        else if (p5 & 2)
        {

        }
        else
        {
            CryptInfo *cinf = getCryptInfo(ctx->crypt);
            u8 wrk1[16];
            u8 wrk2[16];
            memcpy(wrk1, ctx->dg, 16);

            u32 count = datasz / cinf->digestSize;
            while(count > 0)
            {
                for (u32 i = 0; i < 8; i++)
                    wrk2[i] = data[datapos + i] = data[datapos + i] ^ ctx->dg[8 + i];

                if (cinf->digestSize == 0x10)
                {
                    for (u32 i = 0; i < 8; i++)
                        wrk2[8 + i] = data[datapos + 8 + i] = data[datapos + 8 + i] ^ ctx->dg[8 + i];
                }

                AES_decrypt(data + datapos, data + datapos, &ctx->aes_dataKey);

                for (u32 i = 0; i < 8; i++)
                {
                    data[datapos + i] ^= wrk1[i];
                    wrk1[i] = wrk2[i];
                }

                if (cinf->digestSize == 0x10)
                {
                    for (u32 i = 8; i < 16; i++)
                    {
                        data[datapos + i] ^= wrk1[i];
                        wrk1[i] = wrk2[i];
                    }
                }

                datapos += cinf->digestSize;
                count--;
            }
        }
    }
    else if (ctx->mode == 5)
    {
        if (datasz & 0xf)
            return -1;

        u64 ctr = N;

        u32 spos = 0;
        u32 cnt = datasz / 16;
        while (cnt != 0)
        {
            u32 cnum;
            if (cnt < 0x20)
                cnum = spos + cnt;
            else
                cnum = 0x20;

            u64 ctrencr[2];
            memset(ctrencr, 0, 16);
            setU32(ctrencr, ctr);

            AES_encrypt((u8 *)ctrencr, (u8 *)ctrencr, &ctx->aes_seqKey);

            for(int i = 0; i < cnum; i++)
            {
                if (spos <= i)
                {
                    u64 *qdata = (u64 *)(data + datapos);
                    qdata[0] ^= ctrencr[0];
                    qdata[1] ^= ctrencr[1];
                    AES_decrypt(data + datapos, data + datapos, &ctx->aes_dataKey);
                    qdata[0] ^= ctrencr[0];
                    qdata[1] ^= ctrencr[1];
                    datapos += 16;
                }

                u8 xr = 0;
                if (ctrencr[1] & ((u64)1 << 63))
                    xr = 0x87;
                ctrencr[1] <<= 1;
                if (ctrencr[0] & ((u64)1 << 63))
                    ctrencr[1] |= 1;

                ctrencr[0] <<= 1;
                ctrencr[0] ^= xr;
            }

            cnum -= spos;
            spos = 0;
            cnt -= cnum;
            ctr++;
        }
    }
    else
    {
        printf("This app does not support crypt mode %d\n", ctx->mode);
        return -1;
    }
    return 0;
}






int doDecrypt(u8 *data, u32 datasz, u32 blksz, u32 N, u32 p5, CryptContext *ctx)
{
    int dsz = getCryptInfo(ctx->crypt)->digestSize;

    int blk = 0x200;
    if (dsz <= blksz)
        blk = blksz;

    const u32 asz = blk - (blk % dsz);
    if ((p5 & 4) == 0)
    {
        const u32 c = datasz / blk;
        for (int i = 0; i < c; i++)
        {
            if (decrypT(data + i * blk, asz, asz, N + i, p5, ctx) < 0)
                return -1;
        }
    }
    else
    {
        u32 adsz = datasz - (datasz % dsz);
        u32 pos = 0;
        int i = 0;
        while(adsz > 0)
        {
            u32 bsz = asz;
            if (adsz <= asz)
                bsz = adsz;

            if ( decrypT(data + pos, bsz, adsz, N + i, p5, ctx) < 0 )
                return -1;
            pos += bsz;
            adsz -= bsz;
            i++;
        }
    }
    return 0;
}


int decode1(u8 *data)
{
    u8 unsh[0x101];
    memset(unsh, 0, 0x101);
    memcpy(unsh, data, 0x40);

    unshuffle1(unsh);

    CryptContext ctx;

    for(int hashAlgo = 1; hashAlgo < 4; hashAlgo++)
    {
        u32 maxKeySz = getMaxBlkSize(); /* must return 78? */

        u8 key[0x100];
        if (hashAlgo == 1)
            makeKeyRipemd(unsh, 0x40, data, 0x40, 2000, key, maxKeySz + 0x20);
        else if (hashAlgo == 2)
            makeKeySha1(unsh, 0x40, data, 0x40, 2000, key, maxKeySz + 0x20);
        else if (hashAlgo == 3)
            whrlpool_make1(unsh, 0x40, data, 0x40, 1000, key, maxKeySz + 0x20);

        /* Try for first 3 single AES crypt variants */
        for(int vID = 1; vID < 4; vID++)
        {
            CryptVariant *pVar = &g_cryptVariants[vID];

            /* Try different modes for this variant */
            for(int mID = 0; mID < 4; mID++)
            {
                int mode = pVar->mode[mID];
                if (mode <= 0 || mode > 5)
                    break;

                u8 *pd = key;

                if (mode < 5)
                {
                    memcpy(ctx.dg, key, 32);
                    pd = key + 32;
                }

                /* Support only for single AES crypt !!! */
                int crypt = pVar->cryptSeq[0];
                CryptInfo *cinf = getCryptInfo(crypt);

                /* Here must be function which will set encrypt/decrypt keys for data
                and for all crypt in sequence.
                But I limit it for single aes */


                ctx.crypt = crypt;
                ctx.mode = mode;

                if (crypt == CRYPT_AES256)
                    AES_set_decrypt_key(pd, 256, &ctx.aes_dataKey);
                else if (crypt == CRYPT_AES192)
                    AES_set_decrypt_key(pd, 192, &ctx.aes_dataKey);
                else if (crypt == CRYPT_AES128)
                    AES_set_decrypt_key(pd, 128, &ctx.aes_dataKey);
                else
                {
                    printf("Only single AES supported !\n");
                    return 0;
                }

                if (mode == 5)
                {
                    u32 sz = getVariantBlkSz(1);

                    memcpy(ctx.dg, key + sz, sz);

                    if (crypt == CRYPT_AES256)
                        AES_set_encrypt_key(ctx.dg, 256, &ctx.aes_seqKey);
                    else if (crypt == CRYPT_AES192)
                        AES_set_encrypt_key(ctx.dg, 192, &ctx.aes_seqKey);
                    else if (crypt == CRYPT_AES128)
                        AES_set_encrypt_key(ctx.dg, 128, &ctx.aes_seqKey);
                    else
                    {
                        printf("Only single AES supported !\n");
                        return 0;
                    }
                }
                else if (mode == 1)
                {
                    if (cinf->digestSize == 8)
                        ghash_init64(ctx.dg, &ctx.gcm);
                    else if (cinf->digestSize == 0x10)
                        ghash_init128(ctx.dg, &ctx.gcm);
                }

                u8 debuff[512];
                memcpy(debuff, data, 512);

                doDecrypt(debuff + 0x40, 0x1c0, 0x200, 0, 4, &ctx);

                printf("%d %d \n", crypt, mode);

                printHex(debuff + 0x40, 0x1c0);
            }
        }
    }

    return 0;
}


void decode2(u8 *data, u8 *key)
{

}

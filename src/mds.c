#include "mds.h"
#include <zlib.h>





int main(int argc, const char *argv[])
{

    if (argc < 2)
    {
        printf("Nothing to open\n");
        return 0;
    }

    FILE *mds = fopen(argv[1], "rb");

    if (!mds)
    {
        printf("Can't open %s\n", argv[1]);
        return 0;
    }

    fseek(mds, 0x12, SEEK_SET);
    int version = fgetc(mds);

    if (version < 2)
    {
        printf("It's not mdsv2. Bye-bye\n");
        return 0;
    }

    fseek(mds, 0x2c, SEEK_SET);
    u32 offset = freadU32(mds);

    fseek(mds, offset, SEEK_SET);

    u8 data1[0x200];

    fread(data1, 0x200, 1, mds);

    PCRYPTO_INFO ci;
    decode1(data1, NULL, &ci);

    u32 comSize = getU32(data1 + 0x150); //compressed size?
    u32 decSize = getU32(data1 + 0x154); //decompressed size?

    fseek(mds, 0x30, SEEK_SET);
    u8 *data2 = (u8 *)malloc(offset - 0x30);
    fread(data2, 1, offset - 0x30, mds);


    DecryptBlock(data2, offset - 0x30, 0, 0, 4, ci);

    u8 *mdxHeader = (u8 *)malloc(decSize + 0x12);

    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    infstream.avail_in = offset-0x30;
    infstream.next_in = data2;
    infstream.avail_out = decSize;
    infstream.next_out = mdxHeader + 0x12;

    inflateInit(&infstream);

    inflate(&infstream, Z_NO_FLUSH);
    inflateEnd(&infstream);


    fseek(mds, 0, SEEK_SET);
    fread(mdxHeader, 1, 0x12, mds);

    Decoder encryptInfo;
    encryptInfo.mode = -1;
    encryptInfo.ctr = 1;

    u32 keyBlockOff = getU32(mdxHeader + offsetof(MDX_Header, encryption_block_offset));
    if (keyBlockOff)
    {
        printf("Encryption detected\n");

        if (argc < 3)
        {
            printf("Please specify password as 2nd argument\n");
            return 0;
        }

        PCRYPTO_INFO ci2;
        if ( decode1(mdxHeader + keyBlockOff, argv[2], &ci2) == 0 )
            printf("Password \"%s\": OK\n", argv[2]);
        else
        {
            printf("Password \"%s\": WRONG\n", argv[2]);
            return -1;
        }

        //encryptInfo.bsize = EAGetKeySize(ci2->ea);

        // seems it's always use one mode AES 256
        // with gf
        encryptInfo.bsize = 32;
        encryptInfo.mode = 2;

        u8 *keyblock = mdxHeader + keyBlockOff;
        memcpy(encryptInfo.dg, keyblock + 0x50, 0x20);
        Gf128Tab64Init(keyblock + 0x50, &encryptInfo.gf_ctx);
        aes_encrypt_key(keyblock + 0x70, encryptInfo.bsize, &encryptInfo.encr);
        aes_decrypt_key(keyblock + 0x70, encryptInfo.bsize, &encryptInfo.decr);
    }
    else
    {
        printf("No encryption detected\n");
    }

    // dump mdxHeader
    printf("\nDumping header into header.out\n");

    FILE *b = fopen("header.out", "wb");
    fwrite(mdxHeader, 1, decSize + 0x12, b);
    fclose(b);

    u32 footerOff = 0;

    u16 secSize = 0x800;
    u64 startOffset = 0;

    u16 numSessions = getU16(mdxHeader + offsetof(MDX_Header, num_sessions));
    u32 sessOffset = getU32(mdxHeader + offsetof(MDX_Header, sessions_blocks_offset));
    for (u16 i = 0; i < numSessions; i++)
    {
        u32 sblkOff = sessOffset + i * sizeof(MDX_SessionBlock);
        u8 numAllBlocks = getU8(mdxHeader + sblkOff + offsetof(MDX_SessionBlock, num_all_blocks));
        u32 tracksOff = getU32(mdxHeader + sblkOff + offsetof(MDX_SessionBlock, tracks_blocks_offset));

        for (u8 j = 0; j < numAllBlocks; j++)
        {
            u32 trkOff = tracksOff + j * sizeof(MDX_TrackBlock);

            u8 mode = getU8(mdxHeader + trkOff + offsetof(MDX_TrackBlock, mode));
            if (mode & 7) // ????
            {
                footerOff = getU32(mdxHeader + trkOff + offsetof(MDX_TrackBlock, footer_offset));
                secSize = getU16(mdxHeader + trkOff + offsetof(MDX_TrackBlock, sector_size));
                startOffset = getU64(mdxHeader + trkOff + offsetof(MDX_TrackBlock, start_offset));
            }

            // Only one footer?
            if (footerOff)
                break;
        }

        if (footerOff)
            break;
    }


    /* check footer compression info */
    u8 fflags = getU8(mdxHeader + footerOff + offsetof(MDX_Footer, flags));
    u64 numCElm = 0;
    u16 *cElems = NULL;
    u64 unknum = 0;

    u64 cBlockSz = 0;

    int compressed = 0;

    if (fflags & 1) //compression?
        compressed = 1;


    if (compressed == 0 && encryptInfo.mode == 0)
    {
        printf("Not compressed and not encrypted. Nothing to do\n");
        return 0;
    }


    fclose(mds);


    /* here must be footer filename, but we hardcode *.mdf*/
    char n_mdf[1024];
    strcpy(n_mdf, argv[1]);
    n_mdf[ strlen(n_mdf) - 1 ] = 'f';

    printf("\nReading MDF file %s\n\n", n_mdf);

    FILE *mdf = fopen(n_mdf, "rb");
    fseek(mdf, 0, SEEK_END);
    u64 mdfsize = ftell(mdf);
    fseek(mdf, 0, SEEK_SET);


    if (compressed)
    {
        u32 sz1 = getU32(mdxHeader + footerOff + offsetof(MDX_Footer, _unk1_size32_));
        u64 sz2 = getU32(mdxHeader + footerOff + offsetof(MDX_Footer, _unk2_size64_));
        u64 ctableoff = getU64(mdxHeader + footerOff + offsetof(MDX_Footer, compress_table_offset));

        cBlockSz = sz1 * secSize;

        if ((fflags & 2) == 0 && getU32(mdxHeader + footerOff + offsetof(MDX_Footer, _unk2_size_)) == 0)
        {
            unknum = ((secSize - startOffset) - 1 + ctableoff) / secSize; //??? is ctableoff?
        }
        else
        {
            unknum = getU32(mdxHeader + footerOff + offsetof(MDX_Footer, _unk2_size_));
        }

        numCElm = ((sz1 - 1) + sz2) / sz1;
        cElems = (u16 *)calloc(numCElm, 2);

        u16 *tmpBuff = calloc(numCElm + 0x800, 2);
        fseek(mdf, startOffset + ctableoff, SEEK_SET);

        /* read till file end?
           or it's can be multiple instances? */
        fread(tmpBuff, mdfsize - (ctableoff + startOffset), 1, mdf);

        z_stream cstrm;
        cstrm.zalloc = Z_NULL;
        cstrm.zfree = Z_NULL;
        cstrm.opaque = Z_NULL;
        cstrm.avail_in = mdfsize - (ctableoff + startOffset);
        cstrm.next_in = (Bytef *)tmpBuff;
        cstrm.avail_out = numCElm * 2;
        cstrm.next_out = (Bytef *)cElems;

        inflateInit(&cstrm);
        inflate(&cstrm, Z_NO_FLUSH);
        inflateEnd(&cstrm);

        free(tmpBuff);
    }

    printf("Writing image file info into image.out\n");

    /* we write only first track with data ??? */
    FILE *outfile = fopen("image.out", "wb");

    fseek(mdf, startOffset, SEEK_SET);

    if (compressed)
    {
        u8 *ibuf = (u8 *)malloc(cBlockSz);
        u8 *dbuf = (u8 *)malloc(cBlockSz);

        printf("Decompressing");
        if (encryptInfo.mode != -1)
            printf(" and decrypt\n");
        else
            printf("\n");

        u64 outAddr = 0;
        u64 inAddr = startOffset;

        int progress = 0;

        for (u32 i = 0; i < numCElm; i++)
        {
            if ( i * 10 / numCElm > progress )
            {
                progress++;
                printf("%d%%\n", progress * 10);
            }

            u32 rdsize = 0;

            u16 elm = cElems[i];
            if (elm == 0) // decompile flags 0
            {
                /* uncompressed data */
                if ( i + 1 == numCElm )
                {
                    u32 rm = (secSize * unknum) % cBlockSz;
                    rdsize = cBlockSz;
                    if (rm)
                        rdsize = rm;
                }
                else
                {
                    rdsize = cBlockSz;
                }

                fread(ibuf, rdsize, 1, mdf);

                if (encryptInfo.mode != -1)
                {
                    decryptMdxData(&encryptInfo, ibuf, rdsize, cBlockSz, outAddr / cBlockSz);
                }

                fwrite(ibuf, rdsize, 1, outfile);
            }
            else
            {
                if (elm & 0x8000) // decompile flags 0x80
                {
                    memset(ibuf, elm & 0xff, cBlockSz);
                    fwrite(ibuf, cBlockSz, 1, outfile);
                }
                else // decompile flags 0x41
                {
                    u8 flags = 0x41;

                    rdsize = elm;
                    fread(ibuf, rdsize, 1, mdf);

                    if (encryptInfo.mode != -1)
                    {
                        decryptMdxData(&encryptInfo, ibuf, rdsize, cBlockSz, outAddr / cBlockSz);
                    }

                    z_stream cstrm;
                    cstrm.zalloc = Z_NULL;
                    cstrm.zfree = Z_NULL;
                    cstrm.opaque = Z_NULL;
                    cstrm.avail_in = rdsize;
                    cstrm.next_in = (Bytef *)ibuf;
                    cstrm.avail_out = cBlockSz;
                    cstrm.next_out = (Bytef *)dbuf;

                    if (flags & 0x40)
                        inflateInit2(&cstrm, -15);
                    else
                        inflateInit2(&cstrm, 15);

                    inflate(&cstrm, Z_NO_FLUSH);
                    inflateEnd(&cstrm);

                    if (cstrm.avail_in > 0)
                    {
                        printf("Err uncompress. Remain %d bytes\n", cstrm.avail_in);
                        return -1;
                    }

                    fwrite(dbuf, cBlockSz, 1, outfile);
                }
            }

            outAddr += cBlockSz;
            inAddr += rdsize;
        }

        free(ibuf);
        free(dbuf);
    }
    else if (encryptInfo.mode != -1)
    {
        printf("Decrypting\n");

        u8 *ibuf = (u8 *)malloc(secSize);

        u64 outAddr = 0;
        int progress = 0;
        for(u64 inAddr = startOffset; inAddr < mdfsize; inAddr += secSize)
        {
            if ( inAddr * 10 / mdfsize > progress )
            {
                progress++;
                printf("%d%%\n", progress * 10);
            }

            u32 sz = secSize;
            if (sz > mdfsize - inAddr)
                sz = mdfsize - inAddr;

            fread(ibuf, sz, 1, mdf);
            decryptMdxData(&encryptInfo, ibuf, sz, secSize, outAddr / secSize);
            fwrite(ibuf, sz, 1, outfile);

            outAddr += secSize;
        }

        free(ibuf);
    }
    else
    {
        printf("Something going wrong!\n");
    }

    fclose(mdf);
    fclose(outfile);

    return 0;
}

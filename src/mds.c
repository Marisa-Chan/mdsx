#include "mds.h"
#include <zlib.h>


const char *S_TRACK_TYPE[7] =
{
    "MAINTENANCE", //0
    "AUDIO", //1
    "MODE1", //2
    "MODE2", //3
    "MODE2_FORM1", //4
    "MODE2_FORM2", //5
    "" //6
};


typedef struct tTrackInfo
{
    struct tTrackInfo *next;
    int id;
    u8 track_type;
    u8 track_flags;
    u16 file_block_size;
    u64 start_offset;
    u64 length; // logic size in sectors
    u64 dataLength; // real data size in sectors
    u32 blocksCGroup; // number of blocks in one compression group
    u64 end_offset;
    u64 footer_offset;
    u8 footer_flags;
    u64 unk_num;
    u64 c_block;
    u16 *ctable;
    u32 c_num;
} TrackInfo;


void TrackDataDecrypt(Decoder *ctx, u8 *buffer, u32 length, u64 sectorSize, u64 blockIndex, u8 flags)
{
    const u32 blkSize = sectorSize & (~0xf);
    u64 blkIndex = blockIndex;
    if (flags & 1)
    {
        //unaligned less than sector
        s32 dataRemain = length;
        while (dataRemain > 0)
        {
            u32 dsz = blkSize;
            if (dsz > dataRemain)
                dsz = dataRemain;

            decryptMdxData(ctx, buffer, dsz, blkSize, blkIndex);
            buffer += dsz;
            blkIndex++;
            dataRemain -= dsz;
        }
    }
    else
    {
        //aligned by sector size. full sectors, but decrypt only aligned size
        s32 dataRemain = length;
        while (dataRemain > 0)
        {
            u32 dsz = blkSize;
            if (dsz > dataRemain)
                dsz = dataRemain;

            decryptMdxData(ctx, buffer, blkSize, blkSize, blkIndex);
            buffer += sectorSize;
            blkIndex++;
            dataRemain -= sectorSize;
        }
    }
}


int main(int argc, const char *argv[])
{
    int trackCount = 0;
    TrackInfo *processTracks = NULL;
    TrackInfo *lastAddTrack = NULL;

    int extractOnlyData = 0;

    const char *spath = NULL;
    const char *spass = NULL;

    int isMDX = 0;
    u64 mdxOffset = 0;
    u64 mdxSize1 = 0;

    for (int p = 1; p < argc; p++)
    {
        const char *stst = argv[p];
        if (*stst == '-')
        {
            if ( strchr(stst, 'd') != NULL )
                extractOnlyData = 1;
        }
        else
        {
            if (spath == NULL)
                spath = stst;
            else if (spass == NULL)
                spass = stst;
        }
    }

    if (!spath)
    {
        printf("Nothing to open\n");
        return 0;
    }


    FILE *mds = fopen(spath, "rb");

    if (!mds)
    {
        printf("Can't open %s\n", spath);
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
    u64 offset = freadU32(mds);

    if (offset == 0xffffffff)
    {
        isMDX = 1;
        mdxOffset = freadU64(mds);
        mdxSize1 = freadU64(mds);

        offset = mdxOffset + (mdxSize1 - 0x40);
    }

    fseek(mds, offset, SEEK_SET);

    u8 data1[0x200];

    fread(data1, 0x200, 1, mds);

    PCRYPTO_INFO ci;
    decode1(data1, NULL, &ci);

    u32 comSize = getU32(data1 + 0x150); //compressed size?
    u32 decSize = getU32(data1 + 0x154); //decompressed size?

    u64 data2Offset = 0x30;  // for MDSv2
    u64 data2Size = offset - 0x30; // for MDSv2

    if (isMDX)
    {
        data2Offset = mdxOffset;
        data2Size = mdxSize1 - 0x40;
    }

    fseek(mds, data2Offset, SEEK_SET);

    u8 *data2 = (u8 *)malloc(data2Size);
    fread(data2, 1, data2Size, mds);

    DecryptBlock(data2, data2Size, 0, 0, 4, ci);

    u8 *mdxHeader = (u8 *)malloc(decSize + 0x12);

    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    infstream.avail_in = data2Size;
    infstream.next_in = data2;
    infstream.avail_out = decSize;
    infstream.next_out = mdxHeader + 0x12;

    inflateInit(&infstream);

    inflate(&infstream, Z_NO_FLUSH);
    inflateEnd(&infstream);


    fseek(mds, 0, SEEK_SET);
    fread(mdxHeader, 1, 0x12, mds);


    u8 medium_type = getU8(mdxHeader + offsetof(MDX_Header, medium_type));
    int isCD = 0;

    if (medium_type < 3) // 0, 1, 2
        isCD = 1;

    Decoder encryptInfo;
    encryptInfo.mode = -1;
    encryptInfo.ctr = 1;

    u32 keyBlockOff = getU32(mdxHeader + offsetof(MDX_Header, encryption_block_offset));
    if (keyBlockOff)
    {
        printf("Encryption detected\n");

        const char *password = NULL;

        if (!spass)
            printf("Trying without password\n");
        else
            password = spass;



        PCRYPTO_INFO ci2;
        if ( decode1(mdxHeader + keyBlockOff, password, &ci2) == 0 )
            if (password)
                printf("Password \"%s\": OK\n", password);
            else
                printf("It's encrypted with NULL password. OK!\n");
        else
        {
            if (password)
                printf("Password \"%s\": WRONG\n", password);
            else
                printf("Please specify password. Seems it's necessery.\n");

            printf("But we save header_not_decrypted.out with encrypted key block\n");

            FILE *b = fopen("header_not_decrypted.out", "wb");
            fwrite(mdxHeader, 1, decSize + 0x12, b);
            fclose(b);

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

    u16 numSessions = getU16(mdxHeader + offsetof(MDX_Header, num_sessions));
    u32 sessOffset = getU32(mdxHeader + offsetof(MDX_Header, sessions_blocks_offset));
    for (u16 i = 0; i < numSessions; i++)
    {
        u32 sblkOff = sessOffset + i * sizeof(MDX_SessionBlock);
        u8 numAllBlocks = getU8(mdxHeader + sblkOff + offsetof(MDX_SessionBlock, num_all_blocks));
        u32 tracksOff = getU32(mdxHeader + sblkOff + offsetof(MDX_SessionBlock, tracks_blocks_offset));

        u64 sessionStart = (s64)getU64(mdxHeader + sblkOff + offsetof(MDX_SessionBlock, session_start));
        u64 sessionEnd = (s64)getU64(mdxHeader + sblkOff + offsetof(MDX_SessionBlock, session_end));

        for (u8 j = 0; j < numAllBlocks; j++)
        {
            u32 trkOff = tracksOff + j * sizeof(MDX_TrackBlock);

            u8 mode = getU8(mdxHeader + trkOff + offsetof(MDX_TrackBlock, mode));
            if ((mode & TRK_F_TYPE_MASK) != TRK_T_MAINTENANCE)
            {
                TrackInfo *trk = (TrackInfo *)malloc(sizeof(TrackInfo));

                trk->next = NULL;
                trk->track_type = mode & TRK_F_TYPE_MASK;
                trk->track_flags = mode;
                trk->id = trackCount;
                trk->c_num = 0;
                trk->ctable = NULL;
                trk->file_block_size = getU16(mdxHeader + trkOff + offsetof(MDX_TrackBlock, file_block_size));
                trk->start_offset = getU64(mdxHeader + trkOff + offsetof(MDX_TrackBlock, start_offset));
                trk->footer_offset = getU32(mdxHeader + trkOff + offsetof(MDX_TrackBlock, footer_offset));

                trk->footer_flags = getU8(mdxHeader + trk->footer_offset + offsetof(MDX_Footer, flags));

                u64 startSector = getU64(mdxHeader + trkOff + offsetof(MDX_TrackBlock, start_sector));


                if (isCD)
                {
                    u32 extra_offset = getU32(mdxHeader + trkOff + offsetof(MDX_TrackBlock, extra_offset));
                    u8 count = getU8(mdxHeader + trkOff + offsetof(MDX_TrackBlock, _unk1_));

                    trk->length = 0;

                    // start from 1 - skip pregap
                    for(u8 ei = 1; ei < count; ei++)
                        trk->length += getU32(mdxHeader + extra_offset + ei * 4);
                }
                else
                {
                    trk->length = getU64(mdxHeader + trkOff + offsetof(MDX_TrackBlock, track_size64));
                }

                if (lastAddTrack)
                    lastAddTrack->next = trk;

                if (!processTracks)
                    processTracks = trk;

                trackCount++;
                lastAddTrack = trk;
            }
        }
    }

    /*if (compressed == 0 && encryptInfo.mode == -1 && isMDX == 0)
    {
        printf("Not compressed and not encrypted. Nothing to do\n");
        return 0;
    }*/

    FILE *mdf = NULL;
    u64 mdfsize = 0;

    if (isMDX == 0)
    {
        fclose(mds);

        /* here must be footer filename, but we hardcode *.mdf*/
        char n_mdf[1024];
        strcpy(n_mdf, spath);
        n_mdf[ strlen(n_mdf) - 1 ] = 'f';

        printf("\nReading MDF file %s\n\n", n_mdf);

        mdf = fopen(n_mdf, "rb");
        fseek(mdf, 0, SEEK_END);
        mdfsize = ftell(mdf);
        fseek(mdf, 0, SEEK_SET);
    }
    else
    {
        mdf = mds;
        mdfsize = mdxOffset;
    }

    /* read compression tables for tracks */
    for (TrackInfo *trk = processTracks; trk; trk = trk->next)
    {
        trk->blocksCGroup = getU32(mdxHeader + trk->footer_offset + offsetof(MDX_Footer, blocks_in_compression_group));
        trk->dataLength = getU64(mdxHeader + trk->footer_offset + offsetof(MDX_Footer, track_data_length));

        if (trk->footer_flags & 1) // compressed track
        {
            u64 ctableoff = getU64(mdxHeader + trk->footer_offset + offsetof(MDX_Footer, compress_table_offset));

            trk->c_block = trk->blocksCGroup * trk->file_block_size;

            if (0) /* if mds major < 2*/
            {
                if ((trk->footer_flags & 2) == 0 && getU32(mdxHeader + trk->footer_offset + offsetof(MDX_Footer, _unk2_size_)) == 0)
                    trk->unk_num = ((trk->file_block_size - trk->start_offset) - 1 + ctableoff) / trk->file_block_size;
                else
                    trk->unk_num = getU32(mdxHeader + trk->footer_offset + offsetof(MDX_Footer, _unk2_size_));
            }
            else
            {
                trk->unk_num = trk->dataLength;
            }

            trk->c_num = ((trk->blocksCGroup - 1) + trk->dataLength) / trk->blocksCGroup;
            trk->ctable = (u16 *)calloc(trk->c_num, 2);

            u64 filectableoff = trk->start_offset + ctableoff;

            //This is how DT compute size to read
            u16 *tmpBuff = calloc(trk->c_num + 0x800, 2); // trk->c_num * 2 + 0x1000

            u64 creadsz = (trk->c_num + 0x800) * 2;
            if ( mdfsize - filectableoff < creadsz )
                creadsz = mdfsize - filectableoff;

            fseek(mdf, filectableoff, SEEK_SET);
            fread(tmpBuff, creadsz, 1, mdf);

            z_stream cstrm;
            cstrm.zalloc = Z_NULL;
            cstrm.zfree = Z_NULL;
            cstrm.opaque = Z_NULL;
            cstrm.avail_in = creadsz;
            cstrm.next_in = (Bytef *)tmpBuff;
            cstrm.avail_out = trk->c_num * 2;
            cstrm.next_out = (Bytef *)trk->ctable;

            inflateInit(&cstrm);
            inflate(&cstrm, Z_NO_FLUSH);
            inflateEnd(&cstrm);

            // FILE *cc = fopen("ctable", "wb");
            // fwrite(trk->ctable, trk->c_num * 2, 1, cc);
            // fclose(cc);

            free(tmpBuff);
        }
    }

    if (extractOnlyData == 1)
        printf("!! Writing only sector data, not full blocks\n");
    printf("Writing tracks:\n\n");

    for (TrackInfo *trk = processTracks; trk; trk = trk->next)
    {
        char ofbuf[1024];
        sprintf(ofbuf, "track%02d.out", trk->id);

        printf("%s  type: %s  block size: 0x%x\n", ofbuf, S_TRACK_TYPE[trk->track_type], trk->file_block_size);

        if (trk->footer_flags & 1) //compressed
            printf("\tcompressed\n");
        if (encryptInfo.mode != -1) //encrypted
            printf("\tencrypted\n");

        u32 secSize = 0x800;
        u32 dataOffset = 0;

        // This all needs to be checked with different mds/mdx
        // from imgengine.dll 0x180004450 with field_fc = 0xf8
        // inited by engine.dll 0x7ffead41cc70 -> imgengine(ordinal_6)
        // Is this only for CD?
        if (trk->track_type == TRK_T_AUDIO)
        {
            secSize = 0x930;
        }
        else if (trk->track_type == TRK_T_MODE1)
        {
            secSize = 0x800;

            //0xF8 flags enable mask
            if (trk->track_flags & TRK_F_SYNC)
                dataOffset += 0xc;
            if (trk->track_flags & TRK_F_HEADER)
                dataOffset += 4;

        }
        else if (trk->track_type == TRK_T_MODE2)
        {
            secSize = 0x920;

            //0xB0 flags enable mask
            if (trk->track_flags & TRK_F_SYNC)
                dataOffset += 0xc;
            if (trk->track_flags & TRK_F_HEADER)
                dataOffset += 4;
        }
        else if (trk->track_type == TRK_T_MODE2_FORM1)
        {
            secSize = 0x800;

            //0xF8 flags enable mask
            if (trk->track_flags & TRK_F_SYNC)
                dataOffset += 0xc;
            if (trk->track_flags & TRK_F_HEADER)
                dataOffset += 4;
            if (trk->track_flags & TRK_F_SUBHEADER)
                dataOffset += 8;
        }
        else if (trk->track_type == TRK_T_MODE2_FORM2)
        {
            secSize = 0x800;

            //0xF8 flags enable mask
            if (trk->track_flags & TRK_F_SYNC)
                dataOffset += 0xc;
            if (trk->track_flags & TRK_F_HEADER)
                dataOffset += 4;
            if (trk->track_flags & TRK_F_SUBHEADER)
                dataOffset += 8;
        }

        printf("\tdata offset 0x%x   sector data size 0x%x\n", dataOffset, secSize);

        int wrongSize = 0;

        if (secSize + dataOffset != trk->file_block_size)
        {
            printf("\n!!!!!!!!  offset + sector size != block size !!!!!!!\n");
            printf("     dump full sector size in any way\n");
            wrongSize = 1;
        }

        FILE *outfile = fopen(ofbuf, "wb");

        fseek(mdf, trk->start_offset, SEEK_SET);

        if (trk->footer_flags & 1) //compressed
        {
            u8 *ibuf = (u8 *)malloc(trk->c_block);
            u8 *dbuf = (u8 *)malloc(trk->c_block);

            u64 outTrackOffset = 0;
            u64 inAddr = trk->start_offset;

            int progress = 0;

            for (u32 i = 0; i < trk->c_num; i++)
            {
                if ( i * 10 / trk->c_num > progress )
                {
                    progress++;
                    printf("%d%%\n", progress * 10);
                }

                u32 rdsize = 0;

                u16 elm = trk->ctable[i];
                if (elm == 0)
                {
                    // decompile flags 0
                    /* uncompressed data */
                    if ( i + 1 == trk->c_num )
                    {
                        u32 rm = (trk->file_block_size * trk->unk_num) % trk->c_block;
                        rdsize = trk->c_block;
                        if (rm)
                            rdsize = rm;
                    }
                    else
                    {
                        rdsize = trk->c_block;
                    }

                    fread(ibuf, rdsize, 1, mdf);

                    if (encryptInfo.mode != -1)
                        TrackDataDecrypt(&encryptInfo, ibuf, rdsize, trk->file_block_size, outTrackOffset / trk->file_block_size, trk->footer_flags);

                    if (extractOnlyData == 1 && wrongSize == 0 && secSize != trk->file_block_size)
                    {
                        u32 vdata = rdsize;
                        const u8 *vdp = ibuf;
                        while(vdata != 0)
                        {
                            vdata -= dataOffset;
                            vdp += dataOffset;

                            u32 wsize = secSize;
                            if (wsize > vdata)
                                wsize = vdata;

                            fwrite(vdp, wsize, 1, outfile);

                            vdata -= secSize;
                            vdp += secSize;
                        }
                    }
                    else
                        fwrite(ibuf, rdsize, 1, outfile);
                }
                else
                {
                    if (elm & 0x8000)
                    {
                        // decompile flags 0x80
                        memset(ibuf, elm & 0xff, trk->c_block);

                        if (extractOnlyData == 1 && wrongSize == 0 && secSize != trk->file_block_size)
                        {
                            u32 vdata = trk->c_block;
                            const u8 *vdp = ibuf;
                            while(vdata != 0)
                            {
                                vdata -= dataOffset;
                                vdp += dataOffset;

                                u32 wsize = secSize;
                                if (wsize > vdata)
                                    wsize = vdata;

                                fwrite(vdp, wsize, 1, outfile);

                                vdata -= secSize;
                                vdp += secSize;
                            }
                        }
                        else
                            fwrite(ibuf, trk->c_block, 1, outfile);
                    }
                    else
                    {
                        // decompile flags 0x41
                        u8 flags = 0x41;

                        rdsize = elm;
                        fread(ibuf, rdsize, 1, mdf);

                        if (encryptInfo.mode != -1)
                            TrackDataDecrypt(&encryptInfo, ibuf, rdsize, trk->file_block_size, outTrackOffset / trk->file_block_size, trk->footer_flags);

                        z_stream cstrm;
                        cstrm.zalloc = Z_NULL;
                        cstrm.zfree = Z_NULL;
                        cstrm.opaque = Z_NULL;
                        cstrm.avail_in = rdsize;
                        cstrm.next_in = (Bytef *)ibuf;
                        cstrm.avail_out = trk->c_block;
                        cstrm.next_out = (Bytef *)dbuf;

                        if (flags & 0x40)
                            inflateInit2(&cstrm, -15);
                        else
                            inflateInit2(&cstrm, 15);

                        inflate(&cstrm, Z_NO_FLUSH);
                        inflateEnd(&cstrm);

                        if (cstrm.avail_in > 0)
                        {
                            printf("Err uncompress. Remain %d bytes on %d cblock (%04x) inaddr %x\n", cstrm.avail_in, i, elm, inAddr);
                            return -1;
                        }

                        if (extractOnlyData == 1 && wrongSize == 0 && secSize != trk->file_block_size)
                        {
                            u32 vdata = trk->c_block;
                            const u8 *vdp = dbuf;
                            while(vdata != 0)
                            {
                                vdata -= dataOffset;
                                vdp += dataOffset;

                                u32 wsize = secSize;
                                if (wsize > vdata)
                                    wsize = vdata;

                                fwrite(vdp, wsize, 1, outfile);

                                vdata -= secSize;
                                vdp += secSize;
                            }
                        }
                        else
                            fwrite(dbuf, trk->c_block, 1, outfile);
                    }
                }

                outTrackOffset += trk->c_block;
                inAddr += rdsize;
            }

            free(ibuf);
            free(dbuf);
        }
        else
        {
            u8 *ibuf = (u8 *)malloc(trk->file_block_size);

            u64 outTrackOffset = 0;
            int progress = 0;
            u64 bound = trk->start_offset + trk->dataLength * trk->file_block_size;

            for(u64 inAddr = trk->start_offset; inAddr < bound; inAddr += trk->file_block_size)
            {
                if ( inAddr * 10 / mdfsize > progress )
                {
                    progress++;
                    printf("%d%%\n", progress * 10);
                }

                u32 sz = trk->file_block_size;
                if (sz > bound - inAddr)
                    sz = bound - inAddr;

                fread(ibuf, sz, 1, mdf);
                if (encryptInfo.mode != -1)
                    TrackDataDecrypt(&encryptInfo, ibuf, sz, trk->file_block_size, outTrackOffset / trk->file_block_size, trk->footer_flags);

                if (extractOnlyData == 1 && wrongSize == 0 && secSize != trk->file_block_size)
                {
                    u32 vdata = sz;
                    const u8 *vdp = ibuf;
                    while(vdata != 0)
                    {
                        vdata -= dataOffset;
                        vdp += dataOffset;

                        u32 wsize = secSize;
                        if (wsize > vdata)
                            wsize = vdata;

                        fwrite(vdp, wsize, 1, outfile);

                        vdata -= secSize;
                        vdp += secSize;
                    }
                }
                else
                    fwrite(ibuf, sz, 1, outfile);

                outTrackOffset += trk->file_block_size;
            }

            free(ibuf);
        }

        fclose(outfile);
    }

    fclose(mdf);

    return 0;
}

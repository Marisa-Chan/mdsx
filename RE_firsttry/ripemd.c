#include "mds.h"
#include "cryptool.h"

#define RIPEMD160_A	0x67452301
#define RIPEMD160_B	0xEFCDAB89
#define RIPEMD160_C	0x98BADCFE
#define RIPEMD160_D	0x10325476
#define RIPEMD160_E	0xC3D2E1F0

#define F1(x,y,z)	 ((x)^(y)^(z))
#define F2(x,y,z)	(((x)&(y))|((~x)&z))
#define F3(x,y,z)	(((x)|(~y))^(z))
#define F4(x,y,z)	(((x)&(z))|((y)&(~(z))))
#define F5(x,y,z)	 ((x)^((y)|(~(z))))

#define GETX(X,w)  (getU32(X+(w*4)))

#define RIP1(a,b,c,d,e,w,s) { \
	a+=F1(b,c,d)+GETX(X,w); \
        a=ROTATE(a,s)+e; \
        c=ROTATE(c,10); }

#define RIP2(a,b,c,d,e,w,s,K) { \
	a+=F2(b,c,d)+GETX(X,w)+K; \
        a=ROTATE(a,s)+e; \
        c=ROTATE(c,10); }

#define RIP3(a,b,c,d,e,w,s,K) { \
	a+=F3(b,c,d)+GETX(X,w)+K; \
        a=ROTATE(a,s)+e; \
        c=ROTATE(c,10); }

#define RIP4(a,b,c,d,e,w,s,K) { \
	a+=F4(b,c,d)+GETX(X,w)+K; \
        a=ROTATE(a,s)+e; \
        c=ROTATE(c,10); }

#define RIP5(a,b,c,d,e,w,s,K) { \
	a+=F5(b,c,d)+GETX(X,w)+K; \
        a=ROTATE(a,s)+e; \
        c=ROTATE(c,10); }

#define KL1 0x5A827999
#define KL2 0x6ED9EBA1
#define KL3 0x8F1BBCDC
#define KL4 0xA953FD4E

#define KR0 0x50A28BE6
#define KR1 0x5C4DD124
#define KR2 0x6D703EF3
#define KR3 0x7A6D76E9

typedef struct
{
    u32 num;
    u64 N;
    u32 A;
    u32 B;
    u32 C;
    u32 D;
    u32 E;
    u8 data[0x40];
} RipemdCtx;


void ripemd160_block(RipemdCtx *ctx, u8 *X)
{
    u32 A = ctx->A;
    u32 B = ctx->B;
    u32 C = ctx->C;
    u32 D = ctx->D;
    u32 E = ctx->E;

    RIP1(A,B,C,D,E,0,11);
    RIP1(E,A,B,C,D,1,14);
	RIP1(D,E,A,B,C,2,15);
	RIP1(C,D,E,A,B,3,12);
	RIP1(B,C,D,E,A,4,5);
	RIP1(A,B,C,D,E,5,8);
	RIP1(E,A,B,C,D,6,7);
	RIP1(D,E,A,B,C,7,9);
	RIP1(C,D,E,A,B,8,11);
	RIP1(B,C,D,E,A,9,13);
	RIP1(A,B,C,D,E,10,14);
	RIP1(E,A,B,C,D,11,15);
	RIP1(D,E,A,B,C,12,6);
	RIP1(C,D,E,A,B,13,7);
	RIP1(B,C,D,E,A,14,9);
	RIP1(A,B,C,D,E,15,8);

    RIP2(E,A,B,C,D,7,7,KL1);
	RIP2(D,E,A,B,C,4,6,KL1);
	RIP2(C,D,E,A,B,13,8,KL1);
	RIP2(B,C,D,E,A,1,13,KL1);
	RIP2(A,B,C,D,E,10,11,KL1);
	RIP2(E,A,B,C,D,6,9,KL1);
	RIP2(D,E,A,B,C,15,7,KL1);
	RIP2(C,D,E,A,B,3,15,KL1);
	RIP2(B,C,D,E,A,12,7,KL1);
	RIP2(A,B,C,D,E,0,12,KL1);
	RIP2(E,A,B,C,D,9,15,KL1);
	RIP2(D,E,A,B,C,5,9,KL1);
	RIP2(C,D,E,A,B,2,11,KL1);
	RIP2(B,C,D,E,A,14,7,KL1);
	RIP2(A,B,C,D,E,11,13,KL1);
	RIP2(E,A,B,C,D,8,12,KL1);

    RIP3(D,E,A,B,C,3,11,KL2);
	RIP3(C,D,E,A,B,10,13,KL2);
	RIP3(B,C,D,E,A,14,6,KL2);
	RIP3(A,B,C,D,E,4,7,KL2);
	RIP3(E,A,B,C,D,9,14,KL2);
	RIP3(D,E,A,B,C,15,9,KL2);
	RIP3(C,D,E,A,B,8,13,KL2);
	RIP3(B,C,D,E,A,1,15,KL2);
	RIP3(A,B,C,D,E,2,14,KL2);
	RIP3(E,A,B,C,D,7,8,KL2);
	RIP3(D,E,A,B,C,0,13,KL2);
	RIP3(C,D,E,A,B,6,6,KL2);
	RIP3(B,C,D,E,A,13,5,KL2);
	RIP3(A,B,C,D,E,11,12,KL2);
	RIP3(E,A,B,C,D,5,7,KL2);
	RIP3(D,E,A,B,C,12,5,KL2);

	RIP4(C,D,E,A,B,1,11,KL3);
	RIP4(B,C,D,E,A,9,12,KL3);
	RIP4(A,B,C,D,E,11,14,KL3);
	RIP4(E,A,B,C,D,10,15,KL3);
	RIP4(D,E,A,B,C,0,14,KL3);
	RIP4(C,D,E,A,B,8,15,KL3);
	RIP4(B,C,D,E,A,12,9,KL3);
	RIP4(A,B,C,D,E,4,8,KL3);
	RIP4(E,A,B,C,D,13,9,KL3);
	RIP4(D,E,A,B,C,3,14,KL3);
	RIP4(C,D,E,A,B,7,5,KL3);
	RIP4(B,C,D,E,A,15,6,KL3);
	RIP4(A,B,C,D,E,14,8,KL3);
	RIP4(E,A,B,C,D,5,6,KL3);
	RIP4(D,E,A,B,C,6,5,KL3);
	RIP4(C,D,E,A,B,2,12,KL3);

	RIP5(B,C,D,E,A,4,9,KL4);
	RIP5(A,B,C,D,E,0,15,KL4);
	RIP5(E,A,B,C,D,5,5,KL4);
	RIP5(D,E,A,B,C,9,11,KL4);
	RIP5(C,D,E,A,B,7,6,KL4);
	RIP5(B,C,D,E,A,12,8,KL4);
	RIP5(A,B,C,D,E,2,13,KL4);
	RIP5(E,A,B,C,D,10,12,KL4);
	RIP5(D,E,A,B,C,14,5,KL4);
	RIP5(C,D,E,A,B,1,12,KL4);
	RIP5(B,C,D,E,A,3,13,KL4);
	RIP5(A,B,C,D,E,8,14,KL4);
	RIP5(E,A,B,C,D,11,11,KL4);
	RIP5(D,E,A,B,C,6,8,KL4);
	RIP5(C,D,E,A,B,15,5,KL4);
	RIP5(B,C,D,E,A,13,6,KL4);

    u32 a = A;
    u32 b = B;
    u32 c = C;
    u32 d = D;
    u32 e = E;

    A=ctx->A;
    B=ctx->B;
    C=ctx->C;
    D=ctx->D;
    E=ctx->E;

    RIP5(A,B,C,D,E,5,8,KR0);
	RIP5(E,A,B,C,D,14,9,KR0);
	RIP5(D,E,A,B,C,7,9,KR0);
	RIP5(C,D,E,A,B,0,11,KR0);
	RIP5(B,C,D,E,A,9,13,KR0);
	RIP5(A,B,C,D,E,2,15,KR0);
	RIP5(E,A,B,C,D,11,15,KR0);
	RIP5(D,E,A,B,C,4,5,KR0);
	RIP5(C,D,E,A,B,13,7,KR0);
	RIP5(B,C,D,E,A,6,7,KR0);
	RIP5(A,B,C,D,E,15,8,KR0);
	RIP5(E,A,B,C,D,8,11,KR0);
	RIP5(D,E,A,B,C,1,14,KR0);
	RIP5(C,D,E,A,B,10,14,KR0);
	RIP5(B,C,D,E,A,3,12,KR0);
	RIP5(A,B,C,D,E,12,6,KR0);

	RIP4(E,A,B,C,D,6,9,KR1);
	RIP4(D,E,A,B,C,11,13,KR1);
	RIP4(C,D,E,A,B,3,15,KR1);
	RIP4(B,C,D,E,A,7,7,KR1);
	RIP4(A,B,C,D,E,0,12,KR1);
	RIP4(E,A,B,C,D,13,8,KR1);
	RIP4(D,E,A,B,C,5,9,KR1);
	RIP4(C,D,E,A,B,10,11,KR1);
	RIP4(B,C,D,E,A,14,7,KR1);
	RIP4(A,B,C,D,E,15,7,KR1);
	RIP4(E,A,B,C,D,8,12,KR1);
	RIP4(D,E,A,B,C,12,7,KR1);
	RIP4(C,D,E,A,B,4,6,KR1);
	RIP4(B,C,D,E,A,9,15,KR1);
	RIP4(A,B,C,D,E,1,13,KR1);
	RIP4(E,A,B,C,D,2,11,KR1);

	RIP3(D,E,A,B,C,15,9,KR2);
	RIP3(C,D,E,A,B,5,7,KR2);
	RIP3(B,C,D,E,A,1,15,KR2);
	RIP3(A,B,C,D,E,3,11,KR2);
	RIP3(E,A,B,C,D,7,8,KR2);
	RIP3(D,E,A,B,C,14,6,KR2);
	RIP3(C,D,E,A,B,6,6,KR2);
	RIP3(B,C,D,E,A,9,14,KR2);
	RIP3(A,B,C,D,E,11,12,KR2);
	RIP3(E,A,B,C,D,8,13,KR2);
	RIP3(D,E,A,B,C,12,5,KR2);
	RIP3(C,D,E,A,B,2,14,KR2);
	RIP3(B,C,D,E,A,10,13,KR2);
	RIP3(A,B,C,D,E,0,13,KR2);
	RIP3(E,A,B,C,D,4,7,KR2);
	RIP3(D,E,A,B,C,13,5,KR2);

	RIP2(C,D,E,A,B,8,15,KR3);
	RIP2(B,C,D,E,A,6,5,KR3);
	RIP2(A,B,C,D,E,4,8,KR3);
	RIP2(E,A,B,C,D,1,11,KR3);
	RIP2(D,E,A,B,C,3,14,KR3);
	RIP2(C,D,E,A,B,11,14,KR3);
	RIP2(B,C,D,E,A,15,6,KR3);
	RIP2(A,B,C,D,E,0,14,KR3);
	RIP2(E,A,B,C,D,5,6,KR3);
	RIP2(D,E,A,B,C,12,9,KR3);
	RIP2(C,D,E,A,B,2,12,KR3);
	RIP2(B,C,D,E,A,13,9,KR3);
	RIP2(A,B,C,D,E,9,12,KR3);
	RIP2(E,A,B,C,D,7,5,KR3);
	RIP2(D,E,A,B,C,10,15,KR3);
	RIP2(C,D,E,A,B,14,8,KR3);

	RIP1(B,C,D,E,A,12,8);
	RIP1(A,B,C,D,E,15,5);
	RIP1(E,A,B,C,D,10,12);
	RIP1(D,E,A,B,C,4,9);
	RIP1(C,D,E,A,B,1,12);
	RIP1(B,C,D,E,A,5,5);
	RIP1(A,B,C,D,E,8,14);
	RIP1(E,A,B,C,D,7,6);
	RIP1(D,E,A,B,C,6,8);
	RIP1(C,D,E,A,B,2,13);
	RIP1(B,C,D,E,A,13,6);
	RIP1(A,B,C,D,E,14,5);
	RIP1(E,A,B,C,D,0,15);
	RIP1(D,E,A,B,C,3,13);
	RIP1(C,D,E,A,B,9,11);
	RIP1(B,C,D,E,A,11,11);

	D     =ctx->B+c+D;
	ctx->B=ctx->C+d+E;
	ctx->C=ctx->D+e+A;
	ctx->D=ctx->E+a+B;
	ctx->E=ctx->A+b+C;
	ctx->A=D;
}

void ripemd160Update(RipemdCtx *ctx, u8 *data, u32 len)
{
    u64 nbytes = ctx->N / 8;
    ctx->N += len * 8;

    u32 step = nbytes & 0x3f;
    u32 pos = 0;
    u32 nextPos = 0x40 - step;
    if (nextPos <= len)
    {
        if (step)
        {
            memcpy(ctx->data + step, data, nextPos);
            ripemd160_block(ctx, ctx->data);
            step = 0;
            pos = nextPos;
        }

        nextPos = pos + 0x40;

        while (nextPos <= len)
        {
            ripemd160_block(ctx, data + pos);
            pos += 0x40;
            nextPos = pos + 0x40;
        }
    }
    if (pos < len)
        memcpy(ctx->data + step, data + pos, len - pos);
}

void ripemd160Init(RipemdCtx *ctx)
{
    ctx->N = 0;
    ctx->A = RIPEMD160_A;
    ctx->B = RIPEMD160_B;
    ctx->C = RIPEMD160_C;
    ctx->D = RIPEMD160_D;
    ctx->E = RIPEMD160_E;
    memset(ctx->data, 0, sizeof(ctx->data));
}

void ripemd160Final(u8 *out, RipemdCtx *ctx)
{
    u8 nbuf[8];
    setU32(nbuf, ctx->N);

    u32 step = (ctx->N / 8) & 0x3f;
    u32 rmn = 0x40 - step;
    if (rmn <= 8)
        rmn += 0x40;

    u8 end[0x40];
    memset(end, 0, 0x40);
    end[0] = 0x80;

    ripemd160Update(ctx, end, rmn - 8);
    ripemd160Update(ctx, nbuf, 8);

    setU32(out, ctx->A);
    setU32(out + 4, ctx->B);
    setU32(out + 8, ctx->C);
    setU32(out + 12, ctx->D);
    setU32(out + 16, ctx->E);

    memset(ctx, 0, sizeof(RipemdCtx));
}




void ripemd2(u8 *pkey, u32 keysz, u8 *pdata, u32 datasz, u8 *out)
{
    u8 genkey[20];
    RipemdCtx ctx;

    if (keysz > 0x40)
    {
        ripemd160Init(&ctx);
        ripemd160Update(&ctx, pkey, keysz);
        ripemd160Final(genkey, &ctx);
        pkey = genkey;
        keysz = 20;
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

    ripemd160Init(&ctx);
    ripemd160Update(&ctx, buf1, 0x40);
    ripemd160Update(&ctx, pdata, datasz);
    ripemd160Final(out, &ctx);
    ripemd160Init(&ctx);
    ripemd160Update(&ctx, buf2, 0x40);
    ripemd160Update(&ctx, out, 20);
    ripemd160Final(out, &ctx);
}

void ripemd1(u8 *pkey, u32 keysz, u8 *pdata, u32 datasz, u32 iter, u8 *out, u32 N)
{
    u8 dgt1[20];
    u8 dgt2[20];
    u8 buf[128 + 4];
    memcpy(buf, pdata, datasz);
    setU32(buf + datasz, N << 24);
    ripemd2(pkey, keysz, buf, datasz + 4, dgt1);
    memcpy(out, dgt1, 20);

    if (iter > 1)
    {
        iter--;
        while(iter > 0)
        {
            ripemd2(pkey, keysz, dgt1, 20, dgt2);
            for (int i = 0; i < 20; i++)
            {
                out[i] ^= dgt2[i];
                dgt1[i] = dgt2[i];
            }
            iter--;
        }
    }
}

void makeKeyRipemd(u8 *pkey, u32 keysz, u8 *pdata, u32 datasz, u32 iter, u8 *out, u32 outsz)
{
    u32 outpos = 0;
    u32 blockN = 1;
    u32 cnt = outsz / 20;
    if ((outsz % 20) != 0)
        cnt++;

    if (cnt > 1)
    {
        while(cnt > 1)
        {
            ripemd1(pkey, keysz, pdata, datasz, iter, out + outpos, blockN);
            outpos += 20;
            blockN++;
            cnt--;
        }
    }

    u8 buf[20];
    ripemd1(pkey, keysz, pdata, datasz, iter, buf, blockN);
    memcpy(out + outpos, buf, outsz - outpos);
}

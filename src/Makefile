CC=gcc

OBJS =  mds.c\
		edc.c\
		utils.c\
		decode.c\
		common/crc.c\
		common/crypto.c\
		common/endian.c\
		common/gfmul.c\
		common/xts.c\
		common/pkcs5.c\
		common/random.c\
		crypto/aeskey.c\
		crypto/aestab.c\
		crypto/aescrypt.c\
		crypto/bf_ecb.c\
		crypto/bf_enc.c\
		crypto/bf_skey.c\
		crypto/des.c\
		crypto/des_enc.c\
		crypto/ecb3_enc.c\
		crypto/set_key.c\
		crypto/serpent.c\
		crypto/twofish.c\
		crypto/c_ecb.c\
		crypto/c_enc.c\
		crypto/c_skey.c\
		crypto/rmd160.c\
		crypto/sha1.c\
		crypto/sha2.c\
		crypto/whirlpool.c


build:
	$(CC) $(OBJS) -I. -g -O0 -lz -o mds

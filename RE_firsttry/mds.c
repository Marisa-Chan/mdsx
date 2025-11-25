#include "mds.h"


int main(int argc, const char *argv[]) {

    FILE *mds = fopen(argv[1], "rb");

    fseek(mds, 0x10, SEEK_SET);
    int version = fgetc(mds);

    if (version < 2)
    {
        printf("It's not mdsv2\n");
        return 0;
    }

    fseek(mds, 0x2c, SEEK_SET);
    u32 offset = freadU32(mds);

    fseek(mds, offset, SEEK_SET);

    printf("Data1 offset %x\n Reading 0x200 data block\n", offset);

    u8 data1[0x200];

    fread(data1, 0x200, 1, mds);

    decode1(data1);

    return 0;
}

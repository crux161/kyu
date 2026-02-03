#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qq.h"

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s -c|-d <in> <out>\n", argv[0]);
        return 1;
    }

    FILE *f_in = fopen(argv[2], "rb");
    if (!f_in) return 1;
    fseek(f_in, 0, SEEK_END);
    size_t in_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    uint8_t *in_buf = malloc(in_size);
    fread(in_buf, 1, in_size, f_in);
    fclose(f_in);

    size_t out_size = 0;
    uint8_t *out_buf = NULL;

    if (strcmp(argv[1], "-c") == 0) {
        out_buf = qq_compress_buf(in_buf, in_size, &out_size);
    } else if (strcmp(argv[1], "-d") == 0) {
        out_buf = qq_decompress_buf(in_buf, in_size, &out_size);
    }

    if (out_buf) {
        FILE *f_out = fopen(argv[3], "wb");
        fwrite(out_buf, 1, out_size, f_out);
        fclose(f_out);
        free(out_buf);
    } else {
        fprintf(stderr, "Operation failed (Check file integrity/RAM).\n");
    }

    free(in_buf);
    return 0;
}

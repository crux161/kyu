/* gen_seed.c */
#include <stdio.h>
#include <string.h>
#include "kyu.h"
#include "core.c" /* Hack: include core directly to link easily without makefile surgery */

int main() {
    kyu_stream strm;
    kyu_compress_init(&strm, 1); // Level 1

    const char *input = "Hello World! Hello World! Hello World!";
    uint8_t out[1024];
    size_t in_len = strlen(input);
    size_t out_len = sizeof(out);

    kyu_compress_update(&strm, (uint8_t*)input, in_len, out, &out_len);
    
    FILE *f = fopen("seed.bin", "wb");
    fwrite(out, 1, out_len, f);
    fclose(f);
    printf("Generated seed.bin (%zu bytes)\n", out_len);
    return 0;
}

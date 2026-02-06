/**
 * @file fuzzer.c
 * @brief Kyu Decompression Fuzzer (AFL++ Persistent Mode)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "kyu.h"

/* Output buffer (reused to prevent allocations) */
#define FUZZ_OUT_CAP 262144
static uint8_t OUT_BUF[FUZZ_OUT_CAP];

/* The actual fuzz target */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    kyu_stream strm;
    /* Clear stream state (critical in persistent mode!) */
    memset(&strm, 0, sizeof(kyu_stream));

    if (kyu_decompress_init(&strm) != KYU_SUCCESS) return 0;

    size_t in_len = size;
    size_t out_len = FUZZ_OUT_CAP;
    
    /* We ignore the return value because we *want* to find crashes/hangs, 
       not just successful decompressions. */
    kyu_decompress_update(&strm, data, &in_len, OUT_BUF, &out_len);

    /* Clean up is a no-op currently, but good practice */
    kyu_decompress_free(&strm);
    return 0;
}

/* AFL++ Persistent Mode Loop */
int main(int argc, char **argv) {
    (void)argc; (void)argv;

    /* Buffer for the input data */
    unsigned char buf[1024 * 64]; 
    ssize_t len;

    /* This magic loop tells AFL "Don't kill me, just send new data!" */
    while (__AFL_LOOP(10000)) {
        /* Read from stdin (which AFL feeds) */
        len = read(0, buf, sizeof(buf));
        if (len > 0) {
            LLVMFuzzerTestOneInput(buf, (size_t)len);
        }
    }
    
    /* Standard exit for the last run */
    return 0;
}

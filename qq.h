#ifndef QQ_H
#define QQ_H

#include <stdint.h>
#include <stddef.h>

#define QQ_SUCCESS          0
#define QQ_ERR_MEMORY       -1
#define QQ_ERR_INVALID_FILE -2
#define QQ_ERR_CRC_MISMATCH -3

uint8_t* qq_compress_buf(const uint8_t *input, size_t input_len, size_t *output_len);
uint8_t* qq_decompress_buf(const uint8_t *input, size_t input_len, size_t *output_len);

#endif

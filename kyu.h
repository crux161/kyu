#ifndef KYU_H
#define KYU_H

#include <stdint.h>
#include <stddef.h>

#define KYU_SUCCESS           0
#define KYU_ERR_MEMORY       -1
#define KYU_ERR_INVALID_HDR  -2
#define KYU_ERR_CRC_MISMATCH -3
#define KYU_ERR_BUF_SMALL    -4
#define KYU_ERR_DATA_CORRUPT -5

#define KYU_WINDOW_SIZE      32768
#define KYU_WINDOW_MASK      32767
#define KYU_MAX_TOKENS       16384
#define KYU_MAX_SYMBOLS      259 
#define KYU_SYM_MATCH        256
#define KYU_SYM_EOF          257
#define KYU_SYM_BLK_END      258

typedef struct { 
    uint16_t type, dist, len; 
} Token;

typedef struct {
    uint8_t  window[KYU_WINDOW_SIZE];
    int32_t  head[65536];
    int32_t  prev[KYU_WINDOW_SIZE];
    
    uint32_t freqs[KYU_MAX_SYMBOLS];
    Token    tokens[KYU_MAX_TOKENS];
    int      token_count;
    
    size_t   window_pos;
    uint8_t  bit_buf;
    int      bit_count;

    int      state;
    int      phase;
    void* root;
    void* tree_curr;
    
    uint32_t partial_val;
    int      partial_bits;
    int32_t  match_dist;   
    
    size_t   bytes_needed;
    uint8_t  freq_buf[KYU_MAX_SYMBOLS * 4];
    size_t   freq_len;
} kyu_stream;

int kyu_compress_init(kyu_stream *strm);
int kyu_compress_update(kyu_stream *strm, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
int kyu_compress_end(kyu_stream *strm, uint8_t *out, size_t *out_len);

int kyu_decompress_init(kyu_stream *strm);
int kyu_decompress_update(kyu_stream *strm, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

#endif

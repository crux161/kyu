/**
 * @file core.c
 * @brief Kyu compression core (LZ77 + RLE Literals).
 */

#include "kyu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- Constants --- */
#define KYU_WINDOW_SIZE 32768
#define KYU_WINDOW_MASK 32767
#define KYU_MIN_MATCH 3
#define KYU_MAX_MATCH 258
#define KYU_HASH_BITS 15
#define KYU_HASH_SIZE (1 << KYU_HASH_BITS)
#define MAX_LIT_RUN 32 

/* --- Bitstream Helpers --- */

static void write_bits(kyu_stream *strm, uint32_t val, int count, uint8_t *out, size_t *out_pos, size_t out_cap) {
    strm->bit_buf |= ((uint64_t)val << strm->bit_count);
    strm->bit_count += count;

    while (strm->bit_count >= 8) {
        if (*out_pos < out_cap) {
            out[*out_pos] = (uint8_t)(strm->bit_buf & 0xFF);
            (*out_pos)++;
        }
        strm->bit_buf >>= 8;
        strm->bit_count -= 8;
    }
}

static void flush_bits(kyu_stream *strm, uint8_t *out, size_t *out_pos, size_t out_cap) {
    if (strm->bit_count > 0) {
        if (*out_pos < out_cap) {
            out[*out_pos] = (uint8_t)(strm->bit_buf & 0xFF);
            (*out_pos)++;
        }
        strm->bit_buf = 0;
        strm->bit_count = 0;
    }
}

static uint32_t peek_bits(kyu_stream *strm, int count) {
    return (uint32_t)(strm->bit_buf & ((1ULL << count) - 1));
}

static void drop_bits(kyu_stream *strm, int count) {
    strm->bit_buf >>= count;
    strm->bit_count -= count;
}

static int fill_bits(kyu_stream *strm, const uint8_t **in, size_t *in_len, int needed) {
    while (strm->bit_count < needed) {
        if (*in_len == 0) return 0;
        strm->bit_buf |= ((uint64_t)(**in)) << strm->bit_count;
        (*in)++;
        (*in_len)--;
        strm->bit_count += 8;
    }
    return 1;
}

/* --- Core Logic --- */

static inline uint32_t hash_func(const uint8_t *p) {
    uint32_t val = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
    return (val * 2654435761U) >> (32 - KYU_HASH_BITS);
}

static inline void update_hash(kyu_stream *strm, const uint8_t *data, size_t pos) {
    uint32_t h = hash_func(data);
    strm->prev[pos & KYU_WINDOW_MASK] = strm->head[h];
    strm->head[h] = (int32_t)pos;
}

static void flush_literals(kyu_stream *strm, uint8_t *out, size_t *out_pos, size_t out_cap) {
    if (strm->pending_len > 0) {
        write_bits(strm, 0, 1, out, out_pos, out_cap);
        write_bits(strm, strm->pending_len - 1, 5, out, out_pos, out_cap);
        for (uint32_t i = 0; i < strm->pending_len; i++) {
            write_bits(strm, strm->freq_buf[i], 8, out, out_pos, out_cap);
        }
        strm->pending_len = 0;
    }
}

/* --- API --- */

int kyu_compress_init(kyu_stream *strm) {
    if (!strm) return KYU_ERR_BAD_ARG;
    memset(strm, 0, sizeof(kyu_stream));
    memset(strm->head, -1, sizeof(strm->head));
    return KYU_SUCCESS;
}

int kyu_compress_update(kyu_stream *strm, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    size_t ip = 0;          
    size_t out_pos = 0;
    size_t out_cap = *out_len;

    while (ip < in_len) {
        strm->window[strm->window_pos & KYU_WINDOW_MASK] = in[ip];
        
        int match_len = 0;
        int match_dist = 0;
        
        if (ip + KYU_MIN_MATCH <= in_len) {
            uint32_t h = hash_func(in + ip);
            int32_t head = strm->head[h];
            
            int chain_len = 256; 
            int32_t cur_match = head;

            while (cur_match != -1 && chain_len-- > 0) {
                long dist = (long)strm->window_pos - cur_match;
                if (dist <= 0 || dist > KYU_WINDOW_SIZE) break;

                size_t w_idx = (size_t)cur_match & KYU_WINDOW_MASK;
                
                if (strm->window[w_idx] == in[ip] &&
                    strm->window[(w_idx + 1) & KYU_WINDOW_MASK] == in[ip+1] &&
                    strm->window[(w_idx + 2) & KYU_WINDOW_MASK] == in[ip+2]) 
                {
                    int len = 3;
                    /* Explicit cast to size_t to avoid signedness warning */
                    while (len < KYU_MAX_MATCH && (ip + (size_t)len < in_len)) {
                        if (strm->window[(w_idx + (size_t)len) & KYU_WINDOW_MASK] != in[ip + (size_t)len]) break;
                        len++;
                    }

                    if (len > match_len) {
                        match_len = len;
                        match_dist = (int)dist;
                        if (match_len >= 128) break; 
                    }
                }
                cur_match = strm->prev[cur_match & KYU_WINDOW_MASK];
            }
        }

        if (match_len >= 3) {
            flush_literals(strm, out, &out_pos, out_cap);
            write_bits(strm, 1, 1, out, &out_pos, out_cap);
            write_bits(strm, (uint32_t)(match_len - 3), 8, out, &out_pos, out_cap);
            write_bits(strm, (uint32_t)(match_dist - 1), 15, out, &out_pos, out_cap);

            update_hash(strm, in + ip, strm->window_pos);
            strm->window_pos++;
            ip++;

            for (int k = 1; k < match_len; k++) {
                if (ip >= in_len) break;
                strm->window[strm->window_pos & KYU_WINDOW_MASK] = in[ip];
                if (ip + 2 < in_len) update_hash(strm, in + ip, strm->window_pos);
                strm->window_pos++;
                ip++;
            }
        } else {
            strm->freq_buf[strm->pending_len++] = in[ip];
            if (strm->pending_len >= MAX_LIT_RUN) {
                flush_literals(strm, out, &out_pos, out_cap);
            }
            if (ip + 2 < in_len) update_hash(strm, in + ip, strm->window_pos);
            strm->window_pos++;
            ip++;
        }
    }
    
    *out_len = out_pos;
    return KYU_SUCCESS;
}

int kyu_compress_end(kyu_stream *strm, uint8_t *out, size_t *out_len) {
    size_t out_pos = 0;
    flush_literals(strm, out, &out_pos, *out_len); 
    flush_bits(strm, out, &out_pos, *out_len);
    *out_len = out_pos;
    return KYU_SUCCESS;
}

int kyu_decompress_init(kyu_stream *strm) {
    if (!strm) return KYU_ERR_BAD_ARG;
    memset(strm, 0, sizeof(kyu_stream));
    return KYU_SUCCESS;
}

int kyu_decompress_update(kyu_stream *strm, const uint8_t *in, size_t *in_len, uint8_t *out, size_t *out_len) {
    const uint8_t *cur = in;
    size_t rem = *in_len;
    size_t o_pos = 0;
    size_t o_cap = *out_len;
    int ret = KYU_SUCCESS;

    while (rem > 0 || strm->bit_count >= 1) {
        if (!fill_bits(strm, &cur, &rem, 24)) {
            if (strm->bit_count < 1) { ret = KYU_SUCCESS; break; }
        }

        uint32_t flag = peek_bits(strm, 1);
        
        if (flag == 0) {
            if (strm->bit_count < 6) { if(rem==0) break; continue; }
            drop_bits(strm, 1);
            
            uint32_t count = peek_bits(strm, 5) + 1;
            drop_bits(strm, 5);

            for (uint32_t i = 0; i < count; i++) {
                while (strm->bit_count < 8) {
                    if (rem == 0) { ret = KYU_SUCCESS; goto end_decompress; } 
                    strm->bit_buf |= ((uint64_t)(*cur)) << strm->bit_count;
                    cur++; rem--;
                    strm->bit_count += 8;
                }
                
                uint8_t lit = (uint8_t)peek_bits(strm, 8);
                drop_bits(strm, 8);
                
                if (o_pos >= o_cap) { ret = KYU_ERR_BUF_SMALL; goto end_decompress; }
                out[o_pos++] = lit;
                strm->window[strm->window_pos & KYU_WINDOW_MASK] = lit;
                strm->window_pos++;
            }
        } else {
            if (strm->bit_count < 24) { if(rem==0) break; continue; }
            drop_bits(strm, 1);
            
            uint32_t len_code = peek_bits(strm, 8);
            drop_bits(strm, 8);
            uint32_t dist_code = peek_bits(strm, 15);
            drop_bits(strm, 15);
            
            int match_len = (int)len_code + 3;
            int match_dist = (int)dist_code + 1;
            
            for (int k = 0; k < match_len; k++) {
                /* Explicit cast for signedness warning */
                size_t src_idx = (strm->window_pos - (size_t)match_dist) & KYU_WINDOW_MASK;
                uint8_t b = strm->window[src_idx];
                
                if (o_pos >= o_cap) { ret = KYU_ERR_BUF_SMALL; goto end_decompress; }
                out[o_pos++] = b;
                
                strm->window[strm->window_pos & KYU_WINDOW_MASK] = b;
                strm->window_pos++;
            }
        }
    }

end_decompress:
    *in_len = rem; 
    *out_len = o_pos;
    return ret;
}

void kyu_decompress_free(kyu_stream *strm) { (void)strm; }

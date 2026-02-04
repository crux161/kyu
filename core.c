#include "kyu.h"
#include <stdlib.h>
#include <string.h>

/* --- Internal Structures --- */

typedef struct Node { 
    int symbol; 
    uint32_t freq; 
    int seq; 
    struct Node *left, *right; 
} Node;

typedef struct { 
    Node **nodes; 
    int size; 
} MinHeap;


static int compare_nodes(Node *a, Node *b) {
    if (a->freq < b->freq) return -1;
    if (a->freq > b->freq) return 1;
    return (a->seq < b->seq) ? -1 : 1;
}

static void push_heap(MinHeap *h, Node *n) {
    int i = h->size++;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (compare_nodes(h->nodes[p], n) <= 0) break;
        h->nodes[i] = h->nodes[p]; i = p;
    }
    h->nodes[i] = n;
}

static Node* pop_heap(MinHeap *h) {
    Node *ret = h->nodes[0];
    Node *last = h->nodes[--h->size];
    int i = 0;
    while (i * 2 + 1 < h->size) {
        int child = i * 2 + 1;
        if (child + 1 < h->size && compare_nodes(h->nodes[child + 1], h->nodes[child]) < 0) {
            child++;
        }
        if (compare_nodes(last, h->nodes[child]) <= 0) break;
        h->nodes[i] = h->nodes[child]; i = child;
    }
    h->nodes[i] = last;
    return ret;
}

static Node* build_tree(uint32_t freqs[KYU_MAX_SYMBOLS]) {
    MinHeap h = { malloc(sizeof(Node*) * KYU_MAX_SYMBOLS * 2), 0 };
    if (!h.nodes) return NULL;
    
    int next_seq = KYU_MAX_SYMBOLS + 1; 

    for (int i = 0; i < KYU_MAX_SYMBOLS; i++) {
        if (freqs[i] > 0) {
            Node *n = calloc(1, sizeof(Node));
            n->symbol = i; n->freq = freqs[i];
            n->seq = i; 
            push_heap(&h, n);
        }
    }
    while (h.size > 1) {
        Node *a = pop_heap(&h), *b = pop_heap(&h);
        Node *p = calloc(1, sizeof(Node));
        p->symbol = -1; 
        p->freq = a->freq + b->freq;
        p->seq = next_seq++; 
        p->left = a; p->right = b;
        push_heap(&h, p);
    }
    Node *root = (h.size > 0) ? pop_heap(&h) : NULL;
    free(h.nodes);
    return root;
}

static void gen_codes(Node *r, uint32_t *c, int *l, uint32_t cur, int len) {
    if (!r) return;
    if (r->symbol != -1) { c[r->symbol] = cur; l[r->symbol] = len; return; }
    gen_codes(r->left, c, l, (cur << 1), len + 1);
    gen_codes(r->right, c, l, (cur << 1) | 1, len + 1);
}

static void free_tree(Node *n) { if(n) { free_tree(n->left); free_tree(n->right); free(n); } }

static void write_bits_buf(uint8_t **p_out, size_t *p_rem, uint8_t *bit_buf, int *bit_cnt, uint32_t val, int count) {
    val &= (1 << count) - 1; 
    while (count > 0) {
        int bits_free = 8 - *bit_cnt;
        int bits_to_write = (count < bits_free) ? count : bits_free;
        uint8_t chunk = (val >> (count - bits_to_write)); 
        *bit_buf |= (chunk << (bits_free - bits_to_write));
        *bit_cnt += bits_to_write;
        count -= bits_to_write;
        if (*bit_cnt == 8) {
            if (*p_rem > 0) { *(*p_out)++ = *bit_buf; (*p_rem)--; }
            *bit_buf = 0; *bit_cnt = 0;
        }
    }
}


static int kyu_flush_block(kyu_stream *strm, uint8_t *out, size_t *out_len, int is_eof) {
    size_t rem = *out_len;
    uint8_t *cur = out;
    
    if (!is_eof) {
        strm->freqs[KYU_SYM_BLK_END]++;
        strm->tokens[strm->token_count++] = (Token){ KYU_SYM_BLK_END, 0, 0 };
    }

    Node *root = build_tree(strm->freqs);
    if (!root) return KYU_ERR_MEMORY;
    
    uint32_t codes[KYU_MAX_SYMBOLS]; 
    int lens[KYU_MAX_SYMBOLS];
    memset(lens, 0, sizeof(lens));
    gen_codes(root, codes, lens, 0, 0);

    if (rem < sizeof(strm->freqs)) { free_tree(root); return KYU_ERR_BUF_SMALL; }
    memcpy(cur, strm->freqs, sizeof(strm->freqs));
    cur += sizeof(strm->freqs); rem -= sizeof(strm->freqs);

    for (int i = 0; i < strm->token_count; i++) {
        Token t = strm->tokens[i];
        if (rem < 8) { free_tree(root); return KYU_ERR_BUF_SMALL; }
        
        write_bits_buf(&cur, &rem, &strm->bit_buf, &strm->bit_count, codes[t.type], lens[t.type]);
        if (t.type == KYU_SYM_MATCH) {
            write_bits_buf(&cur, &rem, &strm->bit_buf, &strm->bit_count, t.dist, 15);
            write_bits_buf(&cur, &rem, &strm->bit_buf, &strm->bit_count, t.len, 4);
        }
    }

    if (strm->bit_count > 0) {
        if (rem < 1) { free_tree(root); return KYU_ERR_BUF_SMALL; }
        *cur++ = strm->bit_buf;
        rem--;
        strm->bit_buf = 0; strm->bit_count = 0;
    }

    strm->token_count = 0;
    memset(strm->freqs, 0, sizeof(strm->freqs));
    strm->freqs[KYU_SYM_EOF] = 1;
    strm->freqs[KYU_SYM_MATCH] = 1;
    strm->freqs[KYU_SYM_BLK_END] = 1;
    
    *out_len = (cur - out);
    free_tree(root);
    return KYU_SUCCESS;
}

int kyu_compress_init(kyu_stream *strm) {
    if (!strm) return KYU_ERR_MEMORY;
    memset(strm, 0, sizeof(kyu_stream));
    memset(strm->head, 0, sizeof(strm->head)); 
    strm->window_pos = 0;
    strm->freqs[KYU_SYM_EOF] = 1;
    strm->freqs[KYU_SYM_MATCH] = 1;
    strm->freqs[KYU_SYM_BLK_END] = 1;
    return KYU_SUCCESS;
}

int kyu_compress_update(kyu_stream *strm, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    size_t written_total = 0;
    size_t rem_out = *out_len;
    uint8_t *out_ptr = out;
    
    for (size_t i = 0; i < in_len; ) {
        if (strm->token_count >= KYU_MAX_TOKENS - 2) {
            size_t n = rem_out;
            int ret = kyu_flush_block(strm, out_ptr, &n, 0);
            if (ret != KYU_SUCCESS) return ret;
            out_ptr += n; rem_out -= n; written_total += n;
        }

        uint32_t w_idx = strm->window_pos & KYU_WINDOW_MASK;
        strm->window[w_idx] = in[i];
        
        int m_len = 0, m_dist = 0;
        
        if (strm->window_pos >= 3 && i + 2 < in_len) {
             uint16_t h_curr = ((in[i] << 10) ^ (in[i+1] << 5) ^ in[i+2]) & 0xFFFF;
             
             int32_t stored_val = strm->head[h_curr];
             strm->head[h_curr] = (int32_t)(strm->window_pos + 1);
             strm->prev[w_idx] = stored_val;
             
             if (stored_val != 0) {
                 int32_t dist = (int32_t)(strm->window_pos + 1) - stored_val;
                 if (dist > 0 && dist < KYU_WINDOW_SIZE) {
                     int len = 0;
                     size_t match_idx = (size_t)(stored_val - 1);
                     
                     while (i + len < in_len && len < 18) {
                         uint8_t ref_byte;
                         if (len < dist) {
                             ref_byte = strm->window[(match_idx + len) & KYU_WINDOW_MASK];
                         } else {
                             ref_byte = in[i + len - dist];
                         }
                         
                         if (ref_byte != in[i+len]) break;
                         len++;
                     }
                     
                     if (len >= 3) { m_len = len; m_dist = dist; }
                 }
             }
        }

        if (m_len >= 3) {
            strm->tokens[strm->token_count++] = (Token){ KYU_SYM_MATCH, (uint16_t)m_dist, (uint16_t)(m_len - 3) };
            strm->freqs[KYU_SYM_MATCH]++;
            for (int k = 1; k < m_len; k++) {
                strm->window_pos++;
                strm->window[strm->window_pos & KYU_WINDOW_MASK] = in[i+k];
            }
            strm->window_pos++; i += m_len;
        } else {
            strm->tokens[strm->token_count++] = (Token){ in[i], 0, 0 };
            strm->freqs[in[i]]++;
            strm->window_pos++; i++;
        }
    }
    *out_len = written_total;
    return KYU_SUCCESS;
}

int kyu_compress_end(kyu_stream *strm, uint8_t *out, size_t *out_len) {
    strm->tokens[strm->token_count++] = (Token){ KYU_SYM_EOF, 0, 0 };
    strm->freqs[KYU_SYM_EOF]++;
    size_t n = *out_len;
    int ret = kyu_flush_block(strm, out, &n, 1);
    if (ret != KYU_SUCCESS) return ret;
    *out_len = n;
    return KYU_SUCCESS;
}


enum { ST_READ_FREQ, ST_DECODE };
enum { PHASE_SYM, PHASE_DIST, PHASE_LEN };

int kyu_decompress_init(kyu_stream *strm) {
    if (!strm) return KYU_ERR_MEMORY;
    memset(strm, 0, sizeof(kyu_stream));
    strm->state = ST_READ_FREQ;
    strm->bytes_needed = sizeof(strm->freqs);
    strm->freq_len = 0;
    strm->root = NULL;
    return KYU_SUCCESS;
}

static int get_next_bit(kyu_stream *strm, const uint8_t **src, size_t *src_len) {
    if (strm->bit_count == 0) {
        if (*src_len == 0) return -1;
        strm->bit_buf = *(*src)++;
        (*src_len)--;
        strm->bit_count = 8;
    }
    int bit = (strm->bit_buf >> (strm->bit_count - 1)) & 1;
    strm->bit_count--;
    return bit;
}

int kyu_decompress_update(kyu_stream *strm, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    size_t written = 0;
    const uint8_t *src = in;
    size_t src_rem = in_len;
    
    while (1) {
        if (strm->state == ST_READ_FREQ) {
            size_t to_copy = strm->bytes_needed - strm->freq_len;
            if (to_copy > src_rem) to_copy = src_rem;
            
            memcpy(strm->freq_buf + strm->freq_len, src, to_copy);
            strm->freq_len += to_copy;
            src += to_copy; src_rem -= to_copy;
            
            if (strm->freq_len == strm->bytes_needed) {
                if (strm->root) free_tree((Node*)strm->root);
                memcpy(strm->freqs, strm->freq_buf, sizeof(strm->freqs));
                strm->root = build_tree(strm->freqs);
                if (!strm->root) return KYU_ERR_MEMORY;
                
                strm->state = ST_DECODE;
                strm->phase = PHASE_SYM;
                strm->tree_curr = strm->root;
            } else {
                break;
            }
        }
        
        if (strm->state == ST_DECODE) {
            while (1) {
                if (strm->phase == PHASE_SYM) {
                    if (!strm->root) return KYU_ERR_DATA_CORRUPT;
                    Node *curr = (Node*)strm->tree_curr;
                    
                    while (curr->symbol == -1) {
                        int bit = get_next_bit(strm, &src, &src_rem);
                        if (bit == -1) {
                            strm->tree_curr = curr; 
                            goto need_input;
                        }
                        curr = (bit == 0) ? curr->left : curr->right;
                        if (!curr) return KYU_ERR_DATA_CORRUPT;
                    }
                    
                    strm->tree_curr = strm->root; 
                    
                    if (curr->symbol == KYU_SYM_EOF) {
                        *out_len = written;
                        return KYU_SUCCESS;
                    }
                    else if (curr->symbol == KYU_SYM_BLK_END) {
                        strm->state = ST_READ_FREQ;
                        strm->freq_len = 0;
                        strm->bit_count = 0; 
                        break; 
                    }
                    else if (curr->symbol == KYU_SYM_MATCH) {
                        strm->phase = PHASE_DIST;
                        strm->partial_val = 0;
                        strm->partial_bits = 0;
                    }
                    else {
                        if (written >= *out_len) return KYU_ERR_BUF_SMALL;
                        uint8_t byte = (uint8_t)curr->symbol;
                        out[written++] = byte;
                        strm->window[strm->window_pos & KYU_WINDOW_MASK] = byte;
                        strm->window_pos++;
                    }
                }
                
                if (strm->phase == PHASE_DIST) {
                    while (strm->partial_bits < 15) {
                        int bit = get_next_bit(strm, &src, &src_rem);
                        if (bit == -1) goto need_input;
                        strm->partial_val = (strm->partial_val << 1) | bit;
                        strm->partial_bits++;
                    }
                    strm->match_dist = (int32_t)strm->partial_val; 
                    strm->phase = PHASE_LEN;
                    strm->partial_val = 0;
                    strm->partial_bits = 0;
                }
                
                if (strm->phase == PHASE_LEN) {
                    while (strm->partial_bits < 4) {
                        int bit = get_next_bit(strm, &src, &src_rem);
                        if (bit == -1) goto need_input;
                        strm->partial_val = (strm->partial_val << 1) | bit;
                        strm->partial_bits++;
                    }
                    
                    uint32_t dist = (uint32_t)strm->match_dist;
                    uint32_t len = strm->partial_val + 3;
                    
                    for (uint32_t k = 0; k < len; k++) {
                        if (written >= *out_len) return KYU_ERR_BUF_SMALL;
                        uint8_t byte = strm->window[(strm->window_pos + KYU_WINDOW_SIZE - dist) & KYU_WINDOW_MASK];
                        out[written++] = byte;
                        strm->window[strm->window_pos & KYU_WINDOW_MASK] = byte;
                        strm->window_pos++;
                    }
                    strm->phase = PHASE_SYM; 
                }
            }
            if (strm->state == ST_READ_FREQ) continue;
            break;
        }
    }

need_input:
    *out_len = written;
    return KYU_SUCCESS;
}

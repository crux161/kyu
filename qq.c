#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef __APPLE__
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

const char QQ_SIGNATURE[4] = {'Q', 'Q', 'X', '3'};
#define WINDOW_SIZE 32768
#define WINDOW_MASK 32767
#define MAX_SYMBOLS 258 
#define SYM_MATCH 256
#define SYM_EOF 257

typedef struct { 
    uint16_t type, dist, len; 
} Token;

typedef struct Node { 
    int symbol; 
    uint32_t freq; 
    struct Node *left, *right; 
} Node;

typedef struct { 
    Node **nodes; 
    int size; 
} MinHeap;


uint32_t crc32_for_byte(uint32_t r) {
    for(int j = 0; j < 8; ++j) r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
    return r ^ (uint32_t)0xFF000000L;
}

uint32_t compute_crc32(const uint8_t *data, size_t n_bytes) {
    uint32_t crc = 0;
    static uint32_t table[0x100];
    static int table_computed = 0;
    if (!table_computed) {
        for(size_t i = 0; i < 0x100; ++i) table[i] = crc32_for_byte(i);
        table_computed = 1;
    }
    for(size_t i = 0; i < n_bytes; ++i) crc = table[(uint8_t)crc ^ data[i]] ^ crc >> 8;
    return crc;
}

void push_heap(MinHeap *h, Node *n) {
    int i = h->size++;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (h->nodes[p]->freq <= n->freq) break;
        h->nodes[i] = h->nodes[p]; i = p;
    }
    h->nodes[i] = n;
}

Node* pop_heap(MinHeap *h) {
    Node *ret = h->nodes[0];
    Node *last = h->nodes[--h->size];
    int i = 0;
    while (i * 2 + 1 < h->size) {
        int child = i * 2 + 1;
        if (child + 1 < h->size && h->nodes[child + 1]->freq < h->nodes[child]->freq) child++;
        if (last->freq <= h->nodes[child]->freq) break;
        h->nodes[i] = h->nodes[child]; i = child;
    }
    h->nodes[i] = last;
    return ret;
}

Node* build_tree(uint32_t freqs[MAX_SYMBOLS]) {
    MinHeap h = { malloc(sizeof(Node*) * MAX_SYMBOLS * 2), 0 };
    for (int i = 0; i < MAX_SYMBOLS; i++) {
        if (freqs[i] > 0) {
            Node *n = calloc(1, sizeof(Node));
            n->symbol = i; n->freq = freqs[i];
            push_heap(&h, n);
        }
    }
    while (h.size > 1) {
        Node *a = pop_heap(&h), *b = pop_heap(&h);
        Node *p = calloc(1, sizeof(Node));
        p->symbol = -1; p->freq = a->freq + b->freq;
        p->left = a; p->right = b;
        push_heap(&h, p);
    }
    Node *root = (h.size > 0) ? pop_heap(&h) : NULL;
    free(h.nodes);
    return root;
}

void gen_codes(Node *r, uint32_t *c, int *l, uint32_t cur, int len) {
    if (!r) return;
    if (r->symbol != -1) { c[r->symbol] = cur; l[r->symbol] = len; return; }
    gen_codes(r->left, c, l, (cur << 1), len + 1);
    gen_codes(r->right, c, l, (cur << 1) | 1, len + 1);
}

void free_tree(Node *n) { if(n) { free_tree(n->left); free_tree(n->right); free(n); } }


typedef struct {
    uint8_t *data;
    size_t pos, capacity;
    uint8_t bit_buf;
    int bit_count;
} MemBitWriter;

void write_bits_mem(MemBitWriter *bw, uint32_t value, int count) {
    value &= (1 << count) - 1; 
    while (count > 0) {
        int bits_free = 8 - bw->bit_count;
        int bits_to_write = (count < bits_free) ? count : bits_free;
        uint8_t chunk = (value >> (count - bits_to_write)); 
        bw->bit_buf |= (chunk << (bits_free - bits_to_write));
        bw->bit_count += bits_to_write;
        count -= bits_to_write;
        if (bw->bit_count == 8) {
            bw->data[bw->pos++] = bw->bit_buf;
            bw->bit_buf = 0; bw->bit_count = 0;
        }
    }
}

typedef struct {
    const uint8_t *data;
    size_t pos, size;
    uint8_t bit_buf;
    int bit_count;
} MemBitReader;

uint32_t read_bits_mem(MemBitReader *br, int count) {
    uint32_t value = 0;
    while (count > 0) {
        if (br->bit_count == 0) {
            if (br->pos >= br->size) return 0;
            br->bit_buf = br->data[br->pos++];
            br->bit_count = 8;
        }
        int bits_available = br->bit_count;
        int bits_to_read = (count < bits_available) ? count : bits_available;
        uint8_t chunk = (br->bit_buf >> (bits_available - bits_to_read)) & ((1 << bits_to_read) - 1);
        value = (value << bits_to_read) | chunk;
        br->bit_count -= bits_to_read;
        count -= bits_to_read;
    }
    return value;
}


uint8_t* qq_compress_buf(const uint8_t *input, size_t length, size_t *out_len) {
    Token *tokens = malloc(length * sizeof(Token));
    uint32_t freqs[MAX_SYMBOLS] = {0};
    freqs[SYM_EOF] = 1;
    
    int head[65536]; memset(head, -1, sizeof(head));
    int prev[WINDOW_SIZE];
    size_t t_cnt = 0;

    for (size_t i = 0; i < length; ) {
        if (i >= length - 3) {
            tokens[t_cnt++] = (Token){ input[i], 0, 0 };
            freqs[input[i]]++; i++; continue;
        }
        uint32_t h = ((input[i] << 10) ^ (input[i+1] << 5) ^ input[i+2]) & 65535;
        int m_idx = head[h];
        prev[i & WINDOW_MASK] = head[h]; head[h] = (int)i;

        int m_len = 0;
        if (m_idx != -1 && (i - (size_t)m_idx) < WINDOW_SIZE) {
            while(i + m_len < length && input[m_idx + m_len] == input[i + m_len] && m_len < 18) m_len++;
        }
        
        if (m_len >= 3) {
            tokens[t_cnt++] = (Token){ SYM_MATCH, (uint16_t)(i - (size_t)m_idx), (uint16_t)(m_len - 3) };
            freqs[SYM_MATCH]++; i += m_len;
        } else {
            tokens[t_cnt++] = (Token){ input[i], 0, 0 };
            freqs[input[i]]++; i++;
        }
    }
    tokens[t_cnt++] = (Token){ SYM_EOF, 0, 0 };

    Node *root = build_tree(freqs);
    uint32_t codes[MAX_SYMBOLS]; int lens[MAX_SYMBOLS];
    gen_codes(root, codes, lens, 0, 0);

    size_t est_size = length + 2048; 
    uint8_t *out = malloc(est_size);
    memcpy(out, QQ_SIGNATURE, 4);
    uint32_t s32 = (uint32_t)length, c32 = compute_crc32(input, length);
    memcpy(out+4, &s32, 4); memcpy(out+8, &c32, 4);
    memcpy(out+12, freqs, sizeof(freqs));

    MemBitWriter bw = { out, 12 + sizeof(freqs), est_size, 0, 0 };
    for (size_t i = 0; i < t_cnt; i++) {
        Token t = tokens[i];
        write_bits_mem(&bw, codes[t.type], lens[t.type]);
        if (t.type == SYM_MATCH) {
            write_bits_mem(&bw, t.dist, 15);
            write_bits_mem(&bw, t.len, 4);
        }
    }
    if (bw.bit_count > 0) bw.data[bw.pos++] = bw.bit_buf;

    *out_len = bw.pos;
    free(tokens); free_tree(root);
    return out;
}

uint8_t* qq_decompress_buf(const uint8_t *input, size_t input_len, size_t *out_len) {
    if (memcmp(input, QQ_SIGNATURE, 4) != 0) return NULL;

    uint32_t expected_size, expected_crc;
    memcpy(&expected_size, input + 4, 4);
    memcpy(&expected_crc, input + 8, 4);

    uint32_t freqs[MAX_SYMBOLS];
    memcpy(freqs, input + 12, sizeof(freqs));

    Node *root = build_tree(freqs);
    if (!root) return NULL;

    uint8_t *out = malloc(expected_size);
    if (!out) { free_tree(root); return NULL; }

    MemBitReader br = { input, 12 + sizeof(freqs), input_len, 0, 0 };
    uint8_t window[WINDOW_SIZE];
    size_t window_head = 0, total_written = 0;

    while (total_written < expected_size) {
        Node *curr = root;
        while (curr->symbol == -1) {
            uint32_t bit = read_bits_mem(&br, 1);
            curr = (bit == 0) ? curr->left : curr->right;
            if (!curr) goto cleanup;
        }

        if (curr->symbol == SYM_EOF) break;

        if (curr->symbol == SYM_MATCH) {
            uint32_t dist = read_bits_mem(&br, 15);
            uint32_t len = read_bits_mem(&br, 4) + 3;
            for (uint32_t k = 0; k < len && total_written < expected_size; k++) {
                uint8_t byte = window[(window_head + WINDOW_SIZE - dist) & WINDOW_MASK];
                out[total_written++] = byte;
                window[window_head] = byte;
                window_head = (window_head + 1) & WINDOW_MASK;
            }
        } else {
            uint8_t byte = (uint8_t)curr->symbol;
            out[total_written++] = byte;
            window[window_head] = byte;
            window_head = (window_head + 1) & WINDOW_MASK;
        }
    }

    if (compute_crc32(out, total_written) != expected_crc) {
        free(out);
        out = NULL;
    } else {
        *out_len = total_written;
    }

cleanup:
    free_tree(root);
    return out;
}

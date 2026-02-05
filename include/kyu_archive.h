#ifndef KYU_ARCHIVE_H
#define KYU_ARCHIVE_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "kyu.h"

/* --- Protocol V2 Flags --- */
#define KYU_FLAG_COMPRESSED   (1 << 0)
#define KYU_FLAG_ACK          (1 << 1)
#define KYU_FLAG_KEY_ROTATION (1 << 2)
#define KYU_FLAG_FINAL        (1 << 3)

/* --- Libkyu Error Codes (Resolve Conflicts) --- */
#ifdef KYU_ERR_BAD_ARG
#undef KYU_ERR_BAD_ARG
#endif
#ifdef KYU_ERR_MEMORY
#undef KYU_ERR_MEMORY
#endif
#ifdef KYU_ERR_BUF_SMALL
#undef KYU_ERR_BUF_SMALL
#endif
#ifdef KYU_ERR_INVALID_HDR
#undef KYU_ERR_INVALID_HDR
#endif

#define KYU_SUCCESS            0
#define KYU_ERR_NONCE_REUSE   -101
#define KYU_ERR_WINDOW_FULL   -102
#define KYU_ERR_CRYPTO_FAIL   -103
#define KYU_ERR_SEQ_MISMATCH  -104
#define KYU_ERR_BAD_ARG       -105
#define KYU_ERR_MEMORY        -106
#define KYU_ERR_BUF_SMALL     -107
#define KYU_ERR_INVALID_HDR   -108
#define KYU_ERR_GENERIC       -1  

/* --- Sink Callback --- */
typedef int (*kyu_sink_fn)(void *user_data, const void *buf, size_t len);

/* --- Compatibility Types --- */

/* FIX: Complete struct definition for ustar.c */
typedef struct {
    int verbose;
    size_t count;
    uint64_t bytes_to_skip; /* Tracks data blocks to skip */
    size_t buf_pos;         /* Current position in the 512-byte buffer */
    char buffer[512];       /* Internal TAR block buffer */
} kyu_ustar_lister_ctx;

typedef struct {
    uint64_t total_size;
    uint64_t processed_size; 
} kyu_status;

typedef int (*kyu_write_fn)(void *ctx, const void *buf, size_t len);

typedef struct {
    uint32_t mode;
    uint64_t mtime;
    uint64_t size;
    char name[256];
} kyu_manifest;

typedef struct {
    uint8_t key[32];
    uint8_t nonce[24];
    uint64_t next_sequence_id;
} kyu_session;

typedef struct {
    kyu_stream strm;
    kyu_session session;
    kyu_sink_fn sink;
    void *user_data;
    int level;
    uint8_t *work_buffer;
} kyu_context;

/* Alias for legacy driver */
typedef kyu_context kyu_writer;

/* --- API --- */
int kyu_init(kyu_context *ctx, const uint8_t key[32], kyu_sink_fn sink, void *user_data, int level);
int kyu_push(kyu_context *ctx, const void *data, size_t len, uint32_t flags);
int kyu_pull(kyu_context *ctx, const void *packet, size_t packet_len);
void kyu_free(kyu_context *ctx);

/* --- Legacy Shims --- */
kyu_writer* kyu_writer_init(FILE *out_stream, const char *password, const void *params, int level);
int kyu_writer_update(kyu_writer *w, const void *data, size_t len);
int kyu_writer_finalize(kyu_writer *w, const kyu_manifest *tmpl);

int kyu_archive_compress_stream(FILE *in, FILE *out, const char *pass, 
                                const void *params, int level, 
                                const kyu_manifest *tmpl, kyu_manifest *out_man);

int kyu_archive_decompress_stream(FILE *in, kyu_write_fn write_cb, void *write_ctx,
                                  const char *pass, const void *params, 
                                  kyu_manifest *out_man, int *status);

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "kyu.h"
#include "monocypher.h"

#define CHUNK_SIZE 65536
#define MAC_SIZE 16
#define NONCE_SIZE 24
#define KEY_SIZE 32
#define SALT_SIZE 16

/* Simple structure to manage crypto state */
typedef struct {
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t salt[SALT_SIZE];
} kyu_crypto;

/* Helper: Increment Nonce to prevent reuse */
static void increment_nonce(uint8_t *nonce) {
    for (int i = 0; i < 8; i++) {
        nonce[i]++;
        if (nonce[i] != 0) break;
    }
}

/* Derive Key from Password using Argon2i (Monocypher 4 API) */
static void derive_key(const char *pass, uint8_t *salt, uint8_t *key) {
    if (!pass) {
        memset(key, 0, KEY_SIZE);
        printf("WARNING: No password provided. Using ZERO KEY (Debug Mode).\n");
        return;
    }
    
    /* Config: Argon2i, 1024 blocks (1MB), 3 iterations */
    crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_I,
        .nb_blocks = 1024,
        .nb_passes = 3,
        .nb_lanes = 1
    };
    
    crypto_argon2_inputs inputs = {
        .pass = (const uint8_t*)pass,
        .pass_size = (uint32_t)strlen(pass),
        .salt = salt,
        .salt_size = SALT_SIZE
    };
    
    crypto_argon2_extras extras = {0};
    
    void *work_area = malloc(config.nb_blocks * 1024);
    if (!work_area) {
        fprintf(stderr, "Crypto Memory Error\n");
        exit(1);
    }
    
    crypto_argon2(key, KEY_SIZE, work_area, config, inputs, extras);
    free(work_area);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Kyu Archiver (QQX5) - Usage: %s -c|-d <in> <out> [password]\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    FILE *f_in = fopen(argv[2], "rb");
    FILE *f_out = fopen(argv[3], "wb");
    const char *pass = (argc >= 5) ? argv[4] : NULL;

    if (!f_in || !f_out) return 1;

    kyu_stream *strm = calloc(1, sizeof(kyu_stream));
    kyu_crypto ctx = {0};
    
    uint8_t *io_buf = malloc(CHUNK_SIZE * 2 + 1024); 
    uint8_t *comp_buf = malloc(CHUNK_SIZE * 2);
    
    if (strcmp(mode, "-c") == 0) {
        /* --- ENCRYPTION PIPELINE --- */
        if (pass) {
            /* In prod: arc4random_buf(ctx.salt, SALT_SIZE); */
            memset(ctx.salt, 0x55, SALT_SIZE); 
        }
        derive_key(pass, ctx.salt, ctx.key);

        fwrite("KYU5", 1, 4, f_out);
        fwrite(ctx.salt, 1, SALT_SIZE, f_out);
        
        kyu_compress_init(strm);
        
        size_t n_read;
        while ((n_read = fread(io_buf, 1, CHUNK_SIZE, f_in)) > 0) {
            size_t n_comp = CHUNK_SIZE * 2;
            int ret = kyu_compress_update(strm, io_buf, n_read, comp_buf, &n_comp);
            if (ret != KYU_SUCCESS) { printf("Compression Fail %d\n", ret); return 1; }
            
            uint32_t chunk_len = (uint32_t)n_comp;
            fwrite(&chunk_len, 1, 4, f_out);
            
            uint8_t mac[MAC_SIZE];
            uint8_t *ciphertext = io_buf; /* Reuse buffer */
            
            /* Monocypher 4: crypto_aead_lock (XChaCha20-Poly1305) */
            /* Args: cipher, mac, key, nonce, ad, ad_len, plain, plain_len */
            crypto_aead_lock(ciphertext, mac, ctx.key, ctx.nonce, NULL, 0, comp_buf, n_comp);
            
            fwrite(mac, 1, MAC_SIZE, f_out);
            fwrite(ciphertext, 1, n_comp, f_out);
            
            increment_nonce(ctx.nonce);
        }
        
        size_t n_comp = CHUNK_SIZE * 2;
        kyu_compress_end(strm, comp_buf, &n_comp);
        if (n_comp > 0) {
            uint32_t chunk_len = (uint32_t)n_comp;
            fwrite(&chunk_len, 1, 4, f_out);
            
            uint8_t mac[MAC_SIZE];
            crypto_aead_lock(io_buf, mac, ctx.key, ctx.nonce, NULL, 0, comp_buf, n_comp);
            
            fwrite(mac, 1, MAC_SIZE, f_out);
            fwrite(io_buf, 1, n_comp, f_out);
        }
        
    } else if (strcmp(mode, "-d") == 0) {
        /* --- DECRYPTION PIPELINE --- */
        uint8_t sig[4];
        if (fread(sig, 1, 4, f_in) != 4 || memcmp(sig, "KYU5", 4)) {
            printf("Invalid Format.\n"); return KYU_ERR_INVALID_HDR;
        }
        
        if (fread(ctx.salt, 1, SALT_SIZE, f_in) != SALT_SIZE) return KYU_ERR_INVALID_HDR;
        derive_key(pass, ctx.salt, ctx.key);
        
        kyu_decompress_init(strm);
        
        while (1) {
            uint32_t chunk_len;
            if (fread(&chunk_len, 1, 4, f_in) != 4) break; 
            
            if (chunk_len > CHUNK_SIZE * 2) return KYU_ERR_DATA_CORRUPT;
            
            uint8_t mac[MAC_SIZE];
            if (fread(mac, 1, MAC_SIZE, f_in) != MAC_SIZE) return KYU_ERR_DATA_CORRUPT;
            
            size_t n_read = fread(io_buf, 1, chunk_len, f_in);
            if (n_read != chunk_len) return KYU_ERR_DATA_CORRUPT;
            
            /* Monocypher 4: crypto_aead_unlock */
            /* Args: plain, mac, key, nonce, ad, ad_len, cipher, cipher_len */
            if (crypto_aead_unlock(comp_buf, mac, ctx.key, ctx.nonce, NULL, 0, io_buf, chunk_len)) {
                printf("SECURITY ALERT: MAC Mismatch! Tampering detected.\n");
                return KYU_ERR_CRC_MISMATCH;
            }
            increment_nonce(ctx.nonce);
            
            size_t n_out = CHUNK_SIZE * 4;
            uint8_t *final_out = malloc(CHUNK_SIZE * 4); 
            int ret = kyu_decompress_update(strm, comp_buf, chunk_len, final_out, &n_out);
            
            if (ret != KYU_SUCCESS) { free(final_out); return ret; }
            if (n_out > 0) fwrite(final_out, 1, n_out, f_out);
            free(final_out);
        }
    }

    free(io_buf);
    free(comp_buf);
    free(strm);
    fclose(f_in);
    fclose(f_out);
    return 0;
}

#ifndef KECCAK_H
#define KECCAK_H

#include <stdint.h>
#include <stddef.h>

void keccak_f1600(uint64_t state[25]);

typedef struct {
    uint64_t state[25];
    size_t rate;        // in bytes
    size_t offset;      // current byte offset in the rate part
    uint8_t delimiter;  // domain separation suffix + delimiter bit
} keccak_ctx;

// Initialize Keccak context
void keccak_init(keccak_ctx *ctx, size_t rate, uint8_t delimiter);

// Absorb input data
void keccak_update(keccak_ctx *ctx, const uint8_t *input, size_t input_len);

// Squeeze output
void keccak_finalize(keccak_ctx *ctx, uint8_t *output, size_t output_len);

// SHA-3 convenience functions
void sha3_224(const uint8_t *data, size_t len, uint8_t output[28]);
void sha3_256(const uint8_t *data, size_t len, uint8_t output[32]);
void sha3_384(const uint8_t *data, size_t len, uint8_t output[48]);
void sha3_512(const uint8_t *data, size_t len, uint8_t output[64]);

#endif // KECCAK_H

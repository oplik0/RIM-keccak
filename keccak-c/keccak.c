#include "keccak.h"
#include <string.h>
#include <assert.h>

static const uint64_t RC_TABLE[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const uint32_t RHO[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14},
};

// Rotate left operation for 64-bit values
static inline uint64_t rotl64(uint64_t x, uint32_t n) {
    return (x << n) | (x >> (64 - n));
}

static void theta(uint64_t state[25]) {
    uint64_t c[5];
    uint64_t d[5];
    
    for (int x = 0; x < 5; x++) {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    
    for (int x = 0; x < 5; x++) {
        d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }
    
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            state[x + 5 * y] ^= d[x];
        }
    }
}

static void rho_pi(uint64_t state[25]) {
    int x = 1;
    int y = 0;
    uint64_t current = state[x + 5 * y];
    
    for (int i = 0; i < 24; i++) {
        uint32_t t = RHO[x][y];
        int next_x = y;
        int next_y = (2 * x + 3 * y) % 5;
        
        uint64_t temp = state[next_x + 5 * next_y];
        state[next_x + 5 * next_y] = rotl64(current, t);
        current = temp;
        
        x = next_x;
        y = next_y;
    }
}

static void chi(uint64_t state[25]) {
    for (int y = 0; y < 5; y++) {
        uint64_t row[5];
        for (int x = 0; x < 5; x++) {
            row[x] = state[x + 5 * y];
        }
        for (int x = 0; x < 5; x++) {
            state[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]);
        }
    }
}

static void iota(uint64_t state[25], int round) {
    state[0] ^= RC_TABLE[round];
}

static void keccak_round(uint64_t state[25], int round_index) {
    theta(state);
    rho_pi(state);
    chi(state);
    iota(state, round_index);
}

void keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < 24; round++) {
        keccak_round(state, round);
    }
}

void keccak_init(keccak_ctx *ctx, size_t rate, uint8_t delimiter) {
    assert(rate < 200 && "Rate must be less than state size (1600 bits = 200 bytes)");
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate = rate;
    ctx->offset = 0;
    ctx->delimiter = delimiter;
}

// Absorb input data
void keccak_update(keccak_ctx *ctx, const uint8_t *input, size_t input_len) {
    for (size_t i = 0; i < input_len; i++) {
        uint8_t byte = input[i];
        
        // XOR byte into state (little-endian)
        size_t lane_idx = ctx->offset / 8;
        size_t byte_idx = ctx->offset % 8;
        
        ctx->state[lane_idx] ^= (uint64_t)byte << (8 * byte_idx);
        ctx->offset++;
        
        if (ctx->offset == ctx->rate) {
            keccak_f1600(ctx->state);
            ctx->offset = 0;
        }
    }
}

// Squeeze output
void keccak_finalize(keccak_ctx *ctx, uint8_t *output, size_t output_len) {
    // Padding: pad10*1 with domain separation
    size_t lane_idx = ctx->offset / 8;
    size_t byte_idx = ctx->offset % 8;
    ctx->state[lane_idx] ^= (uint64_t)ctx->delimiter << (8 * byte_idx);
    
    size_t last_lane_idx = (ctx->rate - 1) / 8;
    size_t last_byte_idx = (ctx->rate - 1) % 8;
    ctx->state[last_lane_idx] ^= 0x80ULL << (8 * last_byte_idx);
    
    keccak_f1600(ctx->state);
    
    // Squeeze
    size_t output_offset = 0;
    while (output_offset < output_len) {
        size_t block_size = ctx->rate;
        if (block_size > output_len - output_offset) {
            block_size = output_len - output_offset;
        }
        
        for (size_t i = 0; i < block_size; i++) {
            size_t lane = i / 8;
            size_t byte = i % 8;
            output[output_offset++] = (uint8_t)(ctx->state[lane] >> (8 * byte));
        }
        
        if (output_offset < output_len) {
            keccak_f1600(ctx->state);
        }
    }
}

// SHA-3 convenience functions
void sha3_224(const uint8_t *data, size_t len, uint8_t output[28]) {
    keccak_ctx ctx;
    keccak_init(&ctx, 144, 0x01);
    keccak_update(&ctx, data, len);
    keccak_finalize(&ctx, output, 28);
}

void sha3_256(const uint8_t *data, size_t len, uint8_t output[32]) {
    keccak_ctx ctx;
    keccak_init(&ctx, 136, 0x01);
    keccak_update(&ctx, data, len);
    keccak_finalize(&ctx, output, 32);
}

void sha3_384(const uint8_t *data, size_t len, uint8_t output[48]) {
    keccak_ctx ctx;
    keccak_init(&ctx, 104, 0x01);
    keccak_update(&ctx, data, len);
    keccak_finalize(&ctx, output, 48);
}

void sha3_512(const uint8_t *data, size_t len, uint8_t output[64]) {
    keccak_ctx ctx;
    keccak_init(&ctx, 72, 0x01);
    keccak_update(&ctx, data, len);
    keccak_finalize(&ctx, output, 64);
}

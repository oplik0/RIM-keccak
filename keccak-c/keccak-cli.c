#include "keccak.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [ALGORITHM] [INPUT]\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Algorithms:\n");
    fprintf(stderr, "  224, sha3-224    SHA3-224 (28 bytes output)\n");
    fprintf(stderr, "  256, sha3-256    SHA3-256 (32 bytes output) [default]\n");
    fprintf(stderr, "  384, sha3-384    SHA3-384 (48 bytes output)\n");
    fprintf(stderr, "  512, sha3-512    SHA3-512 (64 bytes output)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Input:\n");
    fprintf(stderr, "  If INPUT is provided, hash that string\n");
    fprintf(stderr, "  If INPUT is '-' or omitted, read from stdin\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s 256 \"hello world\"\n", prog_name);
    fprintf(stderr, "  echo \"hello world\" | %s\n", prog_name);
    fprintf(stderr, "  %s 512 - < file.txt\n", prog_name);
}

typedef enum {
    SHA3_224_ALG,
    SHA3_256_ALG,
    SHA3_384_ALG,
    SHA3_512_ALG
} algorithm_t;

static bool parse_algorithm(const char *alg_str, algorithm_t *alg) {
    if (strcmp(alg_str, "224") == 0 || strcmp(alg_str, "sha3-224") == 0) {
        *alg = SHA3_224_ALG;
        return true;
    } else if (strcmp(alg_str, "256") == 0 || strcmp(alg_str, "sha3-256") == 0) {
        *alg = SHA3_256_ALG;
        return true;
    } else if (strcmp(alg_str, "384") == 0 || strcmp(alg_str, "sha3-384") == 0) {
        *alg = SHA3_384_ALG;
        return true;
    } else if (strcmp(alg_str, "512") == 0 || strcmp(alg_str, "sha3-512") == 0) {
        *alg = SHA3_512_ALG;
        return true;
    }
    return false;
}

static size_t get_output_size(algorithm_t alg) {
    switch (alg) {
        case SHA3_224_ALG: return 28;
        case SHA3_256_ALG: return 32;
        case SHA3_384_ALG: return 48;
        case SHA3_512_ALG: return 64;
    }
    return 0;
}

static void hash_data(algorithm_t alg, const uint8_t *data, size_t len, uint8_t *output) {
    switch (alg) {
        case SHA3_224_ALG:
            sha3_224(data, len, output);
            break;
        case SHA3_256_ALG:
            sha3_256(data, len, output);
            break;
        case SHA3_384_ALG:
            sha3_384(data, len, output);
            break;
        case SHA3_512_ALG:
            sha3_512(data, len, output);
            break;
    }
}

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static uint8_t* read_stdin(size_t *out_len) {
    size_t capacity = 4096;
    size_t length = 0;
    uint8_t *buffer = malloc(capacity);
    
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        return NULL;
    }
    
    while (1) {
        if (length + 1024 > capacity) {
            capacity *= 2;
            uint8_t *new_buffer = realloc(buffer, capacity);
            if (!new_buffer) {
                fprintf(stderr, "Error: Failed to reallocate memory\n");
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
        
        size_t bytes_read = fread(buffer + length, 1, 1024, stdin);
        length += bytes_read;
        
        if (bytes_read < 1024) {
            if (feof(stdin)) {
                break;
            }
            if (ferror(stdin)) {
                fprintf(stderr, "Error: Failed to read from stdin\n");
                free(buffer);
                return NULL;
            }
        }
    }
    
    *out_len = length;
    return buffer;
}

int main(int argc, char *argv[]) {
    algorithm_t alg = SHA3_256_ALG;  // default
    const char *input_str = NULL;
    bool use_stdin = true;
    
    // Parse arguments
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        
        // Try to parse first arg as algorithm
        algorithm_t parsed_alg;
        if (parse_algorithm(argv[1], &parsed_alg)) {
            alg = parsed_alg;
            
            if (argc > 2) {
                if (strcmp(argv[2], "-") != 0) {
                    input_str = argv[2];
                    use_stdin = false;
                }
            }
        } else {
            // First arg is not an algorithm, treat it as input
            input_str = argv[1];
            use_stdin = false;
        }
    }
    
    // Get input data
    uint8_t *data;
    size_t data_len;
    bool should_free = false;
    
    if (use_stdin) {
        data = read_stdin(&data_len);
        if (!data) {
            return 1;
        }
        should_free = true;
    } else {
        data = (uint8_t *)input_str;
        data_len = strlen(input_str);
    }
    
    // Hash the data
    size_t output_size = get_output_size(alg);
    uint8_t *output = malloc(output_size);
    if (!output) {
        fprintf(stderr, "Error: Failed to allocate memory for output\n");
        if (should_free) free(data);
        return 1;
    }
    
    hash_data(alg, data, data_len, output);
    
    // Print result
    print_hex(output, output_size);
    
    // Cleanup
    free(output);
    if (should_free) {
        free(data);
    }
    
    return 0;
}

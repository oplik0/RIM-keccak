#include "keccak.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Test SHA3-256 with empty input
static bool test_sha3_256_empty(void) {
    printf("Testing SHA3-256 (empty)... ");
    
    uint8_t output[32];
    sha3_256((const uint8_t *)"", 0, output);
    
    const uint8_t expected[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };
    
    if (memcmp(output, expected, 32) == 0) {
        printf("PASS\n");
        return true;
    } else {
        printf("FAIL\n");
        printf("Expected: ");
        print_hex(expected, 32);
        printf("Got:      ");
        print_hex(output, 32);
        return false;
    }
}

// Test SHA3-256 with "abc"
static bool test_sha3_256_abc(void) {
    printf("Testing SHA3-256 (\"abc\")... ");
    
    uint8_t output[32];
    sha3_256((const uint8_t *)"abc", 3, output);
    
    const uint8_t expected[32] = {
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
    };
    
    if (memcmp(output, expected, 32) == 0) {
        printf("PASS\n");
        return true;
    } else {
        printf("FAIL\n");
        printf("Expected: ");
        print_hex(expected, 32);
        printf("Got:      ");
        print_hex(output, 32);
        return false;
    }
}

// Test SHA3-224 with empty input
static bool test_sha3_224_empty(void) {
    printf("Testing SHA3-224 (empty)... ");
    
    uint8_t output[28];
    sha3_224((const uint8_t *)"", 0, output);
    
    const uint8_t expected[28] = {
        0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7,
        0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e, 0xb1, 0xab,
        0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f,
        0x5b, 0x5a, 0x6b, 0xc7
    };
    
    if (memcmp(output, expected, 28) == 0) {
        printf("PASS\n");
        return true;
    } else {
        printf("FAIL\n");
        printf("Expected: ");
        print_hex(expected, 28);
        printf("Got:      ");
        print_hex(output, 28);
        return false;
    }
}

// Test SHA3-384 with empty input
static bool test_sha3_384_empty(void) {
    printf("Testing SHA3-384 (empty)... ");
    
    uint8_t output[48];
    sha3_384((const uint8_t *)"", 0, output);
    
    const uint8_t expected[48] = {
        0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d,
        0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85,
        0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61,
        0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a,
        0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47,
        0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04
    };
    
    if (memcmp(output, expected, 48) == 0) {
        printf("PASS\n");
        return true;
    } else {
        printf("FAIL\n");
        printf("Expected: ");
        print_hex(expected, 48);
        printf("Got:      ");
        print_hex(output, 48);
        return false;
    }
}

// Test SHA3-512 with empty input
static bool test_sha3_512_empty(void) {
    printf("Testing SHA3-512 (empty)... ");
    
    uint8_t output[64];
    sha3_512((const uint8_t *)"", 0, output);
    
    const uint8_t expected[64] = {
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
        0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
        0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
        0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
        0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
        0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
        0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26
    };
    
    if (memcmp(output, expected, 64) == 0) {
        printf("PASS\n");
        return true;
    } else {
        printf("FAIL\n");
        printf("Expected: ");
        print_hex(expected, 64);
        printf("Got:      ");
        print_hex(output, 64);
        return false;
    }
}

int main(void) {
    printf("Running Keccak/SHA-3 tests...\n\n");
    
    int passed = 0;
    int total = 0;
    
    total++; if (test_sha3_256_empty()) passed++;
    total++; if (test_sha3_256_abc()) passed++;
    total++; if (test_sha3_224_empty()) passed++;
    total++; if (test_sha3_384_empty()) passed++;
    total++; if (test_sha3_512_empty()) passed++;
    
    printf("\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    
    return (passed == total) ? 0 : 1;
}

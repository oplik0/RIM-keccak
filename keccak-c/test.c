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

// Test SHA3-224 with "abc"
static bool test_sha3_224_abc(void) {
    printf("Testing SHA3-224 (\"abc\")... ");
    
    uint8_t output[28];
    sha3_224((const uint8_t *)"abc", 3, output);
    
    const uint8_t expected[28] = {
        0xe6, 0x42, 0x82, 0x4c, 0x3f, 0x8c, 0xf2, 0x4a,
        0xd0, 0x92, 0x34, 0xee, 0x7d, 0x3c, 0x76, 0x6f,
        0xc9, 0xa3, 0xa5, 0x16, 0x8d, 0x0c, 0x94, 0xad,
        0x73, 0xb4, 0x6f, 0xdf
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

// Test SHA3-224 with 448 bits of data
static bool test_sha3_224_448_bits(void) {
    printf("Testing SHA3-224 (448 bits)... ");
    
    const uint8_t input[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t output[28];
    sha3_224(input, sizeof(input) - 1, output);
    
    const uint8_t expected[28] = {
        0x8a, 0x24, 0x10, 0x8b, 0x15, 0x4a, 0xda, 0x21,
        0xc9, 0xfd, 0x55, 0x74, 0x49, 0x44, 0x79, 0xba,
        0x5c, 0x7e, 0x7a, 0xb7, 0x6e, 0xf2, 0x64, 0xea,
        0xd0, 0xfc, 0xce, 0x33
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

// Test SHA3-224 with 896 bits of data
static bool test_sha3_224_896_bits(void) {
    printf("Testing SHA3-224 (896 bits)... ");
    
    const uint8_t input[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t output[28];
    sha3_224(input, sizeof(input) - 1, output);
    
    const uint8_t expected[28] = {
        0x54, 0x3e, 0x68, 0x68, 0xe1, 0x66, 0x6c, 0x1a,
        0x64, 0x36, 0x30, 0xdf, 0x77, 0x36, 0x7a, 0xe5,
        0xa6, 0x2a, 0x85, 0x07, 0x0a, 0x51, 0xc1, 0x4c,
        0xbf, 0x66, 0x5c, 0xbc
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

// Test SHA3-256 with 448 bits of data
static bool test_sha3_256_448_bits(void) {
    printf("Testing SHA3-256 (448 bits)... ");
    
    const uint8_t input[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t output[32];
    sha3_256(input, sizeof(input) - 1, output);
    
    const uint8_t expected[32] = {
        0x41, 0xc0, 0xdb, 0xa2, 0xa9, 0xd6, 0x24, 0x08,
        0x49, 0x10, 0x03, 0x76, 0xa8, 0x23, 0x5e, 0x2c,
        0x82, 0xe1, 0xb9, 0x99, 0x8a, 0x99, 0x9e, 0x21,
        0xdb, 0x32, 0xdd, 0x97, 0x49, 0x6d, 0x33, 0x76
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

// Test SHA3-256 with 896 bits of data
static bool test_sha3_256_896_bits(void) {
    printf("Testing SHA3-256 (896 bits)... ");
    
    const uint8_t input[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t output[32];
    sha3_256(input, sizeof(input) - 1, output);
    
    const uint8_t expected[32] = {
        0x91, 0x6f, 0x60, 0x61, 0xfe, 0x87, 0x97, 0x41,
        0xca, 0x64, 0x69, 0xb4, 0x39, 0x71, 0xdf, 0xdb,
        0x28, 0xb1, 0xa3, 0x2d, 0xc3, 0x6c, 0xb3, 0x25,
        0x4e, 0x81, 0x2b, 0xe2, 0x7a, 0xad, 0x1d, 0x18
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

// Test SHA3-384 with "abc"
static bool test_sha3_384_abc(void) {
    printf("Testing SHA3-384 (\"abc\")... ");
    
    uint8_t output[48];
    sha3_384((const uint8_t *)"abc", 3, output);
    
    const uint8_t expected[48] = {
        0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9,
        0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d,
        0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25,
        0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2,
        0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5,
        0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25
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

// Test SHA3-384 with 448 bits of data
static bool test_sha3_384_448_bits(void) {
    printf("Testing SHA3-384 (448 bits)... ");
    
    const uint8_t input[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t output[48];
    sha3_384(input, sizeof(input) - 1, output);
    
    const uint8_t expected[48] = {
        0x99, 0x1c, 0x66, 0x57, 0x55, 0xeb, 0x3a, 0x4b,
        0x6b, 0xbd, 0xfb, 0x75, 0xc7, 0x8a, 0x49, 0x2e,
        0x8c, 0x56, 0xa2, 0x2c, 0x5c, 0x4d, 0x7e, 0x42,
        0x9b, 0xfd, 0xbc, 0x32, 0xb9, 0xd4, 0xad, 0x5a,
        0xa0, 0x4a, 0x1f, 0x07, 0x6e, 0x62, 0xfe, 0xa1,
        0x9e, 0xef, 0x51, 0xac, 0xd0, 0x65, 0x7c, 0x22
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

// Test SHA3-384 with 896 bits of data
static bool test_sha3_384_896_bits(void) {
    printf("Testing SHA3-384 (896 bits)... ");
    
    const uint8_t input[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t output[48];
    sha3_384(input, sizeof(input) - 1, output);
    
    const uint8_t expected[48] = {
        0x79, 0x40, 0x7d, 0x3b, 0x59, 0x16, 0xb5, 0x9c,
        0x3e, 0x30, 0xb0, 0x98, 0x22, 0x97, 0x47, 0x91,
        0xc3, 0x13, 0xfb, 0x9e, 0xcc, 0x84, 0x9e, 0x40,
        0x6f, 0x23, 0x59, 0x2d, 0x04, 0xf6, 0x25, 0xdc,
        0x8c, 0x70, 0x9b, 0x98, 0xb4, 0x3b, 0x38, 0x52,
        0xb3, 0x37, 0x21, 0x61, 0x79, 0xaa, 0x7f, 0xc7
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

// Test SHA3-512 with "abc"
static bool test_sha3_512_abc(void) {
    printf("Testing SHA3-512 (\"abc\")... ");
    
    uint8_t output[64];
    sha3_512((const uint8_t *)"abc", 3, output);
    
    const uint8_t expected[64] = {
        0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
        0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
        0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
        0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
        0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
        0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
        0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
        0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
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

// Test SHA3-512 with 448 bits of data
static bool test_sha3_512_448_bits(void) {
    printf("Testing SHA3-512 (448 bits)... ");
    
    const uint8_t input[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t output[64];
    sha3_512(input, sizeof(input) - 1, output);
    
    const uint8_t expected[64] = {
        0x04, 0xa3, 0x71, 0xe8, 0x4e, 0xcf, 0xb5, 0xb8,
        0xb7, 0x7c, 0xb4, 0x86, 0x10, 0xfc, 0xa8, 0x18,
        0x2d, 0xd4, 0x57, 0xce, 0x6f, 0x32, 0x6a, 0x0f,
        0xd3, 0xd7, 0xec, 0x2f, 0x1e, 0x91, 0x63, 0x6d,
        0xee, 0x69, 0x1f, 0xbe, 0x0c, 0x98, 0x53, 0x02,
        0xba, 0x1b, 0x0d, 0x8d, 0xc7, 0x8c, 0x08, 0x63,
        0x46, 0xb5, 0x33, 0xb4, 0x9c, 0x03, 0x0d, 0x99,
        0xa2, 0x7d, 0xaf, 0x11, 0x39, 0xd6, 0xe7, 0x5e
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

// Test SHA3-512 with 896 bits of data
static bool test_sha3_512_896_bits(void) {
    printf("Testing SHA3-512 (896 bits)... ");
    
    const uint8_t input[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t output[64];
    sha3_512(input, sizeof(input) - 1, output);
    
    const uint8_t expected[64] = {
        0xaf, 0xeb, 0xb2, 0xef, 0x54, 0x2e, 0x65, 0x79,
        0xc5, 0x0c, 0xad, 0x06, 0xd2, 0xe5, 0x78, 0xf9,
        0xf8, 0xdd, 0x68, 0x81, 0xd7, 0xdc, 0x82, 0x4d,
        0x26, 0x36, 0x0f, 0xee, 0xbf, 0x18, 0xa4, 0xfa,
        0x73, 0xe3, 0x26, 0x11, 0x22, 0x94, 0x8e, 0xfc,
        0xfd, 0x49, 0x2e, 0x74, 0xe8, 0x2e, 0x21, 0x89,
        0xed, 0x0f, 0xb4, 0x40, 0xd1, 0x87, 0xf3, 0x82,
        0x27, 0x0c, 0xb4, 0x55, 0xf2, 0x1d, 0xd1, 0x85
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
    total++; if (test_sha3_224_abc()) passed++;
    total++; if (test_sha3_224_448_bits()) passed++;
    total++; if (test_sha3_224_896_bits()) passed++;
    total++; if (test_sha3_256_448_bits()) passed++;
    total++; if (test_sha3_256_896_bits()) passed++;
    total++; if (test_sha3_384_abc()) passed++;
    total++; if (test_sha3_384_448_bits()) passed++;
    total++; if (test_sha3_384_896_bits()) passed++;
    total++; if (test_sha3_512_abc()) passed++;
    total++; if (test_sha3_512_448_bits()) passed++;
    total++; if (test_sha3_512_896_bits()) passed++;
    
    printf("\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    
    return (passed == total) ? 0 : 1;
}

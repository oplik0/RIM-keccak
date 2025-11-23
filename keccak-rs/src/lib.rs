pub mod round_constants;
mod keccak_f1600;

pub use round_constants::{RoundConstantMode, RC_TABLE};
pub use keccak_f1600::KeccakF1600;

/// Convenience function for Keccak-f[1600] using table-based round constants
pub fn keccak_f1600(state: &mut [u64; 25]) {
    let permutation = KeccakF1600::new(RoundConstantMode::Table);
    permutation.permute(state);
}


pub struct Keccak {
    state: [u64; 25],
    rate: usize,     // in bytes
    offset: usize,   // current byte offset in the rate part of the state
    delimiter: u8,   // domain separation suffix combined with first padding bit
                     // SHA-3: 0x06 (bits: 01 || 1), SHAKE: 0x1F (bits: 1111 || 1), RawSHAKE: 0x07 (bits: 11 || 1)
}

impl Keccak {
    pub fn new(rate: usize, delimiter: u8) -> Self {
        assert!(rate < 200, "Rate must be less than state size (1600 bits = 200 bytes)");
        Keccak {
            state: [0; 25],
            rate,
            offset: 0,
            delimiter,
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        for &byte in input {
            // XOR byte into state
            let lane_idx = self.offset / 8;
            let byte_idx = self.offset % 8;
            
            self.state[lane_idx] ^= (byte as u64) << (8 * byte_idx);
            self.offset += 1;

            if self.offset == self.rate {
                keccak_f1600(&mut self.state);
                self.offset = 0;
            }
        }
    }

    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        // Padding
        let lane_idx = self.offset / 8;
        let byte_idx = self.offset % 8;
        self.state[lane_idx] ^= (self.delimiter as u64) << (8 * byte_idx);

        let last_lane_idx = (self.rate - 1) / 8;
        let last_byte_idx = (self.rate - 1) % 8;
        self.state[last_lane_idx] ^= 0x80 << (8 * last_byte_idx);

        keccak_f1600(&mut self.state);

        // Squeeze
        let mut output = Vec::with_capacity(output_len);
        while output.len() < output_len {
            let block_size = std::cmp::min(self.rate, output_len - output.len());
            for i in 0..block_size {
                let lane_idx = i / 8;
                let byte_idx = i % 8;
                let byte = (self.state[lane_idx] >> (8 * byte_idx)) as u8;
                output.push(byte);
            }
            
            if output.len() < output_len {
                keccak_f1600(&mut self.state);
            }
        }
        
        output
    }
}

// SHA-3 Variants

pub fn sha3_224(data: &[u8]) -> [u8; 28] {
    let mut hasher = Keccak::new(144, 0x06);
    hasher.update(data);
    let out = hasher.finalize(28);
    out.try_into().unwrap()
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::new(136, 0x06);
    hasher.update(data);
    let out = hasher.finalize(32);
    out.try_into().unwrap()
}

pub fn sha3_384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Keccak::new(104, 0x06);
    hasher.update(data);
    let out = hasher.finalize(48);
    out.try_into().unwrap()
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Keccak::new(72, 0x06);
    hasher.update(data);
    let out = hasher.finalize(64);
    out.try_into().unwrap()
}


#[test]
fn test_lfsr_round_constants() {
    // Verify that LFSR generates the correct round constants
    use crate::round_constants::lfsr_round_constant;
    
    let expected = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];
    
    for (round, &expected_rc) in expected.iter().enumerate() {
        let computed_rc = lfsr_round_constant(round);
        assert_eq!(computed_rc, expected_rc, 
            "Round {} constant mismatch: expected 0x{:016x}, got 0x{:016x}",
            round, expected_rc, computed_rc);
    }
}

#[test]
fn test_keccak_f1600_table_vs_lfsr() {
    // Test that table-based and LFSR-based round constants produce the same result
    let mut state_table = [0u64; 25];
    let mut state_lfsr = [0u64; 25];
    
    // Initialize with some test pattern
    for i in 0..25 {
        state_table[i] = i as u64 * 0x0123456789abcdef;
        state_lfsr[i] = i as u64 * 0x0123456789abcdef;
    }
    
    let table_perm = KeccakF1600::new(RoundConstantMode::Table);
    let lfsr_perm = KeccakF1600::new(RoundConstantMode::Lfsr);
    
    table_perm.permute(&mut state_table);
    lfsr_perm.permute(&mut state_lfsr);
    
    assert_eq!(state_table, state_lfsr, "Table and LFSR modes should produce identical results");
}

#[test]
fn test_individual_steps() {
    // Test that individual steps can be called separately
    let mut state = [0u64; 25];
    state[0] = 1;
    
    let perm = KeccakF1600::new(RoundConstantMode::Table);
    
    // Manually perform one round
    perm.theta(&mut state);
    perm.rho_pi(&mut state);
    perm.chi(&mut state);
    perm.iota(&mut state, 0);
    
    // Compare with single round call
    let mut state2 = [0u64; 25];
    state2[0] = 1;
    perm.round(&mut state2, 0);
    
    assert_eq!(state, state2, "Manual steps should equal round() call");
}

#[test]
fn test_sha3_256_empty() {
    let hash = sha3_256(b"");
    // a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    assert_eq!(hash, [
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    ]);
}

#[test]
fn test_sha3_256_vector() {
    // "abc"
    // 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    let hash = sha3_256(b"abc");
    assert_eq!(hash, [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
    ]);
}

#[test]
fn test_sha3_224_empty() {
    let hash = sha3_224(b"");
    // 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7
    assert_eq!(hash, [
        0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7,
        0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e, 0xb1, 0xab,
        0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f,
        0x5b, 0x5a, 0x6b, 0xc7
    ]);
}

#[test]
fn test_sha3_384_empty() {
    let hash = sha3_384(b"");
    // 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004
    assert_eq!(hash, [
        0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d,
        0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85,
        0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61,
        0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a,
        0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47,
        0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04
    ]);
}

#[test]
fn test_sha3_512_empty() {
    let hash = sha3_512(b"");
    // a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
    assert_eq!(hash, [
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
        0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
        0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
        0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
        0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
        0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
        0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26
    ]);
}

// SHA-3 test vectors from https://di-mgt.com.au/sha_testvectors.html

#[test]
fn test_sha3_224_abc() {
    let hash = sha3_224(b"abc");
    assert_eq!(
        hex::encode(hash),
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
    );
}

#[test]
fn test_sha3_224_448_bits() {
    let hash = sha3_224(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        hex::encode(hash),
        "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"
    );
}

#[test]
fn test_sha3_224_896_bits() {
    let hash = sha3_224(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    assert_eq!(
        hex::encode(hash),
        "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc"
    );
}

#[test]
fn test_sha3_224_million_a() {
    let data = vec![b'a'; 1_000_000];
    let hash = sha3_224(&data);
    assert_eq!(
        hex::encode(hash),
        "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"
    );
}

#[test]
fn test_sha3_256_448_bits() {
    let hash = sha3_256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        hex::encode(hash),
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    );
}

#[test]
fn test_sha3_256_896_bits() {
    let hash = sha3_256(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    assert_eq!(
        hex::encode(hash),
        "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"
    );
}

#[test]
fn test_sha3_256_million_a() {
    let data = vec![b'a'; 1_000_000];
    let hash = sha3_256(&data);
    assert_eq!(
        hex::encode(hash),
        "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"
    );
}

#[test]
fn test_sha3_384_abc() {
    let hash = sha3_384(b"abc");
    assert_eq!(
        hex::encode(hash),
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
    );
}

#[test]
fn test_sha3_384_448_bits() {
    let hash = sha3_384(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        hex::encode(hash),
        "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22"
    );
}

#[test]
fn test_sha3_384_896_bits() {
    let hash = sha3_384(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    assert_eq!(
        hex::encode(hash),
        "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"
    );
}

#[test]
fn test_sha3_384_million_a() {
    let data = vec![b'a'; 1_000_000];
    let hash = sha3_384(&data);
    assert_eq!(
        hex::encode(hash),
        "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"
    );
}

#[test]
fn test_sha3_512_abc() {
    let hash = sha3_512(b"abc");
    assert_eq!(
        hex::encode(hash),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    );
}

#[test]
fn test_sha3_512_448_bits() {
    let hash = sha3_512(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        hex::encode(hash),
        "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"
    );
}

#[test]
fn test_sha3_512_896_bits() {
    let hash = sha3_512(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    assert_eq!(
        hex::encode(hash),
        "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"
    );
}

#[test]
fn test_sha3_512_million_a() {
    let data = vec![b'a'; 1_000_000];
    let hash = sha3_512(&data);
    assert_eq!(
        hex::encode(hash),
        "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"
    );
}
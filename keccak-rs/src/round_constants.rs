/// Precomputed round constants
pub const RC_TABLE: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundConstantMode {
    Table,
    Lfsr,
}

/// Generate round constant using LFSR (from the Keccak Reference)
/// rc[t] = (x^t mod x^8 + x^6 + x^5 + x^4 + 1) mod x in GF(2)[x]
pub fn lfsr_round_constant(round: usize) -> u64 {
    // Initialize LFSR
    let mut r = 0x01u8;
    let mut rc = 0u64;
    
    // Run LFSR to position for this round
    for _ in 0..(7 * round) {
        // LFSR step: polynomial x^8 + x^6 + x^5 + x^4 + 1
        let high_bit = r & 0x80;
        r <<= 1;
        if high_bit != 0 {
            r ^= 0x71; // x^8 + x^6 + x^5 + x^4 + 1 -> 0b01110001
        }
    }

    // Now extract the 7 bits for this round
    for j in 0..7 {
        let bit_position = (1 << j) - 1; // 2^j - 1
        if r & 1 != 0 {
            rc ^= 1u64 << bit_position;
        }
        
        let high_bit = r & 0x80;
        r <<= 1;
        if high_bit != 0 {
            r ^= 0x71;
        }
    }
    
    rc
}

/// Get round constant based on mode
pub fn get_round_constant(round: usize, mode: RoundConstantMode) -> u64 {
    match mode {
        RoundConstantMode::Table => RC_TABLE[round],
        RoundConstantMode::Lfsr => lfsr_round_constant(round),
    }
}

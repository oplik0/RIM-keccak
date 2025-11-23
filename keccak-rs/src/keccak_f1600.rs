use crate::round_constants::{get_round_constant, RoundConstantMode};

// Rotation offsets (x, y)
const RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

pub struct KeccakF1600 {
    mode: RoundConstantMode,
}

impl KeccakF1600 {
    // the round mode it just for benchmarking to see how much tabling the constant helps in software
    // I believe even in hw tabling is still preferable, but LFSRs work a lot better there than on a CPU
    pub fn new(mode: RoundConstantMode) -> Self {
        Self { mode }
    }

    pub fn theta(&self, state: &mut [u64; 25]) {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }
    }

    /// Rho and Pi steps are typically combined for efficiency
    /// Implementing them separately would lower performance even more...
    pub fn rho_pi(&self, state: &mut [u64; 25]) {
        let mut x = 1;
        let mut y = 0;
        let mut current = state[x + 5 * y];
        for _ in 0..24 {
            let t = RHO[x][y];
            let next_x = y;
            let next_y = (2 * x + 3 * y) % 5;
            
            let temp = state[next_x + 5 * next_y];
            state[next_x + 5 * next_y] = current.rotate_left(t);
            current = temp;
            
            x = next_x;
            y = next_y;
        }
    }

    pub fn chi(&self, state: &mut [u64; 25]) {
        for y in 0..5 {
            let mut row = [0u64; 5];
            for x in 0..5 {
                row[x] = state[x + 5 * y];
            }
            for x in 0..5 {
                state[x + 5 * y] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
    }

    pub fn iota(&self, state: &mut [u64; 25], round: usize) {
        let rc = get_round_constant(round, self.mode);
        state[0] ^= rc;
    }

    pub fn round(&self, state: &mut [u64; 25], round_index: usize) {
        self.theta(state);
        self.rho_pi(state);
        self.chi(state);
        self.iota(state, round_index);
    }

    /// All rounds
    pub fn permute(&self, state: &mut [u64; 25]) {
        for round in 0..24 {
            self.round(state, round);
        }
    }
}

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime};
use keccak_rs::{sha3_256, sha3_224, sha3_384, sha3_512, KeccakF1600, RoundConstantMode};
use std::hint::black_box;

/// Benchmark the raw Keccak-f[1600] permutation
fn bench_keccak_f1600_permutation(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_f1600_permutation");
    
    // Each permutation processes 200 bytes of state (1600 bits)
    group.throughput(Throughput::Bytes(200));

    let mut state = [0u64; 25];
    for i in 0..25 {
        state[i] = i as u64 * 0x0123456789abcdef;
    }

    group.bench_function("table_mode", |b| {
        let perm = KeccakF1600::new(RoundConstantMode::Table);
        b.iter(|| {
            let mut s = black_box(state);
            perm.permute(black_box(&mut s));
            black_box(s);
        });
    });

    group.bench_function("lfsr_mode", |b| {
        let perm = KeccakF1600::new(RoundConstantMode::Lfsr);
        b.iter(|| {
            let mut s = black_box(state);
            perm.permute(black_box(&mut s));
            black_box(s);
        });
    });

    group.finish();
}

/// Benchmark individual steps of the Keccak-f[1600] permutation
fn bench_keccak_steps(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_f1600_steps");
    
    // Each step processes 200 bytes of state
    group.throughput(Throughput::Bytes(200));

    let mut state = [0u64; 25];
    for i in 0..25 {
        state[i] = i as u64 * 0x0123456789abcdef;
    }

    let perm = KeccakF1600::new(RoundConstantMode::Table);

    group.bench_function("theta", |b| {
        b.iter(|| {
            let mut s = black_box(state);
            perm.theta(black_box(&mut s));
            black_box(s);
        });
    });

    group.bench_function("rho_pi", |b| {
        b.iter(|| {
            let mut s = black_box(state);
            perm.rho_pi(black_box(&mut s));
            black_box(s);
        });
    });

    group.bench_function("chi", |b| {
        b.iter(|| {
            let mut s = black_box(state);
            perm.chi(black_box(&mut s));
            black_box(s);
        });
    });

    group.bench_function("iota", |b| {
        b.iter(|| {
            let mut s = black_box(state);
            perm.iota(black_box(&mut s), black_box(0));
            black_box(s);
        });
    });

    group.bench_function("single_round", |b| {
        b.iter(|| {
            let mut s = black_box(state);
            perm.round(black_box(&mut s), black_box(0));
            black_box(s);
        });
    });

    group.finish();
}

/// Benchmark SHA3-256 hashing with various input sizes
fn bench_sha3_256_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_256_throughput");

    // Test different input sizes
    let sizes = [
        64,      // Small: single block
        136,     // Exactly one rate (SHA3-256 rate)
        1024,    // 1 KB
        4096,    // 4 KB
        16384,   // 16 KB
    ];

    for size in sizes {
        let data = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let hash = sha3_256(black_box(data));
                black_box(hash);
            });
        });
    }

    group.finish();
}

/// Benchmark all SHA-3 variants with same input size
fn bench_sha3_variants(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_variants");

    let empty = b"";
    let small = b"Against stupidity, the gods themselves contend in vain";
    let medium = vec![0xAAu8; 1024];

    group.throughput(Throughput::Bytes(0));
    group.bench_function("sha3_256_empty", |b| {
        b.iter(|| {
            let hash = sha3_256(black_box(empty));
            black_box(hash);
        });
    });

    group.throughput(Throughput::Bytes(small.len() as u64));
    group.bench_function("sha3_256_small", |b| {
        b.iter(|| {
            let hash = sha3_256(black_box(small));
            black_box(hash);
        });
    });

    group.throughput(Throughput::Bytes(medium.len() as u64));
    group.bench_function("sha3_256_medium", |b| {
        b.iter(|| {
            let hash = sha3_256(black_box(&medium));
            black_box(hash);
        });
    });

    group.finish();
}

/// Benchmark different SHA-3 output sizes
fn bench_sha3_all_variants(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_all_variants");
    
    let data = vec![0xA5u8; 4096];
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("sha3_224", |b| {
        b.iter(|| {
            let hash = sha3_224(black_box(&data));
            black_box(hash);
        });
    });

    group.bench_function("sha3_256", |b| {
        b.iter(|| {
            let hash = sha3_256(black_box(&data));
            black_box(hash);
        });
    });

    group.bench_function("sha3_384", |b| {
        b.iter(|| {
            let hash = sha3_384(black_box(&data));
            black_box(hash);
        });
    });

    group.bench_function("sha3_512", |b| {
        b.iter(|| {
            let hash = sha3_512(black_box(&data));
            black_box(hash);
        });
    });

    group.finish();
}

/// Benchmark round constant generation methods
fn bench_round_constants(c: &mut Criterion) {
    use keccak_rs::round_constants::{get_round_constant, lfsr_round_constant, RoundConstantMode, RC_TABLE};

    let mut group = c.benchmark_group("round_constant_generation");
    
    // Processing 24 round constants (24 * 8 bytes = 192 bytes)
    group.throughput(Throughput::Bytes(192));

    group.bench_function("table_lookup", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            for round in 0..24 {
                sum ^= black_box(RC_TABLE[round]);
            }
            black_box(sum);
        });
    });

    group.bench_function("lfsr_generation", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            for round in 0..24 {
                sum ^= black_box(lfsr_round_constant(round));
            }
            black_box(sum);
        });
    });

    group.bench_function("get_round_constant_table", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            for round in 0..24 {
                sum ^= black_box(get_round_constant(round, RoundConstantMode::Table));
            }
            black_box(sum);
        });
    });

    group.bench_function("get_round_constant_lfsr", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            for round in 0..24 {
                sum ^= black_box(get_round_constant(round, RoundConstantMode::Lfsr));
            }
            black_box(sum);
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(WallTime);
    targets = 
        bench_keccak_f1600_permutation,
        bench_keccak_steps,
        bench_sha3_256_throughput,
        bench_sha3_variants,
        bench_sha3_all_variants,
        bench_round_constants
);

criterion_main!(benches);

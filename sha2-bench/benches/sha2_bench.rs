use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main, black_box};
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256, Digest};

/// Benchmark SHA-256 with various input sizes
fn bench_sha256_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_throughput");

    // Test different input sizes
    let sizes = [
        64,      // Small: single block
        512,     // Multiple blocks
        1024,    // 1 KB
        4096,    // 4 KB
        16384,   // 16 KB
    ];

    for size in sizes {
        let data = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut hasher = Sha256::new();
                hasher.update(black_box(data));
                let result = hasher.finalize();
                black_box(result);
            });
        });
    }

    group.finish();
}

/// Benchmark all SHA-2 variants with same input size
fn bench_sha2_variants(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha2_variants");

    let empty = b"";
    let small = b"The quick brown fox jumps over the lazy dog";
    let medium = vec![0xAAu8; 1024];

    // Empty input
    group.throughput(Throughput::Bytes(0));
    group.bench_function("sha256_empty", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(empty));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    // Small input
    group.throughput(Throughput::Bytes(small.len() as u64));
    group.bench_function("sha256_small", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(small));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    // Medium input
    group.throughput(Throughput::Bytes(medium.len() as u64));
    group.bench_function("sha256_medium", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&medium));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark all SHA-2 family variants
fn bench_sha2_all_variants(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha2_all_variants");
    
    let data = vec![0xA5u8; 4096];
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("sha224", |b| {
        b.iter(|| {
            let mut hasher = Sha224::new();
            hasher.update(black_box(&data));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    group.bench_function("sha256", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&data));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    group.bench_function("sha384", |b| {
        b.iter(|| {
            let mut hasher = Sha384::new();
            hasher.update(black_box(&data));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    group.bench_function("sha512", |b| {
        b.iter(|| {
            let mut hasher = Sha512::new();
            hasher.update(black_box(&data));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    group.bench_function("sha512_224", |b| {
        b.iter(|| {
            let mut hasher = Sha512_224::new();
            hasher.update(black_box(&data));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    group.bench_function("sha512_256", |b| {
        b.iter(|| {
            let mut hasher = Sha512_256::new();
            hasher.update(black_box(&data));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark SHA-256 vs SHA-512 on different input sizes
fn bench_sha256_vs_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_vs_sha512");

    let sizes = [64, 512, 4096, 16384];

    for size in sizes {
        let data = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("sha256", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut hasher = Sha256::new();
                    hasher.update(black_box(data));
                    let result = hasher.finalize();
                    black_box(result);
                });
            }
        );

        group.bench_with_input(
            BenchmarkId::new("sha512", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut hasher = Sha512::new();
                    hasher.update(black_box(data));
                    let result = hasher.finalize();
                    black_box(result);
                });
            }
        );
    }

    group.finish();
}

/// Benchmark one-shot hashing vs incremental
fn bench_oneshot_vs_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("oneshot_vs_incremental");

    let data = vec![0xA5u8; 4096];
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("sha256_oneshot", |b| {
        b.iter(|| {
            let result = Sha256::digest(black_box(&data));
            black_box(result);
        });
    });

    group.bench_function("sha256_incremental", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&data));
            let result = hasher.finalize();
            black_box(result);
        });
    });

    // Incremental with multiple chunks
    let chunk_size = 512;
    group.bench_function("sha256_incremental_chunked", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            for chunk in data.chunks(chunk_size) {
                hasher.update(black_box(chunk));
            }
            let result = hasher.finalize();
            black_box(result);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sha256_throughput,
    bench_sha2_variants,
    bench_sha2_all_variants,
    bench_sha256_vs_sha512,
    bench_oneshot_vs_incremental
);

criterion_main!(benches);

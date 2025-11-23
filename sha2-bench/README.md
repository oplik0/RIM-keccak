# SHA-2 Benchmarks

Benchmarks for the SHA-2 family of hash functions using the `sha2` crate.

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark group
cargo bench sha256_throughput
cargo bench sha2_all_variants
cargo bench sha256_vs_sha512
```

## Benchmark Groups

### sha256_throughput
Tests SHA-256 performance with various input sizes (64B to 16KB).

### sha2_variants
Compares SHA-256 performance on empty, small, and medium inputs.

### sha2_all_variants
Compares all SHA-2 family members (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256) on 4KB input.

### sha256_vs_sha512
Direct comparison of SHA-256 vs SHA-512 across different input sizes.

### oneshot_vs_incremental
Compares one-shot hashing vs incremental hashing (single update vs multiple chunked updates).

## Results Location

- HTML reports: `target/criterion/`
- Raw data: `target/criterion/<benchmark-name>/`

## Dependencies

- `sha2`: Official Rust implementation of SHA-2
- `criterion`: Statistical benchmarking framework

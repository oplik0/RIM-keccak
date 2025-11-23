# Keccak/SHA-3 Implementation in C

Port of the Rust implementation to C.

Test using nix:
```sh
nix run .#test
```

Simple CLI:
```sh
nix run .#default -- sha3-256 abc
```
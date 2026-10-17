# Offline host RAM hashing measurements

This run compares the selected host BLAKE3 implementation with an offline SHA-256 implementation over the same canonical RAM domains. It is performance evidence for hashing only; it does not qualify memory placement, resident peaks, native C fingerprinting, storage, metadata allocation or fork costs.

The receipt records an AMD EPYC 9755 x86_64 host. BLAKE3 1.8.5 uses the workspace `std,pure` features: `pure` excludes assembly and AVX-512, while runtime detection selected Rust AVX2 intrinsics with SIMD degree eight. Small-block compression uses the implementation's SSE4.1 path. SHA-256 uses sha2 0.10.9 with default x86 runtime detection; SHA, SSE2, SSSE3 and SSE4.1 were available, selecting hardware SHA intrinsics. No ARM acceleration was measured.

[receipt.json](receipt.json) contains the actual CPU flags, algorithm paths and scope limitations. [measurements.csv](measurements.csv) contains all 130 samples. There are five samples per workload and algorithm, with fixed repetition counts and warm inputs. Each batch changes every declared dirty page, hashes the changed pages and leaves, visits the union of ancestors once, then commits the region and scoped root. Prebuilt buffers and dense node storage exclude persistent-tree allocation and metadata COW. The benchmark tests verify canonical preimages against the production commitments and union updates against the actual persistent tree.

The table gives the median elapsed nanoseconds per preimage or complete batch. Zero page counts denote standalone preimages rather than a modeled RAM inventory. SHA-256 was faster for these measured inputs on this host; this run does not establish a general speed ranking or justify an assumed BLAKE3 speedup. No processor affinity or frequency isolation was applied.

| Workload | Logical pages | Changed pages | BLAKE3 median ns | SHA-256 median ns | SHA/BLAKE3 time |
|---|---:|---:|---:|---:|---:|
| page-4096 | 0 | 0 | 7026.1 | 2103.8 | 0.30 |
| final-partial-page-4095 | 0 | 0 | 7017.0 | 2099.2 | 0.30 |
| final-partial-page-1 | 0 | 0 | 132.9 | 58.8 | 0.44 |
| leaf | 0 | 0 | 126.3 | 56.3 | 0.45 |
| branch | 0 | 0 | 244.8 | 99.3 | 0.41 |
| region-tree | 0 | 0 | 251.0 | 99.8 | 0.40 |
| scoped-root-one-region | 0 | 0 | 383.7 | 147.8 | 0.39 |
| sparse-union-update | 256 | 1 | 9786.9 | 3209.7 | 0.33 |
| sparse-union-update | 256 | 16 | 134866.7 | 42481.5 | 0.31 |
| dense-union-update | 256 | 256 | 1898459.2 | 577723.7 | 0.30 |
| sparse-union-update | 4096 | 1 | 10740.1 | 3582.3 | 0.33 |
| sparse-union-update | 4096 | 16 | 150468.4 | 48845.7 | 0.32 |
| dense-union-update | 4096 | 4096 | 30377845.6 | 9276819.2 | 0.31 |

Reproduce with the repository's source-built development toolchain:

```sh
nix develop --accept-flake-config --option builders '' -c \
  env CARGO_TARGET_DIR="$PWD/crates/target" cargo build \
  --manifest-path crates/Cargo.toml -p crucible-ram --release \
  --example ram-hash-benchmark --features test-support
./crates/target/release/examples/ram-hash-benchmark <output-directory>
```

The example and SHA dependency are gated by `test-support`; SHA-256 is not an alternate production RAM algorithm. The receipt's profile and dependency versions must be checked against the build when rerunning after a dependency or compiler change.

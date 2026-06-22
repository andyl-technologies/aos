# aos-nix fuzz targets

This package is intentionally outside the main Cargo workspace. It is driven by
`cargo-fuzz` and compares generated aos-nix JSON evaluation against pinned C++
Nix when `AOS_NIX_ORACLE` points at `nix-instantiate` 2.24.12.

```text
cargo fuzz run parity_json
AOS_NIX_ORACLE=/path/to/nix-instantiate cargo fuzz run parity_json
```

Corpus files beginning with `# aos-nix-fuzz-source` are treated as literal Nix
source seeds. Other inputs are decoded through the structure-aware `arbitrary`
generator in `src/lib.rs`.

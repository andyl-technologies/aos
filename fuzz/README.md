# aos-nix fuzz targets

This package is intentionally outside the main Cargo workspace. It is driven by
`cargo-fuzz` and compares generated aos-nix JSON evaluation against pinned C++
Nix when `AOS_NIX_ORACLE` points at `nix-instantiate` 2.24.12. It also carries
the internal differential entry point used by optimized tiers to compare strict
raw rendering against the safe tree-walk oracle.

```text
cargo fuzz run parity_json
AOS_NIX_ORACLE=/path/to/nix-instantiate cargo fuzz run parity_json
cargo fuzz run internal_diff_raw
```

Corpus files beginning with `# aos-nix-fuzz-source` are treated as literal Nix
source seeds. Other inputs are decoded through the structure-aware `arbitrary`
generator in `src/lib.rs`.

`internal_diff_raw` currently uses a tree-walk mirror candidate so the fuzz
target and corpus are live before optimized tiers exist. P6/P7 tiers replace
that mirror candidate with their own `InternalDiffTier` implementation.

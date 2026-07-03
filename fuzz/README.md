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

Populate the generated parity seed corpus from the same package/toolchain/system
corpus used by `aos nix-diff --all --systems`:

```text
aos nix-fuzz-corpus --clean
AOS_NIX_LANG_TESTS=/path/to/nix/tests/functional/lang aos nix-fuzz-corpus --clean
```

The command writes ignored files under `fuzz/corpus/parity_json/generated/`.
Generated seeds default to `system = "x86_64-linux"` and honor the global
`--eval-system` override when another target is intentional.
Each generated source seed records the effective eval mode, target system, and
restricted-mode allowlist policy in `# aos-nix-fuzz-config ...` comments; the
fuzz harness applies those settings to both the native evaluator and the
configured C++ oracle while still accepting older source seeds without metadata.
When `AOS_NIX_LANG_TESTS` points at the pinned C++ Nix lang corpus, supported
`eval-okay` cases are included through a copied
`generated-conformance-corpus.nix` support file beside the generated seeds.

Replay source seeds through the command-line JSON diff gate:

```text
aos nix-diff --eval-json --eval-json-corpus fuzz/corpus/parity_json
aos nix-diff --eval-json --eval-json-corpus fuzz/corpus/parity_json/generated
```

The CLI loader accepts only `# aos-nix-fuzz-source` seed files and applies
`# aos-nix-fuzz-config ...` metadata to both evaluators. Seed-local eval mode,
target system, and restricted-eval allowlists override the command's global eval
flags; older source seeds without metadata still use the command flags.
The checked-in source seeds are also wired through
`checks.integration.aos-eval-json-corpus-smoke`.

`internal_diff_raw` currently uses a tree-walk mirror candidate so the fuzz
target and corpus are live before optimized tiers exist. P6/P7 tiers replace
that mirror candidate with their own `InternalDiffTier` implementation.

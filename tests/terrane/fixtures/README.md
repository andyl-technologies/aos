# Terrane tree boundary measurements

These TSV files preserve the T-RISK-3 experiment for RISK-5 and TREE-22.
Every run builds complete canonical leaf and internal nodes, checks the
inline-file golden node identity, and replays each sorted sequence with
ingestion batches of 1 and 257. Root identities and every level's statistics
must match. Sizes exclude node framing; child weights include it.

The sequential fixture uses eight-digit decimal filenames. The shared-prefix
fixture adds a 120-byte common component prefix. The hash-like fixture sorts
actual BLAKE3 digests of little-endian ordinal values and renders them as
64-byte hexadecimal names. All entries use the normative 15-byte inline file
and its chunk identity; all keys are valid single components.

| Artifact | Source revision | Normative source | Result |
| --- | --- | --- | --- |
| `tree-node-distribution.tsv` | `e1aa6e5bac` | specification at `26db76d346` | Fails: target means and strict node limit |
| `tree-node-distribution-corrected.tsv` | `85ee260ead` | D-24 at `4875bddabc`, sample clarification at `1deb468120` | Passes: qualifying means, all size limits, all deterministic replays |

The original source revision remains on `dplecki/terrane-risk-3-wip` and
contains the temporary module wiring needed to build that historical spike.
The corrected source revision's base is `b57401ddc9`; the sample-floor rule
was read from `1deb468120` before implementing its exact predicate.

From a checkout containing the selected source revision and its core module
registration, build through the AOS toolchain and run the resulting example:

```sh
CARGO_TARGET_DIR="$(agent-worktree cargo-target)" nix develop .#terrane -c cargo build --manifest-path crates/Cargo.toml -p terrane-core --example tree_node_distribution --release
"$(agent-worktree cargo-target)/release/examples/tree_node_distribution" > tree-node-distribution.tsv
```

The original run exits with status 1 after reporting every fixture. The
corrected run exits successfully. `--report-only` suppresses the failing exit
for investigation; the Nix gate invokes the example without that option.
Every fixture exercises 10^4, 10^5, 10^6, and 10^7 entries. Roots and tails
are reported separately from complete-node means; corrected target-band
assertions require at least 100 complete nodes at a fixture level. Every
node still obeys the hard cap and every tree still undergoes replay checks.

Regenerate measurements from the referenced algorithm before replacing an
artifact. Review changes in keys, entry bytes, prefix compression, framing,
child weights, integer thresholds, and root identities as format changes.

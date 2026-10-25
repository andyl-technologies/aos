# CLI source selection

The test constructor in `tests/build/_bazel-aos-cli.nix` accepts
`sourceInventory`, matching the production constructor. A configured inventory
selects its source files, implementation discovery roots, and declaration
contracts. `null` retains the conservative selection used to regenerate
inventories while qualification continues.

The [retained source-filter probe](../tests/evidence/cli-precise-source-selection.json)
uses the actual test constructor and a merged configured inventory containing
89 targets, 1,364 source files, and 210 declaration contracts. Adding unrelated
documentation and metadata JSON preserves the precise source identity while
changing the conservative source identity. A new implementation file enters the
precise source without regenerating the inventory. Changing the CLI BUILD file
rejects the stale inventory. All temporary edits are removed, and the original
source identity is restored.

The report retains the executed harness, Nix expression, source contracts, and
immutable analysis inputs. This probe qualifies source filtering only. Full
compiler and test comparisons remain separate gates; ordinary defaults stay
conservative until the complete inventory and compiler checks pass.

The [executed precise-source comparison](../tests/evidence/cli-precise-source-tests.json)
passes all 543 ordinary and 551 fleet cases, together with the selected
first-party and procedural-macro profile checks. Its 1,269 ordinary and 1,278
fleet actions execute in Linux sandboxes without cache hits. All selected Rust
files match the previously executed offline Cargo baselines. The repository
fixtures differ only in the constructor adding the optional source inventory;
the report records that difference explicitly. This comparison uses the staged
inventory and leaves the default unchanged. External dependency units and full
compiler, native C/linker, runtime, editor, platform, and performance checks
remain separate qualification work.

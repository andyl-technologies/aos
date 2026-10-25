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

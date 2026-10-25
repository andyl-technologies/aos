# CLI source selection

The test constructor in `tests/build/_bazel-aos-cli.nix` accepts
`sourceInventory` and defaults to the checked-in CLI inventory. The inventory
selects source files, implementation discovery roots, and declaration contracts.
An explicit `null` retains conservative selection for regeneration. The production
constructor keeps its separate opt-in precise selection.

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
compiler and test comparisons remain separate gates. This historical probe used
an explicit inventory before precise selection became the test default.

The [executed precise-source comparison](../tests/evidence/cli-precise-source-tests.json)
passes all 543 ordinary and 551 fleet cases, together with the selected
first-party and procedural-macro profile checks. Its 1,269 ordinary and 1,278
fleet actions execute in Linux sandboxes without cache hits. All selected Rust
files match the previously executed offline Cargo baselines. The repository
fixtures differ only in the constructor adding the optional source inventory;
the report records that difference explicitly. That historical comparison supplied a staged
inventory before the default changed. External dependency units and full
compiler, native C/linker, runtime, editor, platform, and performance checks
remain separate qualification work.

The [default-source qualification](../tests/evidence/cli-default-source-selection.json)
uses the test constructor without a `sourceInventory` override. Both ordinary
and fleet configurations pass the complete case comparison, selected first-party
and procedural-macro profiles, and all 552 external feature/cfg/edition units.
The report retains the source-filter probe and checks every selected Rust file
against the executed native baseline. Complete compiler defaults, native C/linker,
ABI/runtime/editor/platform/cache, and numeric performance qualification remain
separate work.

Regenerate the combined production, ordinary-test, and fleet-test inventory with:

```sh
nix-build tools/bazel/tests/aos-cli.nix -A inventories.merged --no-out-link
```

Review the returned `inventory.json`, then copy it to
`tools/bazel/metadata/aos-cli-inventory.json`. The `inventories.default`,
`inventories.fleet`, and `inventories.production` attributes expose their
individual analysis outputs. These routes select conservative source trees
explicitly, so they remain available when a changed BUILD declaration makes
the checked-in inventory stale. The merger checks every input contract against
its declared source snapshot. The retained qualification builds both the normal
merge and the immutable stale-declaration snapshot. The normal merge reproduces
the checked-in inventory byte for byte. The stale snapshot refreshes only the
changed BUILD contract; both preserve all previously recorded sources, discovery
roots, target labels, and feature/platform units.

# Cargo workspace migration tooling

`crate-migration.json` records the reviewed initial mapping from the former flat
workspace to scoped package names and nested source locations. Follow-up merges
and extractions are implemented separately: an initial mapping entry does not
promise that a temporary package remains in the final workspace.

Run the script from any directory with Python 3.11 or later:

```sh
python3 tools/dev/crate-migrate.py          # preview the initial migration
python3 tools/dev/crate-migrate.py --apply  # apply it once
python3 tools/dev/crate-migrate.py --check  # validate mapped targets and members
python3 tools/dev/crate-migrate.py --report # classify remaining old names
```

The initial migration has already been applied. Use `--check` and `--report` for
subsequent review. Initial application stages directories before moving them;
this allows the former `crates/aos` package to become the `crates/aos/` project
parent without moving a directory into itself.

The script updates package identities, dependency keys, dependency `package`
fields, direct path dependencies, workspace members, Cargo feature references,
lockfile local identities, Rust crate identifiers, Cargo package selectors,
explicit repository paths, and existing relative source/include paths. Explicit
dependency aliases retain their names. Implicit executable targets are pinned to
their old names before package renaming. Renaming Rust crate identifiers uses
separate code and string regions so arbitrary serialized strings are preserved.

The report is intentionally a review queue. An old word can name an executable,
Nix derivation, historical record, ABI label, signed schema, or digest domain;
those values must not be changed simply because a Cargo package changed. Native
qualification evidence under `tests/crucible/fixtures/` is left intact.

After mechanical edits, review and validate:

- Generated API source inputs and build-script dependencies.
- Root discovery and package inventories in architectural tests.
- Nix selections: members are directory paths, package selectors are names.
- Nix source filters: retain ancestors of nested selected members.
- Public commands, protocol identities, and signing domains.
- Cargo metadata, application test-target compilation, native/Wasm builds, and
  the affected runtime and license-boundary gates.

The authoritative active package set is `crates/Cargo.toml`, not the historical
migration map. New package locations and dependency boundaries are documented in
`docs/architecture/crate-workspace.md`.

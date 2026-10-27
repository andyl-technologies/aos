# Production dependency metadata

`pkgs.aosBazelArchitecture` exports the source-package catalogue and Rust
production dependency graph from Bazel declarations. It runs an unconfigured
query inside the Nix sandbox with the pinned source-built rule inputs. It does
not configure an application or require crate archives or application binaries.
The launcher disables repository downloads and uses the prepared module lock.

`architecture.json` records each package's identity, production targets, and
production package dependencies. The accompanying `rules.jsonl` preserves the
structured query, including selectors. The export records the query digest and
the digests of SDK source manifests used to resolve upstream package names.

The graph unions every platform and feature branch, including concatenated
selectors. Only explicit `deps` and `proc_macro_deps` of production Rust
compilation rules contribute package edges. Rust build-script programs count;
test-only targets, data, generator tools, and implicit toolchains do not. Native
library labels and unavailable-profile analysis guards are recorded separately.
Aliases resolve through every branch, using pinned SDK manifests for upstream
package names. Unknown labels, alias cycles, ambiguous ownership, and aliases
that resolve only to unavailable-profile guards fail the export.

A package with source metadata but no production compilation target has
`production_dependencies: null`. This is an incomplete model, so architecture
guards must reject a dependency walk that reaches it. An empty list means the
package has modeled production targets and no other Rust package dependencies.

CLI architecture tests receive `build/bazel-architecture.json` through the
declared repository source manifest, which verifies the generated file's size
and digest before materializing it. Bazel test executions require that input;
they cannot fall back to reading Cargo manifests. The dependency guards retain
the portable-core, application-layering, and permissive-QEMU-boundary checks.
Three additional cases cover metadata validation and rejection of reachable
unmodeled packages. The retained `../tests/evidence/aos-cli-architecture.json`
checkpoint binds all six guards to matching default/fleet Bazel and Cargo runs,
Clippy and documentation actions, and the application Rust compilation gate.

The temporary Cargo oracle checks source identities for every workspace member
and exact production dependency sets for every modeled package. It includes
normal and build dependencies from every Cargo target section, including
optional dependencies, and excludes development dependencies. The standalone
`crates/accache` workspace is declared separately in the comparison. Its two
members retain their own workspace dependency and package inheritance rules;
duplicate package ownership and members outside the declared source fail:

```text
nix-build tools/bazel/tests/aos-cli.nix -A architecture --no-out-link
```

This comparison qualifies the declared package graph. Configured compilation,
runtime behavior, license closure checks, and compiler-option equivalence have
their own gates.

Nix source gates can require or forbid direct production package dependencies
through `tests/crucible/_bazel-package-requirements.nix`. The guard checks the
package summary against its owned compilation targets and resolved target
edges. A missing or unmodeled package fails even a negative requirement;
test-only and transitive dependencies cannot satisfy a direct requirement.
Aliases and platform selectors retain the exporter's union semantics.

The protocol descriptor-handover gate uses this guard for its `libc` dependency
and executes its integration target through Bazel with one test worker. Its
existing Rust source assertions and result fields remain in the Nix gate:

```text
nix-build -A checks.crucible.phase2.protocolDescriptorHandover --no-out-link
```

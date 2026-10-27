# Installed public reference implementation

`pkgs.crucible-reference-implementation` builds the Apache public checksum
provider and its controlled companion as a separate installation. It gives the
host a source-owned artifact inventory without making the Crucible suite a
dependency of its own provider installer. The installation contains no QEMU or
gem5 executable dependency.

The package runs the provider's complete unit, binary and integration targets
and production Clippy checks using the AOS toolchain and vendored sources.
Native provider and companion tests execute inside the build sandbox. The
recipe currently requires a native Linux builder; cross-built installations
need an independently source-built measurement tool and a target test runner.
Passing these package checks does not produce a behavioral qualification.

## Installed documents

The installation places these files under `share/crucible/reference`:

| File | Meaning |
| --- | --- |
| `implementation.json` | Closed implementation descriptor with measured provider, companion, source, recipe, contract and closure identities. |
| `runtime-closure.json` | Exact runtime reference graph, measured regular ELF inventory and separately measured build provenance. |
| `source.tar.gz` | Deterministic archive of the actual workspace source snapshot and complete vendored dependency sources. |
| `recipe.nix` | Original package recipe. |
| `contract.tar.gz` | Deterministic archive of the RFC-0025 specification and reference material used by this source snapshot. |

`crucible-reference-manifest` measures these artifacts after the binaries have
completed their ordinary install and fixup phases. Every artifact entry is a
closed `{path, content}` object. `content` is the existing CNP `ContentRef`,
with its original media type, decimal-string length and `cnp.blob.v1` BLAKE3
identity. Both generated documents use the shared strict canonical JSON codec.
Subsequent path scrubbing is disabled for this installation because it would
change the measured protocol data.

The descriptor schema is `crucible.reference.installed-implementation.v1`.
Its fixed policy is `public-byte-linked-checksum-v1`, version `1`.
`artifacts` contains exactly `provider` and `device`; `source_artifacts`
contains exactly `source`, `recipe`, `contract` and `build_closure`.
The declared limitations are:

- `conditional-native-timing`;
- `exact-execution-unsupported`;
- `limited-state-only`;
- `native-preservation-unsupported`;
- `physical-pause-unsupported`;
- `repeatability-unqualified`.

Those limitations remain in force when the source and binaries are authentic.
There are no passing-case booleans, readiness tokens or qualification
certificates in this descriptor.

## Runtime and build closure separation

`runtime-closure.json` uses schema
`crucible.reference.runtime-closure.v1`, with these closed fields:

```text
schema
roots                 {provider: Artifact, device: Artifact}
reference_graph       Artifact
store_paths           sorted unique Nix store roots
objects               sorted regular ELF Artifact entries
build_reference_graph Artifact
build_tools           {archive, c_compiler, cargo, compression, copy, rustc}
```

The runtime inventory starts from the actual binaries' realized Nix reference
graph. The source-owned graph builder emits `aos.reference-graph/v1`, retaining
the original roots, sorted paths, references, NAR hash and NAR size. Measurement
requires the exact original root set, no subtracted roots, complete referenced
paths and full reachability. An omitted loader, extra unscoped root, duplicate
path or reordered path inventory refuses measurement.

All regular ELF bodies under those realized roots are measured. Symlink names
are excluded from the object inventory; the corresponding actual regular body
must exist under a retained root. The inventory can include unused ELF files
from a retained library package. Native enrollment must still authenticate the
actual provider and companion executable, ancestry and process group, and
compare every real mapped library file against `objects`. File presence in the
inventory alone says nothing about a process's behavior.

The separately retained build graph starts from the declared AOS compiler,
Rust, archive, compression, copy and substitution dependencies. `build_tools`
records the actual resolved tool bodies within that graph. These provenance
objects are not a runtime library allowlist. A host must not authorize a native
mapping merely because it appears in `build_tools` or the build graph.

## Measurement bounds and integrity

The emitter enforces a one-MiB input/output metadata ceiling, a 512-MiB
per-artifact ceiling and a four-GiB cumulative measurement ceiling. Each graph
has at most 512 roots; runtime traversal has at most 65,536 filesystem entries
and 4,096 ELF bodies. Build declarations have at most 16 roots and 16 named
tools. Identity hashes stream through a fixed-size buffer rather than loading
large archives into memory.

Measured files must be regular files in an explicit Nix store root. Final file
opens use `NOFOLLOW`; lexical traversal, non-store paths, invalid store hashes
and unbounded names are refused. A streamed measurement checks the original
length, rejects short or extended content, and checks device, inode and change
metadata again after hashing. Generated documents are created once and synced.

Unit cases pin the existing CNP identity framing and reject short/extended
streams, foreign or subtracted root inventories, missing loader roots,
unscoped entries, duplicate/reordered paths and lexical traversal. Actual
source-package checks additionally execute the public control lifecycle and
controlled child tests. None of those cases substitutes for the independently
accepted native behavioral case population.

## Host acceptance boundary

The daemon installer consumes only a compile-time pinned installation
descriptor, independently remeasures the declared artifacts and graphs, and
enrolls the actual owned provider and companion processes. The host-selected
profile, authenticated session, original readiness and complete world
publication are separate requirements. Accepted class-specific behavioral
evidence remains a further conjunct, with its own source policy and complete
predeclared case population.

The observation-only `ReferenceController` archive can retain original
post-Hello control evidence for that independent witness. Its completeness
flag cannot turn this installation descriptor into a certificate. Bootstrap,
Hello and resume secrets remain outside the emitted source and evidence data.

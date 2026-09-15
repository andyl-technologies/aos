# Generation, store materialization, and publication

## Why generation happens before Hub indexing

Hub's native and Worker indexers consume a signed registry tree and byte
objects. They deliberately do not possess the package's Nix evaluation graph,
an evaluator, a Nix daemon, build tools, or permission to run package code.
Adding Nix evaluation to indexing would make Worker parity impossible, increase
the attack surface of registry ingestion, and make indexing dependent on an
ambient repository state rather than the signed package release.

Documentation therefore joins package publication as a producer-side artifact.
The flow is:

```text
ordinary package module declarations
                 |
                 v
canonical package ability projection
                 |
                 v
resolved signed PackageDocument
                 |
                 v
shared package validator + documentation projection
                 |
                 v
single-file Nix store documentation object
                 |
                 v
store realization + provenance + signed package TOML
                 |
                 v
NAR/narinfo/Git publication, then Hub indexing
```

Hub may regenerate presentation HTML or SQL search rows from the document. It
never regenerates the document itself.

## Restricted extraction

The package ability carrier evaluates the ordinary package module and emits one
canonical projection. Documentation generation receives its checked signed
`PackageDocument`, including:

- mechanically derived option declarations, types, values, visibility, and
  source provenance;
- package-owned interfaces, methods, outputs, implementations, requirements,
  and guarantees;
- ordinary package summary, license, homepage, source, version, and platform
  metadata.

It does not receive ambient `pkgs`, host facts, secrets, environment variables,
the network, arbitrary filesystem access, or builders. The evaluation may
discover documentation, but it does not create a store object through an
untrusted `builtins.derivation`. It returns a closed Nix value to the trusted
publisher.

The publisher validates that package contract through the shared Rust package
gate, derives the transient documentation view, enforces limits and
cross-artifact invariants, and encodes canonical JSON. A trusted fixed builder
or Nix store API then adds the single regular file to the store. Keeping
materialization after validation preserves the evaluation boundary.

## Authoring API

Ordinary option documentation continues to live with the option:

```nix
options.etcd.listenClientUrls = lib.mkOption {
  type = types.listOf types.str;
  description = "Client URLs on which etcd listens.";
  default = ["https://127.0.0.1:2379"];
  example = ["https://10.0.0.10:2379"];
};
```

Ability descriptions live on the ordinary interface, method, output,
implementation, requirement, and guarantee declarations in that same package
module. Package summary and project metadata live on the package derivation.
These constraints are normative:

- option descriptions/defaults/examples have one declaration site;
- ability descriptions have one declaration site;
- package reference data comes only from the checked signed package contract;
- concrete effects and realizations come only from checked deployment plans and
  provider observations;
- no documentation enrichment map can override or supplement declarations.

## Signed metadata association

`PlatformEntry` authenticates the documentation companion beside the package's
single ability contract:

```toml
[versions.platforms.x86_64-linux.documentation]
format = "aos.package-documentation/v1+json"
store_path = "/nix/store/...-nginx-1.30.4-aos-docs.json"
nar_hash = "sha256:..."
nar_size = 123456
document_sha256 = "sha256:..."
document_size = 122901
semantic_schema_sha256 = "sha256:..."
references = []
```

The Rust model is a `DocumentationArtifactMeta` with denied unknown fields and
the same store-path, NAR, reference, size, and feature validation applied to
other companion outputs. The signed Git commit authenticates the association
between package/version/platform and documentation identity. The store graph
authenticates its realization. Provenance includes the documentation NAR as a
named subject.

The document repeats package/version/platform, semantic digest, and selected NAR
digests for self-description. It does not repeat store paths or store-hash
components, which would create content-scanned store references. Publication
cross-checks the repeated fields; the signed metadata remains the selection
authority.

## Documentation versus module ABI and measurement

The signed package's option declarations are the sole option schema used by
resolution and documentation. The executable semantic identity covers
configuration meaning:

- declared paths and structured types;
- contribution rules;
- visibility and deprecation/replacement;
- provided and consumed ability semantics.

Descriptions and formatting do not affect executable interface, guarantee, or
provider identities. The signed documentation bytes can therefore change when
prose changes without changing those runtime identities. A semantic change
remains visible and comparable through the exact checked package declarations.

## NAR and cache rules

Documentation NARs use the ordinary Nix archive format and narinfo. To preserve
Worker simplicity, version 1 requires:

- `Compression: none` for the documentation NAR;
- one regular-file root;
- non-executable mode;
- no directory, symlink, device, or trailing archive member;
- empty references;
- the versioned NAR/document size limits.

This is not a new object protocol. It is a strict profile of the existing Nix
cache protocol. Native and Worker can validate it with a small shared streaming
decoder without linking a Nix daemon or compression C library. Future formats
may admit another compression only after both runtimes share a bounded decoder
and identical adversarial fixtures.

## Atomic publication

The publication session builds a typed object inventory containing the runtime
output, source derivation, config output, expose artifact, documentation object,
provenance, images, and any other required platform artifacts. It then:

1. validates all metadata and cross-object identities;
2. uploads store NARs and narinfos idempotently;
3. verifies object presence at the selected placement(s);
4. writes the package TOML and signed Git commit/release metadata;
5. advances the mutable publication/channel pointer only after the complete
   inventory is durable.

A retry reuses content-addressed objects. A signed package TOML that references
an absent or invalid documentation object is not indexable. A documentation NAR
uploaded without a signed reference is an ordinary unreachable cache object and
is eventually collected.

Static registry Web generation must also consume the authenticated document
rather than re-evaluating Nix. It may emit content-bearing no-JavaScript pages
and small JSON summaries, but those are mutable derivatives and clearly expose
the source document digest.

## Version and platform behavior

Documentation is selected at exact package version and platform because exposed
units, paths, defaults, capabilities, and availability may differ. Publishers
may deduplicate identical documentation objects across platforms naturally:
equal canonical bytes yield the same store object. They may not silently serve
one platform's document for another unless both signed entries name that exact
object.

A documentation-only correction may publish a new package release record that
reuses all runtime artifacts and selects a new documentation object. Release and
channel views expose that distinction. Mutable "latest docs" are never used to
describe an installed or historical release.

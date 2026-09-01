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
package/config/expose Nix declarations
                 |
                 v
restricted options/documentation evaluation
                 |
                 v
closed pure Nix value
                 |
                 v
trusted publisher validates + canonicalizes
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

The configuration publisher already performs an options-only evaluation to
derive declared paths and stable type descriptions. RFC-0016 extends the
restricted base library with documentation constructors and a pure export
function. The export receives only:

- the package's option declarations and their evaluated option metadata;
- authenticated config/expose declarations;
- package summary/license/homepage/source metadata;
- package-authored structured sections expressed as pure data;
- the exact platform and publication feature set.

It does not receive ambient `pkgs`, host facts, secrets, environment variables,
the network, arbitrary filesystem access, or builders. The evaluation may
discover documentation, but it does not create a store object through an
untrusted `builtins.derivation`. It returns a closed Nix value to the trusted
publisher.

The publisher converts that value to the shared Rust document model, enforces
limits and cross-artifact invariants, computes the semantic schema digest, and
encodes canonical JSON. A trusted fixed builder or Nix store API then adds the
single regular file to the store. Keeping materialization after validation
preserves the current dummy-store/config-evaluation boundary.

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

The implementation adds structured metadata only where `mkOption` cannot
express it, for example:

```nix
documentation = {
  summary = "Distributed, strongly consistent key-value service";
  sections.operations = [
    (lib.aosDoc.paragraph "Member identity is stable across restart.")
  ];
  options.etcd.listenClientUrls.activation = {
    kind = "restart";
    units = ["etcd.service"];
  };
};
```

The exact API is an implementation detail, but these constraints are
normative:

- option descriptions/defaults/examples have one declaration site;
- runtime facts are derived from expose/config metadata whenever possible;
- authored enrichment cannot override authenticated paths, types, ownership,
  credentials, or runtime permissions;
- prose is structured data, not embedded Markdown files;
- shared constructors live in the injected AOS base library so package config
  roots do not import an ambient helper package.

## Signed metadata association

`PlatformEntry` gains a generic optional documentation field rather than adding
it only inside `ConfigModuleMeta`:

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

The existing `declares` and `declaration_schema` remain the small resolver index
used before fetching a documentation object. The documentation's rich option
model must exactly refine that index. This avoids making resolution depend on a
large optional presentation artifact.

The semantic schema digest covers configuration meaning:

- declared paths and structured types;
- ownership/contribution interfaces and ABI;
- visibility, availability, deprecation/replacement;
- credential contracts;
- declared activation/runtime effects.

Descriptions, explanatory sections, examples, source line numbers, formatting,
and external links do not affect that digest. Neither the documentation object
nor its prose digest is included in the runtime `root_digest`, config publish
binding, unit fingerprint, or TPM measurement. A release can therefore correct
documentation without causing a service restart. A semantic change remains
visible and comparable, but the module ABI is changed only under its existing
compatibility rules.

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

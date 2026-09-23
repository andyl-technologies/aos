# Canonical documentation document

## Format choice

The initial wire format is canonical UTF-8 JSON with the media/schema identifier
`aos.package-reference/v1+json`. JSON is selected over CBOR and Protobuf
because it is directly constructible from restricted Nix values, supported by
Serde and browsers, inspectable with ordinary AOS tools, and usable as an offline
interchange format without generated bindings.

Canonicalization uses one normative AOS implementation and fixes object-key
order, integer representation, string escaping, Unicode handling, absence versus
`null`, and trailing newline behavior. Producers do not sign arbitrary JSON that
happens to deserialize to the model. They validate a pure value, encode the one
canonical byte representation, hash those bytes, and store those exact bytes.

The schema is closed: unknown fields fail validation. Additive format evolution
uses a new advertised schema version or a feature explicitly understood by the
reader. A document may not contain floating-point numbers, arbitrary HTML,
Markdown, executable expressions, or external includes.

## Store object shape

Each document is the root regular file of an independent store object:

```text
/nix/store/<hash>-<package>-<version>-aos-docs.json
```

The root must be one non-executable regular file. It has no store references and
therefore an empty `References` set. The object is deliberately separate from
the runtime output, config module, and expose artifact:

- editorial changes do not rebuild a large runtime payload;
- packages without a config module can still document commands, files, and
  package purpose;
- a package version/platform has one signed documentation selection;
- the object can be cached, retained, and garbage-collected with ordinary Nix
  machinery.

The document must not contain exact Nix store paths or store-hash components.
Nix reference scanning would otherwise turn those explanatory strings into
retention edges. The signed platform metadata and API view resource carry exact
store paths; the document may repeat non-reference NAR/content digests for
cross-checking.

The first implementation caps the uncompressed NAR and package reference at 12 MiB,
with tighter per-field and per-collection limits. Raising the cap is a format
policy change, not an operator-tunable way to bypass Worker resource limits.

## Top-level model

The following example is illustrative. The machine-readable schema is generated
from the authoritative Rust model; it is not maintained as a second checked-in
catalog.

```json
{
  "schema": "aos.package-documentation/v1",
  "package": {
    "name": "nginx",
    "version": "1.30.4",
    "platform": "x86_64-linux",
    "summary": "HTTP and reverse proxy service",
    "homepage": "https://nginx.org/",
    "license": "BSD-2-Clause"
  },
  "identity": {
    "semantic_schema_sha256": "sha256:...",
    "runtime_nar_hash": "sha256:...",
    "source_nar_hash": "sha256:..."
  }
}
```

The package metadata remains a nested value inside the one signed package
reference. The checked package fixed point supplies its ability reference:

```json
{
  "schema": "aos.package-reference/v1",
  "document": { "schema": "aos.package-documentation/v1" },
  "ability_reference": { "schema": "aos.package-ability-reference/v1" }
}
```

The complete values occupy the abbreviated fields above. The validator checks
their package/version agreement. Readers derive option and method rows from
`ability_reference`; the signed object has no copied schema-row collection.

## Structured prose

Descriptions and package-authored conceptual sections use a small structured
block model rather than Markdown. Version 1 supports:

- paragraphs containing plain text and explicit inline code/link spans;
- ordered and unordered lists;
- code blocks with a declared language and copy-safe bytes;
- notes with `info`, `warning`, or `security` severity;
- definition tables with plain-text terms and structured block bodies.

Links have an explicit kind: `package`, `option`, `section`, `source`, or
validated `https`. Package/option links resolve within the selected registry and
version by default. Renderers escape all text and own all markup. Script, style,
raw HTML, data URLs, event attributes, and package-selected UI components are
not representable.

This model is intentionally less expressive than CommonMark. It covers reference
documentation while ensuring terminal, man, Web, JSON, and editor renderers show
the same content without embedding a general markup interpreter at every trust
boundary.

## Option path and type algebra

An option path is an array of exact segments. Wildcard/submodule positions use
an explicit path-segment variant in the schema; the human `display_path` is
derived and checked, never parsed as authority. This prevents ambiguity around
dots, quotes, and generated attribute names.

The shared option type algebra is recursive and closed. It covers booleans,
integers, strings, enums, paths, packages, and typed artifact/resource/provider
references; optional values; lists and maps with explicit bounds and ordering;
fixed `record` values whose keys are package-local identifiers; and
`documentRecord` values whose bounded exact field names may include
configuration-format names such as `@type`. `taggedUnion` carries an explicit
tag, while `disjointUnion` preserves raw values only when each variant has a
distinct top-level JSON kind. Standard Nix-only forms remain representable for
ordinary module options, but a public portable ability option cannot use an
opaque type.

Every option also carries the module engine's stable `type_signature`.
Publication validates the path, rich type, signature, value examples,
visibility, and source provenance as one signed `PackageOptionDeclaration`.
There is no second `declares` inventory or documentation type mirror.

## Option fields

Each option row mechanically derived from the signed package reference records:

- exact path segments and derived display path;
- structured type and stable type signature;
- authored description;
- safe literal default, `default_text`, or explicit absence;
- safe example, when one is useful;
- public, internal, or hidden visibility;
- read-only and deprecation state, with replacement option when applicable;
- contribution boundary;
- source-relative declaration path and optional line/attribute locator.

Static option documentation does not predict activation effects. Deployment
tools derive concrete effects from the checked desired, binding, and effect
plans for the selected environment.

`default_text` describes computed or environment-dependent behavior without
serializing a value. A literal default/example is admitted only when it is
bounded, deterministic, JSON-compatible, carries no Nix store context, and does
not contain or derive from credentials. Function defaults and lazy values are
never forced merely to improve documentation.

## Ownership and contribution

The signed package reference explains authenticated configuration authority without
becoming that authority. Each option belongs to the package whose authenticated
module declares it and retains the exact evaluated declaration's contribution
flag and source provenance.

Publication derives these fields from the signed package fixed-point projection
and rejects any disagreement. A contributor cannot claim documentation
ownership or mark a forbidden path extensible through prose.

## Abilities and deployment observations

`PackageAbilityReference` carries package-owned interfaces, implementations,
requirements, and guarantees from the checked package contract. The package
reference retains that exact projection; readers derive one method row for each
exported interface method, including its exact `InterfaceKey` and complete
provider-neutral `MethodDescriptor`. Implementations and requirements carry
their own authored descriptions. Guarantee documentation carries the authored
name, version, semantics, and description; executable identity derives from
name, version, and semantics only.

Concrete services and other realized resources belong to a deployment view.
That view renders only checked resource revisions and provider-produced
observations from the shared inspection graph, including their controller and
provenance. Package reference generation never infers a unit, listener, path,
or activation action from package names, option prefixes, expose metadata, or a
documentation-only inventory. When no checked plan or observation is present,
the deployment view omits the missing realization details.

## Package sections and source identity

Packages without public options still publish package metadata and integrity
identity. Their checked ability reference remains separate, and their tooling
response may contain empty derived option and method lists. Any explanatory
package prose is authored once through the ordinary package module fixed point.

Source locators are repository-relative paths plus optional stable attribute
locations. Absolute authoring-worktree paths are forbidden. Hub may link them to
an authenticated source browser only when the signed release identifies a
repository/commit; otherwise it displays the locator as provenance, not as a
fabricated URL.

## Completeness rules

Publication fails when:

- a signed public declaration has no public description;
- a documented option is not in the signed declaration schema;
- paths or type signatures disagree;
- ownership or contribution statements disagree with signed metadata;
- package-owned interface, method, output, implementation, requirement, or
  guarantee documentation is incomplete or names an absent declaration;
- a public enum value or submodule field is undocumented;
- a literal default/example is unsafe or contains store context;
- the document exceeds limits or is not canonical;
- a public package opts into the required documentation feature but omits the
  object.

Consumers that cannot validate the advertised format reject it rather than
showing stale or partial reference material.

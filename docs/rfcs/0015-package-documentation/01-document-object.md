# Canonical documentation document

## Format choice

The initial wire format is canonical UTF-8 JSON with the media/schema identifier
`aos.package-documentation/v1+json`. JSON is selected over CBOR and Protobuf
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

The first implementation should cap the uncompressed NAR and document at 4 MiB,
with tighter per-field and per-collection limits. Raising the cap is a format
policy change, not an operator-tunable way to bypass Worker resource limits.

## Top-level model

The following example is illustrative; the implementation phase supplies a
closed checked schema and canonical fixture corpus.

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
    "config_module_nar_hash": "sha256:...",
    "expose_artifact_nar_hash": "sha256:...",
    "source_nar_hash": "sha256:..."
  },
  "sections": [
    {
      "id": "overview",
      "title": "Overview",
      "blocks": [
        { "kind": "paragraph", "text": "Configure virtual hosts and upstreams." }
      ]
    }
  ],
  "options": [
    {
      "path": ["nginx", "virtualHosts", "<name>", "listenPort"],
      "display_path": "nginx.virtualHosts.<name>.listenPort",
      "type": { "kind": "port" },
      "type_signature": "unsigned 16-bit TCP port",
      "description": [
        { "kind": "paragraph", "text": "Port on which this virtual host listens." }
      ],
      "default": { "kind": "literal", "value": 80 },
      "example": { "kind": "literal", "value": 8080 },
      "visibility": "public",
      "owner": { "package": "nginx", "root": "nginx", "interface_abi": 1 },
      "contributable": true,
      "activation": { "kind": "reload", "units": ["nginx.service"] },
      "source": { "path": "pkgs/networking/_nginx-config/module.nix" }
    }
  ],
  "runtime": {
    "units": [],
    "listeners": [],
    "managed_paths": [],
    "config_artifacts": [],
    "credentials": [],
    "capabilities": [],
    "confinement": null
  }
}
```

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

The type algebra is recursive and closed:

- `bool`, signed/unsigned `integer`, `string`, `port`, `path`, `duration`,
  `cidr`, and `opaque-reference` scalars;
- `enum` with documented values;
- `list`, `set`, and `attrs-of` containers;
- fixed-field `submodule` records with open or closed additional attributes;
- `nullable` and bounded `one-of` unions;
- constraints such as integer range, string pattern/length, collection size,
  and uniqueness.

Every option also carries the stable legacy `type_signature` already used by
the resolver's declaration schema. Publication verifies that the rich type
projects to that signature and that option paths exactly match the signed
`declares` inventory. The rich document cannot widen the configuration
authority granted by `ConfigModuleMeta`.

## Option fields

Each option records:

- exact path segments and derived display path;
- structured type and stable type signature;
- structured description;
- safe literal default, `default_text`, or explicit absence;
- safe example, when one is useful;
- public, internal, or hidden visibility;
- read-only and deprecation state, with replacement option when applicable;
- package/root owner, root interface ABI, and contribution boundary;
- package version, platform, image/module ABI, or feature availability;
- expected activation effect: none, re-evaluate, reload, restart, recreate,
  reboot, or package-specific operation, including affected units;
- source-relative declaration path and optional line/attribute locator.

`default_text` describes computed or environment-dependent behavior without
serializing a value. A literal default/example is admitted only when it is
bounded, deterministic, JSON-compatible, carries no Nix store context, and does
not contain or derive from credentials. Function defaults and lazy values are
never forced merely to improve documentation.

## Ownership and contribution

The document explains authenticated configuration authority without becoming
that authority. It records:

- private package roots;
- exclusive shared-root owners and interface ABI;
- exact contributable wildcard subpaths;
- package contributions and their required owner ABI;
- artifacts, units, users, groups, and capabilities the module may create.

Publication derives these fields from signed `ConfigModuleMeta` and rejects any
disagreement. A contributor cannot claim documentation ownership or mark a
forbidden path contributable through prose.

## Runtime surface

The runtime section is derived from signed expose metadata and config artifacts,
then enriched by package-authored descriptions. It records:

- services, sockets, timers, paths, mounts, targets, and their relationships;
- listeners, protocols, ports, and declared network mode;
- state, cache, logs, runtime, and configuration paths;
- configuration artifacts and validation/reload behavior;
- credential **names**, purpose, destination, accepted opaque-reference kinds,
  required/optional feature gate, mode, and restart/reload effect;
- capability provides/uses, kernel/module/sysctl/firewall requirements, and
  confinement summary;
- package lifecycle effects for enable, disable, upgrade, rollback, and remove.

Credential values and resolved source locations are never present. The Web
composer and LSP may suggest the shape
`system-credential:<name>` but cannot read or preview the credential.

## Package sections and source identity

Packages without a config module still publish package metadata, commands,
runtime/dependency summaries, integrity identity, and optional structured
sections. Configurable packages may add overview, examples, migration notes,
operational cautions, and troubleshooting sections as Nix data beside their
module.

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
- ownership, contribution, credential, artifact, or runtime statements disagree
  with signed metadata;
- a public enum value or submodule field is undocumented;
- a literal default/example is unsafe or contains store context;
- the document exceeds limits or is not canonical;
- a public package opts into the required documentation feature but omits the
  object.

The gate may initially permit legacy packages with summary-only generated
documents. Once a package publishes `requires-features =
["package-documentation-v1"]`, consumers that cannot validate the format reject
it rather than showing stale or partial reference material.

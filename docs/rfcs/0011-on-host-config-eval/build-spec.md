# Build spec — field-level interface & schema contracts

Decision-free implementation contracts for RFC-0011, written against the locked [decisions](decisions.md). Each section is a drop-in contract: schemas, signatures, algorithms. Pairs with [`acceptance-criteria.md`](acceptance-criteria.md) (definition-of-done per checklist item).


---

# Data model — manifest, config output, system roots, module_abi

Grounding complete. Here is the drop-in RFC markdown.

---

# Data model — the field-level contract

This document is the **implementation contract** for the RFC-0011 data model. It
specifies, with no remaining choices, three artifacts:

1. the **`config-manifest/v1`** eval output (`gen-N/manifest.json`);
2. the second **`config`** package output and its `PackageMeta` metadata
   (`ConfigOutputMeta` + `ConfigModuleMeta`) and its feature gate;
3. the per-package `ConfigModuleMeta` carried by name in `registry.toml`
   (`owns_roots` / `provides_capabilities` / `module_abi_compat = { min, max }`),
   the locally-derived **`SystemRoots`** structure it feeds, and their resolver
   gate.

All Rust types live in `crates/aos-package/src/types.rs` alongside the existing
`PackageMeta` family and follow its conventions: `#[serde(deny_unknown_fields)]`
on closed structs, `#[serde(default, skip_serializing_if = …)]` on optional
fields, snake_case field identifiers with explicit `rename` only where the wire
key differs. All hashes are `"sha256:" + lowercase-hex(32 bytes)` unless stated
otherwise. "Store-path hash" means the 32-character nixbase32 component of a
`/nix/store/<hash>-name` path.

## 0. Canonicalization and hashing (normative, shared by all three)

Every hash in this document is computed over a **canonical byte form**. There is
exactly one canonicalization, used everywhere:

> **Canonical JSON (CJSON).** UTF-8; object members sorted by unicode code point
> of the key; no insignificant whitespace (no spaces, no newlines); arrays kept
> in declared order (never reordered); integers as shortest decimal with no
> leading zeros and no `+`; strings with minimal RFC 8259 escaping
> (`"`, `\`, and `U+0000..U+001F` only, lowercase `\u` hex); no trailing newline.

`hash_cjson(v) = "sha256:" + hex(sha256(cjson_bytes(v)))`. The manifest on disk
(`manifest.json`) MAY be pretty-printed for humans; **its hash is always taken
over its CJSON re-serialization**, never over the on-disk bytes. This makes
`manifest_hash` independent of formatting.

A hash over a *set of store paths* is defined as
`hash_cjson([ [store_path, nar_hash], … ] sorted by store_path)` — the array is
sorted before hashing so set membership, not enumeration order, determines the
value.

---

## (a) `config-manifest/v1`

The manifest is the sole contract between the pure on-host evaluation and the
imperative materializer. It is **pure data**: no derivations, no store-path
forcing, no secrets (credentials appear only as handles). It is persisted at
`gen-N/manifest.json`.

### 1.1 JSON shape

```json
{
  "schema": "aos.config-manifest/v1",
  "etc": {
    "systemd/system/redis.service": { "kind": "text", "text": "[Unit]\n…", "mode": "0644" },
    "systemd/system/multi-user.target.wants/redis.service": {
      "kind": "symlink", "target": "/etc/systemd/system/redis.service"
    },
    "ssl/certs/ca-bundle.crt": { "kind": "store-symlink", "target": "/nix/store/<hash>-ca-bundle/…" }
  },
  "units": {
    "redis.service": {
      "action": "restart",
      "credentials": ["redis-join-token"],
      "enable": true
    }
  },
  "jobScripts": {
    "redis.service:ExecStartPre.0": { "text": "#!/bin/sh\nexec mkdir -p /var/lib/redis\n", "mode": "0755" }
  },
  "users": [
    { "name": "redis", "uid": 991, "group": "redis", "gid": 991,
      "home": "/var/lib/redis", "shell": "/sbin/nologin", "system": true,
      "description": "Redis service user", "supplementaryGroups": [] }
  ],
  "presets": [
    { "unit": "redis.service", "policy": "enable", "source": "redis" }
  ],
  "storePaths": [
    "/nix/store/<hash>-redis-8.2",
    "/nix/store/<hash>-curl-8.12"
  ],
  "module_abi": 1,
  "inputs": {
    "base_lib":       { "store_path": "/nix/store/<hash>-aos-base-lib", "abi_hash": "sha256:…", "module_abi": 1 },
    "evaluator":      { "store_path": "/nix/store/<hash>-nix-2.24.12", "store_hash": "sha256:…" },
    "config_modules": { "closure_hash": "sha256:…", "count": 2 },
    "host_nix":       { "content_hash": "sha256:…", "trust_mode": "platform", "platform": "aws", "signer_key": null },
    "instance_facts": { "facts_hash": "sha256:…", "platform": "aws" }
  }
}
```

### 1.2 Rust schema

```rust
/// Manifest schema tag understood by this crate.
pub const CONFIG_MANIFEST_SCHEMA: &str = "aos.config-manifest/v1";

/// The pure-data output of one on-host config evaluation.
///
/// Produced by `aos-eval.service`, persisted at `gen-N/manifest.json`, and
/// consumed by the materializer. Contains no derivations and no secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigManifest {
    /// Always [`CONFIG_MANIFEST_SCHEMA`]; rejected otherwise.
    pub schema: String,
    /// `/etc` tree keyed by path *relative to `/etc`* (no leading slash).
    pub etc: BTreeMap<String, EtcEntry>,
    /// Per-unit post-swap reconcile actions, keyed by unit name.
    pub units: BTreeMap<String, UnitAction>,
    /// Rendered job-script texts (F2-A), keyed `"<unit>:<phase>.<index>"`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub job_scripts: BTreeMap<String, JobScript>,
    /// Declared users, in resolver order (deduplicated by `name`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<ManifestUser>,
    /// systemd preset decisions, in resolver order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presets: Vec<PresetEntry>,
    /// Store paths whose closures the generation pins (GC roots).
    pub store_paths: Vec<String>,
    /// Shared-tree ABI this manifest was evaluated against. Equals
    /// `inputs.base_lib.module_abi`; recorded as `module_abi_pinned`.
    pub module_abi: u32,
    /// The five content-addressed eval inputs (reproducibility contract).
    pub inputs: ManifestInputs,
}
```

#### `etc`

Key = path relative to `/etc`, normalized: no leading `/`, no `.`/`..`
components, `/`-separated. Keys MUST be unique (it is a map). Value:

```rust
/// One entry in the rendered `/etc` tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
pub enum EtcEntry {
    /// Inline regular file. `text` is the verbatim content (UTF-8).
    Text {
        text: String,
        /// Octal permission string, exactly 4 digits, e.g. `"0644"`.
        mode: String,
    },
    /// Relative/absolute symlink into the rendered `/etc` tree itself.
    Symlink { target: String },
    /// Symlink into the Nix store (the closure pins it via `store_paths`).
    StoreSymlink { target: String },
}
```

Rules: `mode` matches `^0[0-7]{3}$`. `Symlink.target` is an `/etc`-relative or
absolute-under-`/etc` path. `StoreSymlink.target` MUST start with the store dir
and its store-path prefix MUST appear in `store_paths`. (The legacy
`"mode": "symlink"` sentinel from the architecture sketch is replaced by the
tagged `kind`.)

#### `units`

```rust
/// Post-swap reconcile decision for a single unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitAction {
    /// What reconcile does when this unit's inputs changed.
    pub action: UnitReconcileAction,
    /// systemd credential *handles* (names) this unit consumes. Names only —
    /// never values. Resolved from the credstore at activation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
    /// Operator-resolved enable state (install ≠ enable). `true` only when
    /// `{service}.enable` was set at tier ≤ 100 in the fixpoint.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enable: bool,
}

/// Reconcile verb for a unit whose config changed across generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitReconcileAction {
    /// Restart the unit.
    Restart,
    /// Reload, falling back to restart if the unit declares no reload.
    Reload,
    /// Materialize only; do not touch the running unit.
    None,
}
```

`UnitReconcileAction` is the manifest-level mirror of the existing
`ConfigReloadPolicy` (`types.rs:672`); values map 1:1
(`restart`/`reload`/`none`). Keys in `units` need not appear in `etc` (a unit
may reconcile because a referenced store path changed).

#### `jobScripts` (F2-A)

Key grammar (normative): `"<unit>:<phase>.<index>"` where `<unit>` is a full
unit name (e.g. `redis.service`), `<phase>` ∈
`{ ExecStartPre, ExecStartPost, ExecReload, ExecStop, ExecStopPost, Script }`,
and `<index>` is the 0-based position of the directive within that phase list.
`Script` (the `script=` option) always uses index `0`.

```rust
/// One rendered job-script body (F2-A).
///
/// The materializer writes `text` to a generation-local path and rewrites the
/// owning `ExecStart*=` directive to point there. The P0 byte-identical gate
/// compares `text` semantically, not the embedded path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobScript {
    /// Verbatim script content, including its `#!` shebang line.
    pub text: String,
    /// Octal mode, exactly 4 digits; always `"0755"` for executables.
    pub mode: String,
}
```

#### `users`

```rust
/// A user the generation must ensure exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestUser {
    pub name: String,
    /// Fixed uid; `None` means allocate from the system range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    pub group: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    pub home: String,
    pub shell: String,
    /// System (true) vs human (false) account.
    pub system: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supplementary_groups: Vec<String>,
}
```

`users` is a `Vec` (preserves resolver order for stable diffs) but `name` is a
key: duplicates are a manifest error. The materializer is responsible for
group creation implied by `group`/`supplementary_groups`.

#### `presets`

```rust
/// A systemd preset decision contributed by a package or the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetEntry {
    /// Unit the preset applies to.
    pub unit: String,
    /// `enable` or `disable`.
    pub policy: PresetPolicy,
    /// Provenance: the package root (or `"host.nix"`) that set it.
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PresetPolicy { Enable, Disable }
```

#### `storePaths`

`Vec<String>` of absolute store paths, **sorted by path**, deduplicated. This
is the GC-root set the config-gen pins (manifest *outputs*). It does **not**
include config-module *source* NARs or `host.nix` — those are pinned separately
by the `gen-N/cfgsrc/<hash>` root (see `generations.md`, M-gc-inputs).

#### `module_abi`

`u32`. Equals `inputs.base_lib.module_abi`. Persisted by the config-gen record
as `module_abi_pinned` and checked by the rollback pin.

#### `inputs` — the reproducibility contract

```rust
/// The five content-addressed inputs that fully determine the manifest.
///
/// `manifest = eval(base_lib, evaluator, config_modules, host_nix, facts)`.
/// A verifier reproduces the generation from these alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestInputs {
    pub base_lib: BaseLibInput,
    pub evaluator: EvaluatorInput,
    pub config_modules: ConfigModulesInput,
    pub host_nix: HostNixInput,
    pub instance_facts: InstanceFactsInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseLibInput {
    /// Store path of the base lib shipped in the running image.
    pub store_path: String,
    /// Hash binding the shared-option *schema* and the ABI integer (below).
    pub abi_hash: String,
    /// The running image's `module_abi`.
    pub module_abi: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorInput {
    /// Store path of the eval binary (⊂ measured UKI).
    pub store_path: String,
    /// Store-path hash re-expressed as `"sha256:<hex of the 20 decoded bytes>"`.
    pub store_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigModulesInput {
    /// Registry whose signed release selected the module set.
    pub registry: Option<String>,
    /// Semver release tag accepted by `verify_tag_chain`.
    pub release_tag: Option<String>,
    /// Short fingerprint of the roster key that signed the tag.
    pub tag_signer_key: Option<String>,
    /// Hash of the exact signed `store/` subgraphs consumed below.
    pub realization: Option<String>,
    /// Set-hash over every resolved package's `config` output NAR (below).
    pub closure_hash: String,
    /// Number of config modules in the resolved set.
    pub count: usize,
    /// Exact config-output store paths, sorted by path.
    pub store_paths: Vec<String>,
    /// Canonical NAR hashes corresponding positionally to `store_paths`.
    pub nar_hashes: Vec<String>,
    /// Package identities corresponding positionally to `store_paths`.
    pub package_names: Vec<String>,
    /// ABI compatibility evidence corresponding positionally to `store_paths`.
    pub module_abi_compat: Vec<ModuleAbiCompat>,
    /// Shared-root authorization evidence corresponding positionally to `store_paths`.
    pub authorizations: Vec<PackageAuthorization>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostNixInput {
    /// `sha256` of the policy-accepted `host.nix` bytes.
    pub content_hash: String,
    /// Selected policy: `"platform"`, `"signed"`, or the no-input `"image"` arm.
    pub trust_mode: String,
    /// Control-plane identity for platform mode.
    pub platform: Option<String>,
    /// Trusted configuration-key fingerprint for signed mode.
    pub signer_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceFactsInput {
    /// `sha256` of the canonical `host.facts.*` tree (below).
    pub facts_hash: String,
    /// Platform that supplied the facts (`aws`, `gcp`, …). Recorded, not signed.
    pub platform: String,
}
```

**Canonicalization + hashing of each input (normative):**

| Input | What is hashed |
|-------|----------------|
| `base_lib.abi_hash` | `hash_cjson({ "abi": <module_abi:u32>, "schema": [ [path, type_sig], … ] })` where the schema array is the result of an **options-only eval** of the base lib (no `config` forced), one `[option-path, type-signature-string]` pair per declared shared-tree option, sorted by `option-path`. `type_sig` is `options.<path>.type.description`. |
| `evaluator.store_hash` | the evaluator store path's hash component decoded from nixbase32 to its 20 bytes, re-encoded `"sha256:"+hex`. (`store_path` carries the same identity; both recorded for cross-checking.) |
| `config_modules.closure_hash` | set-hash (§0) over `[ [config_output_store_path, config_output_nar_hash], … ]` for every resolved package, taken from each package's `ConfigOutputMeta`. Sorted; identity is the *set*. |
| `config_modules.realization` | For each selected config-output root, hash the canonical JSON object mapping every reachable IA hash to the canonical signed `store/` realization record. Then set-hash (§0) the sorted `[config_output_store_path, subtree_hash]` pairs. This commits to the exact consumed signed graph, including non-package dependencies. Absent only when `count == 0`. |
| `host_nix.content_hash` | `"sha256:"+hex(sha256(verified_host_nix_bytes))` — the exact bytes the resolver verified the operator signature over, before any parsing. |
| `instance_facts.facts_hash` | `hash_cjson(resolved_host_facts_tree)` — the `host.facts.*` subtree as resolved into the fixpoint (hostname, MAC→interface map, disk-id map, ssh_authorized_keys, …), serialized as a nested JSON object and CJSON-hashed. Facts are recorded, not signed. |

For a non-empty config-module set, all four signed-release identity fields are
required and every selected module must come from that one release. For the
canonical empty set, all four are absent, all parallel arrays are empty, and
`closure_hash = hash_cjson([])`; a mixture of empty and non-empty evidence is
invalid.

`manifest_hash` (used as `generation_id` input and in the attestation bundle) =
`hash_cjson(manifest)` over the whole `ConfigManifest` value.

---

## (b) The second `config` package output and its metadata

### 2.1 Feature gate

```rust
/// Registry feature flag for the RFC-0011 second `config` package output and
/// its config-module metadata (`ConfigOutputMeta` + `ConfigModuleMeta`).
pub const FEATURE_CONFIG_MODULE_V1: &str = "config-module-v1";
```

Appended to `SUPPORTED_PACKAGE_FEATURES` (`types.rs:71`). Gating rule, enforced
in `validate_supported_package_meta_with` (`types.rs:1169`):

- If `PackageMeta.config_module.is_some()` → `require_feature(meta,
  FEATURE_CONFIG_MODULE_V1)?`.
- A `config_module` block makes the package privileged metadata: it MUST be
  backed by DSSE provenance. Extend `rfc0001_metadata_requires_provenance`
  (`types.rs:828`) so `config_module.is_some()` forces
  `attestation.provenance.is_some()`; otherwise bail
  (`"…uses config-module metadata without attestation provenance"`).
- A package MAY carry `config_module` without `expose`; the two are
  independent. A `config_module` whose `config_output` references a store path
  that fails the publish-time *no-derivation* lint (architecture.md §Stage-1) is
  a **publish failure**, surfaced as `validate_config_module_meta`.

### 2.2 `PackageMeta` additions

Add to `PackageMeta` (`types.rs:513`), after `expose_artifact`:

```rust
    /// RFC-0011 config-only module output and its declared interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_module: Option<ConfigModuleMeta>,
```

### 2.3 `ConfigOutputMeta`

The `config` output is a store path NAR carrying the package's config-only Nix
module (`module.nix` at its root) plus any relative-imported private `.nix`.
Its metadata mirrors `ExposeArtifactMeta` (`types.rs:755`):

```rust
/// Store metadata for a package's second `config` output (RFC-0011).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigOutputMeta {
    /// Store path of the `config` output (contains `module.nix` at its root).
    pub store_path: String,
    /// Hash of the uncompressed `config`-output NAR: `"sha256:…"`.
    pub nar_hash: String,
    /// Uncompressed NAR size in bytes.
    pub nar_size: u64,
    /// Store-path hashes of the `config` output's *direct* references.
    /// MUST be empty of any `.drv` and MUST NOT include the `out` closure —
    /// the module references binaries as string paths, pinned by the manifest's
    /// `store_paths`, not by a config-output reference edge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}
```

Validation (`validate_config_output_meta`): `store_path` absolute and a valid
store path; `nar_hash` starts `sha256:`/`sha256-`; every entry of `references`
is a store-path hash; **no reference may name a `.drv`** (publish lint). These
mirror `validate_expose_artifact_meta` (`types.rs:1472`).

---

## (c) System roots, ABI compat, and the resolver gate

### 3.1 Per-package config-module metadata

```rust
/// RFC-0011 config-module interface declared by a package.
///
/// Carries the second `config` output, the declared option surface (the
/// package's own `declares`, computed by options-only eval at publish), the
/// shared roots it owns or contributes to, and its base-lib ABI compatibility
/// range. This metadata is looked up **by name** from `registry.toml`; nothing
/// registry-published aggregates it into a cross-package index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigModuleMeta {
    /// The `config` output store metadata.
    pub config_output: ConfigOutputMeta,
    /// Base-lib ABI range this module is compatible with (inclusive).
    pub module_abi_compat: ModuleAbiCompat,
    /// Option paths this module *declares*, computed by an options-only eval in
    /// isolation. Sorted, deduplicated. Retained as per-package metadata for
    /// publish-side lints and `aos show`; it is **not** aggregated into any
    /// cross-package registry index.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declares: Vec<String>,
    /// Shared roots this module declares exclusive ownership of (e.g.
    /// `firewall`, `nginx`). Each carries its own interface ABI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owns_roots: Vec<OwnedRoot>,
    /// Foreign shared roots this module contributes into, restricted to the
    /// owner-declared contributable sub-paths (F3-B).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributes: Vec<RootContribution>,
    /// Capability tokens this module *sets*, e.g.
    /// `system.capabilities.dns-resolver`. Contributed to the installed-set
    /// capability map in `SystemRoots` at resolve time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides_capabilities: Vec<String>,
}

/// Inclusive base-lib ABI compatibility range for a config module.
///
/// The resolver refuses the module unless `min <= running_image_abi <= max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAbiCompat {
    /// Lowest `module_abi` this module supports.
    pub min: u32,
    /// Highest `module_abi` this module supports.
    pub max: u32,
}

/// A shared root a package owns, plus its own interface ABI and the sub-paths
/// non-owners may contribute into (F3-B capability-scoped surface).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedRoot {
    /// Root segment, e.g. `firewall`, `nginx`.
    pub root: String,
    /// Independent interface ABI for this shared root.
    pub interface_abi: u32,
    /// Owner-declared contributable sub-paths (relative to the root), e.g.
    /// `virtualHosts`, `upstreams`. Owner-only paths (`enable`, globals) are
    /// excluded. A non-owner write outside these is rejected at resolve time
    /// against the installed owner's contributable surface in `SystemRoots`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributable: Vec<String>,
}

/// A foreign-root contribution declared by a non-owner package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootContribution {
    /// The shared root being contributed into, e.g. `nginx`.
    pub root: String,
    /// Sub-paths (relative to `root`) this package writes; each MUST be within
    /// the owner's `contributable` set, checked at resolve.
    pub paths: Vec<String>,
}
```

`module_abi_compat` is validated `min <= max`. `ModuleAbiCompat` is the RFC-0011
analogue of the `SbatEntry` revocation floor (`types.rs:3016`): a monotonic
integer band, gated pre-eval.

### 3.2 System roots (`SystemRoots`) — derived on-host, never published

There is **no registry-published cross-package index.** Shared-root ownership is an
attribute of the **system** (the composed image/toplevel plus the installed
set), not of the registry. The resolver derives a `SystemRoots` structure at
resolve time and consults it in place of any fetched index. It is computed
locally, held in memory for the duration of a `switch`, and never serialized to
a registry repo.

`SystemRoots` maps each **shared** root (`firewall`, `dns`, `nginx`, …) to the
single installed package that owns it, and each capability token to the
installed packages that set it. It is built from exactly two local sources:

1. the **base-lib / image manifest**'s bundled roots (the structural tree the
   in-image module library ships, `manifest.inputs.base_lib`); and
2. the **installed set**'s per-package `ConfigModuleMeta`, read by name from
   `registry.toml`: each package's `owns_roots` (→ root owners) and
   `provides_capabilities` (→ capability setters).

Private roots (`{pkg}.*`) are **not** members of `SystemRoots`: their ownership
is structural (root segment = package name) and is resolved by a registry
by-name lookup, not by this map (§3.3, §4).

```rust
/// Locally-derived map of shared roots to their installed owner and of
/// capability tokens to their installed setters, assembled at resolve time.
///
/// Built from the base-lib/image manifest's bundled roots and the installed
/// set's [`ConfigModuleMeta`] (`owns_roots` / `provides_capabilities`). Held in
/// memory for one `switch`; **never published to a registry, never fetched.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRoots {
    /// Shared root segment (`firewall`, `nginx`) → its single installed owner.
    /// Two installed packages owning the same root is a hard error at build
    /// time, citing both (owned-root exclusivity is per-system).
    pub roots: BTreeMap<String, RootOwner>,
    /// Capability token → the installed packages that *set* it (the union of
    /// every installed package's `provides_capabilities`).
    pub capabilities: BTreeMap<String, Vec<CapabilitySetter>>,
}

/// The installed package that owns a shared root, with the ABI and contribution
/// surface the resolver enforces against.
///
/// `module_abi_compat` and `config_output` are **pinned from the installed
/// owner** at build time — never re-queried from the registry at selection — so
/// the fixpoint fetches and ABI-gates exactly the config output the system
/// owns, immune to a newer version appearing in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOwner {
    /// Owning package name.
    pub package: String,
    /// Owning package version.
    pub version: String,
    /// Owning package target platform.
    pub platform: String,
    /// Independent interface ABI for this shared root (from `OwnedRoot`).
    pub interface_abi: u32,
    /// The owner's base-lib ABI band; selection is gated on it (§3.3 gate 1).
    pub module_abi_compat: ModuleAbiCompat,
    /// The owner's `config` output store path, fetched when the root is needed.
    pub config_output: String,
    /// Owner-declared contributable sub-paths (relative to the root); a foreign
    /// contributor's paths MUST be a subset of these (F3-B, checked at resolve).
    pub contributable: Vec<String>,
}

/// One installed package that *sets* a capability token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySetter {
    /// Setting package name.
    pub package: String,
    /// Setting package version.
    pub version: String,
}
```

**Construction (resolve time, mechanical).** Seed `roots` from the base-lib
manifest's bundled roots. Then, for each package in the installed set carrying
`config_module`: for every `OwnedRoot` in `owns_roots`, insert
`root → RootOwner` (all fields pinned from the installed owner) — a second
installed owner of an already-present root is a hard error citing both packages
(**owned-root exclusivity, per-system**, `module-system.md`). For every token in
`provides_capabilities`, append a `CapabilitySetter` to `capabilities[token]`. The
registry never adjudicates ownership: two registry packages may each claim
`firewall`, but a single system cannot install both, and it is the install
decision — not a publish-time claim — that resolves the choice.

**Shadowing guard.** A shared root in `SystemRoots.roots` that collides with the
NAME of a different installed package is a hard error: `SystemRoots` is consulted
before the structural (`root = package name`) fallback, so a package name must
never be silently shadowed by another package's owned root.

### 3.3 Resolver gate (normative algorithm)

The resolver reads the **running image's** `module_abi` (`K`) from the toplevel
manifest / `os-release` — never from the network. Two gates, both **pre-eval,
fail-closed**, the old config-gen stays live on failure (mirrors
`enforce_totality`, `sysroot.rs:192`):

1. **Root-based dispatch → provider selection.** On a missing-option signal
   (strict throw or missing-attr; `module-system.md` §Requires), the resolver
   dispatches on the option's **root segment** (§4):
   - if the root is present in `SystemRoots.roots`, the owner is the installed
     package named there — no fetch. A shared root with **no** installed owner
     is a terminal, legible error (`"no installed package owns root
     '<root>'"`); the resolver never auto-fetches a shared-root owner from the
     registry.
   - otherwise the root is treated **structurally** (root segment = package
     name): the resolver performs a registry **by-name** lookup of that
     package's `ConfigModuleMeta`, gates it on
     `module_abi_compat.min <= K <= module_abi_compat.max` (ABI band excludes
     `K` ⇒ `AbiMismatch`; name absent ⇒ `NoProvider`), fetches its
     `config_output`, and re-evals to a fixpoint.

2. **ABI compat gate (per module in the resolved set).** Before the manifest is
   forced, for every config module `M`:
   `M.module_abi_compat.min <= K <= M.module_abi_compat.max` MUST hold; else
   refuse `M` with `"config module '<pkg>@<ver>' requires module_abi in
   [<min>,<max>], running image is <K>"` and abort before producing a manifest.

3. **Owned-root interface ABI + contributable surface** is checked independently
   of the base `K`, entirely at resolve time against `SystemRoots`: for each
   installed contributor, its `RootContribution.root` must name a root whose
   `RootOwner` is installed, the contributor must have been built against that
   owner's `interface_abi`, and every contributed path must lie within that
   owner's `contributable` set (`RootContribution.paths ⊆ RootOwner.contributable`)
   — otherwise reject (conscription / foreign-write guard, F3-B). Publish no
   longer performs this check against any global index; it is a per-system,
   resolve-time assertion.

The produced manifest records `module_abi = K` (→ `module_abi_pinned`), which the
rollback pin (`generations.md` §pinning rule) later checks: a config-gen
re-activates directly iff its `module_abi_pinned` equals the running image's `K`,
and is re-evaluated (never replayed) across a different `K`.


---

# Resolve↔eval fixpoint algorithm

Grounding confirmed. Here is the drop-in RFC markdown.

---

# The resolve↔eval fixpoint: algorithm contract

This document is the **implementation contract** for the resolver loop that
drives stock-Nix `evalModules` to a complete configuration on-host. It is
normative: an agent implementing P1 against it should produce a deterministic
resolver without further design input. Line citations are to
`lib/modules.nix`, `crates/aos-package/src/resolve.rs`, and the manifest schema
in [`architecture.md`](architecture.md). Companion specs:
[`module-system.md`](module-system.md) (provides/requires inference),
[`operability.md`](operability.md) (failure classes, traces).

The fixpoint exists because stock Nix gives **no read-access instrumentation**
(`module-system.md` §"What the existing module system already provides"). The
set of providers a config needs cannot be statically closed; it is discovered
by evaluating, observing what is missing, fetching the named provider, and
re-evaluating until the eval succeeds or a terminal state is reached. P2
aos-nix collapses the loop to one pass with structured errors (§7); the
contract below is the seam both implementations sit behind.

## 1. The loop — inputs, state, termination

### Inputs (immutable for the duration of one `switch`)

- `host_nix: StorePath` — the policy-accepted leaf `host.nix` (provenance-stamped; see
  `module-system.md` §"Merge precedence").
- `base_lib: StorePath` — the in-image module library, ABI-pinned to the image
  generation (`manifest.inputs.base_lib`).
- `seed_set: Vec<PackageName>` — packages explicitly installed
  (`desired.toml`), the starting working set.
- `system_roots: SystemRoots` — the locally-derived shared-root → installed-owner
  and capability-token → installed-setter map (§3.2), built at resolve time from
  the base-lib manifest's bundled roots and the installed set's `owns_roots` /
  `provides_capabilities` (`module-system.md` §"Provides — derived, not
  declared"). Read-only here; never fetched.
- `module_abi: u32` — the image's base-lib ABI (§6).

### Mutable state (one `FixpointState` per `switch`)

```text
working_set : OrderedSet<PackageName>   // starts = seed_set; grows monotonically
fetched     : Set<StorePath>            // config-output NARs already local
trace       : Vec<IterRecord>           // causal chain, for non-convergence dump
iter        : u32                       // 0-based iteration counter
```

`working_set` is **append-only**: a provider is added, never removed, inside a
single fixpoint run. This is what guarantees termination (§5) — the lattice is
the finite powerset of registry packages, ordered by inclusion, and each
non-terminal step strictly grows `working_set`.

### The loop

```text
fn fixpoint(inputs) -> Result<Manifest, FixpointError>:
    state.working_set = inputs.seed_set
    # Pre-close with the publish-time AST scan so the loop usually adds 0..1.
    state.working_set |= ast_requires_closure(seed_set)          # §4, over-approximate

    loop:
        if state.iter >= ITER_CAP:                  # §5
            return Err(NonConvergence(dump_trace(state)))

        entry = render_entry_nix(state.working_set, host_nix, base_lib)
        result = run_eval(entry)                    # §3 invocation; cold subprocess in P1

        match classify(result):                     # §2
            Ok(manifest):
                return Ok(manifest)

            MissingOption{ path, kind, read_by }:   # write-to-undeclared OR read-of-absent
                provider = resolve_root(path, system_roots)   # §4 root-based dispatch
                  .ok_or(Err(NoProvider{ path, read_by }))?     # terminal, distinct exit
                if provider in state.working_set:
                    # already present yet still missing ⇒ not a fetch problem
                    return Err(Unsatisfiable{ path, provider })  # §5 cycle/guard
                fetch_config_output(provider)?      # §4 config output FIRST
                state.working_set.insert(provider)
                state.trace.push(IterRecord{ iter, path, provider, kind })
                state.iter += 1
                continue                            # re-eval

            Assertion{ msg, file }      => return Err(AssertionFailed{ msg, file })  # §2
            ScalarConflict{ defs }      => return Err(Conflict{ defs })              # §2
            Killed{ reason }            => return Err(EvalKilled{ reason })          # §2 (OOM/timeout)
            OtherEvalError{ stderr }    => return Err(EvalError{ stderr })           # opaque Nix failure
```

**Termination** is one of: `Ok(manifest)`; a *terminal* `Err` (`NoProvider`,
`AssertionFailed`, `Conflict`, `EvalKilled`, `Unsatisfiable`, `EvalError`); or
`NonConvergence` at the iteration cap. Every terminal state is a **clean no-op
on the live system** — the fixpoint produces *only* a manifest and never calls
`activate` (`architecture.md` §"Failure-safe by construction"). No generation
exists until `aos-install-packages.service` consumes a returned manifest.

The resolver's package-fetch + closure machinery is the existing
`resolve_multiple` / `resolve_closure`
(`crates/aos-package/src/resolve.rs:65,233`); the fixpoint is a driver *around*
it. `resolve_with_requires` already has the cycle guard
(`resolve.rs:267-271`, `"package requires cycle"`) and the `expose.requires` /
`expose.uses` traversal (`resolve.rs:297-314`) — the fixpoint adds the
**eval-discovered** edges that the static `expose` graph cannot express.

## 2. Classifying an eval result — the two missing-option cases

`classify(result)` maps a stock-Nix exit + stderr to the variants above. The
two *missing-option* cases are mechanically distinct and **must be detected
separately** (`module-system.md` review M-read-absent): the strict throw names
only writes; reads of an absent root surface as a raw attribute error.

### Case A — write to an undeclared option (strict throw, `:917`)

A package sets `firewall.*` but no firewall module is in `working_set`. With
`_module.strict = true` on the on-host eval, Phase 6 collects every
no-declaration def and throws (`lib/modules.nix:908-922`):

```text
error: The following option(s) are not declared:
  - 'firewall.forwardPolicy' (defined in /nix/store/<h>-web-config/config.nix)
  - 'firewall.zone' (defined in /nix/store/<h>-web-config/config.nix)

Because `_module.strict = true` on this evaluation, undeclared options are not allowed. ...
```

Detection: the header line is the sentinel; each `- '<path>' (defined in
<file>)` line yields one `(path, read_by=file)`. **All** listed paths are
emitted (a single eval can name several); the driver picks the first whose
root-based dispatch (§4) resolves and fetches it, but records all for the trace.
The full leaf path is retained for error text; dispatch keys only on its root
segment.

### Case B — read of an absent root (raw missing-attr, NOT `:744`)

A package reads `config.firewall.forwardPolicy` while firewall is absent. This
is **not** the `:744` throw — `:744` (`"The option '<path>' is used but has no
definition and no default value."`) fires only for a *declared* option whose
provider is already present but left it unset. An absent *root* never reaches
option machinery; attribute selection on the config attrset fails first with
stock Nix's raw:

```text
error: attribute 'firewall' missing
       at /nix/store/<h>-web-config/config.nix:42:14:
```

Detection: this naked message names only the **first** path segment
(`firewall`), not the full read path. The driver therefore **cannot** rely on
the string alone. It:

1. extracts the missing root segment (`firewall`) and the `at <file>:line`
   locus from the trace;
2. dispatches on that root segment (§4): if `firewall` is a shared root in
   `SystemRoots.roots` with an installed owner, that owner is selected (no
   fetch); a shared root with no installed owner is the terminal `"no installed
   package owns root '<root>'"` error;
3. otherwise the root is structural (root = package name): a registry by-name
   lookup of that package fetches it; if the name is genuinely unknown to the
   registry, this is `NoProvider`.

Because both cases collapse to **root-based dispatch**, the A-vs-B distinction is
no longer load-bearing for *lookup* (A's full path and B's bare root key on the
same segment); it remains load-bearing for **error text** — A can name the full
leaf path, B only the root. The detectors themselves are unchanged.

### The exact P1 parse patterns (and their fragility)

P1 parses human-readable throw strings — an **acknowledged P1 fragility, not a
stable API** (`module-system.md` §"Requires — discovered"). The patterns,
anchored to current `lib/modules.nix` / stock-Nix text:

| Class | Anchor / regex (multiline, on eval stderr) | Captures |
|-------|--------------------------------------------|----------|
| A — undeclared write | header `^The following option\(s\) are not declared:` then per-line `^\s*-\s*'(?P<path>[^']+)'\s*\(defined in (?P<file>[^)]+)\)` | `path`, `file` |
| B — absent-root read | `^\s*attribute '(?P<root>[^']+)' missing` + following `^\s*at (?P<file>[^:]+):(?P<line>\d+)` | `root`, `file:line` |
| Undefined declared option (`:744`) | `^The option '(?P<path>[^']+)' is used but has no definition and no default value\.` | `path` (provider present → **not** auto-fetched; surfaces as the operability "Undefined option" diagnostic, not a fixpoint step) |
| Scalar conflict (`:721` / types) | `conflicting definitions` / `conflicting values`, followed by the per-def `- '<value>'? (defined in <file>)` block listing **every** def + `file` | `Vec<(value, file)>` |
| Assertion (`:935`, forced) | the assertion message text as authored, surfaced when the manifest is forced | `msg`, `file` |
| Killed | non-zero exit with empty/truncated stderr **and** a systemd cgroup kill event (see §3) | `reason ∈ {OOM, timeout}` |

Rules for the parser:

- Match on the **last** throw block in stderr (the innermost `:744`/`:917`
  throw is the terminal frame; Nix prepends `error:` and a trace stack).
- `:744` is **terminal, not a fetch trigger.** It means the declaring provider
  *is* present but no def sets the option and there is no default — fetching
  more packages cannot fix it. Emit the operability "Undefined option"
  one-liner (`operability.md` table) and stop. (Contrast Case B, where the
  provider is *absent*.)
- Treat any unrecognized `error:` as `OtherEvalError` (opaque) — never
  misclassify it as a missing option, or the loop will fetch a wrong provider
  and mask the real fault.
- The parser is isolated behind one `fn classify(stderr, exit) -> EvalClass`
  with an exhaustive test fixture, so P2 replaces exactly this function.

## 3. Eval invocation (P1) and the kill channel

Each iteration runs a **cold stock-Nix subprocess** (`architecture.md`
§"The evaluator"):

```text
nix-instantiate --store dummy:// --eval --strict --json \
  --option restrict-eval true \                  # read only /run/aos-eval + the store
  --option allow-import-from-derivation false \  # no IFD ⇒ no build can sneak in
  -I /run/aos-eval \
  -A manifest /run/aos-eval/entry.nix
```

`entry.nix` is regenerated each iteration from the current `working_set`
(base-lib injected as module args — packages do not import it;
`lib/modules.nix:541-567,620`). The eval forces `config.system.build.manifest`
(the rendered data contract), which is what triggers assertion enforcement
(`:935`) and the strict walk (`:813-922`).

The subprocess runs inside a **hardened transient systemd scope** whose limits
*are* the perf budget (`operability.md` §"Perf budget"):

```text
RuntimeMaxSec=120   MemoryMax=2G   MemoryHigh=1536M   TasksMax=...
```

A runaway is OOM-/timeout-killed by the cgroup; the driver reads the scope's
exit cause (`systemctl show --property=Result`, or the
`oom-kill`/`timeout` result) to populate `Killed{reason}` rather than guessing
from stderr. **Per-eval** budget; the resolver separately bounds **total**
iterations (§5). A kill is a clean no-op (eval precedes the staged swap).

## 4. Root-based dispatch and provider fetch

### Dispatch — `resolve_root`

Both missing-option cases collapse to one operation keyed on the option's
**root segment**. There is no registry-wide index to query; the resolver
consults `SystemRoots` (derived on-host, §3.2) and then the structural
package-name convention:

```text
fn resolve_root(path, system_roots) -> Option<Provider>:
    root = first_segment(path)
    if let Some(owner) = system_roots.roots.get(root):   # shared root
        return Some(owner)                               # installed; never fetched
        # (no installed owner ⇒ the caller emits the terminal
        #  "no installed package owns root '<root>'" error, not NoProvider)
    else:                                                # structural: root == package name
        return registry_lookup_by_name(root)             # ABI-gated (§3.3); None ⇒ NoProvider
```

- **Shared root** (`root ∈ SystemRoots.roots`) → the single installed owner
  named there. Owned-root exclusivity is enforced **per-system** when
  `SystemRoots` is built (§3.2), so this is always 0-or-1 by construction; a
  shared root with no installed owner is the terminal `"no installed package
  owns root '<root>'"` error — never an auto-fetch.
- **Structural root** (root segment = package name) → a registry **by-name**
  lookup of that package's `ConfigModuleMeta`, ABI-gated pre-fetch (§3.3). The
  `declares` surface is still computed by **options-only evaluation** at publish
  (does not force `config`; `lib/modules.nix:924-930`, `lib/testing/eval.nix:20`)
  but is retained as per-package metadata, not aggregated registry-wide.

`SystemRoots` is consulted **before** the structural fallback, so an installed
package's owned root always shadows the bare-name convention (shadowing guard,
§3.2).

### Fetch — config output first

On a resolved provider the driver fetches the **`config` output NAR before the
`out` closure** (`architecture.md` §"Stage 1"): the next eval needs only the
config-only module (typed options + string-path `config`), and the runtime
binary closure is needed solely if that provider survives into the final
manifest. Concretely:

1. `fetch_config_output(provider)` — download + verify the `config` output NAR
   into the local store, mark in `fetched`. This is the only thing the *eval*
   reads.
2. The `out` closure is resolved lazily via the existing
   `resolve_closure`/`resolve_via_store` (`resolve.rs:65,106`) only when the
   provider is in the **converged** `working_set`, so a provider fetched then
   shadowed by a conflict (terminal) never drags its binary closure.

The config-output NAR must be present locally for `restrict-eval` to read it
(`-I /run/aos-eval` + store). The fetch failure modes (registry unreachable,
unsigned, hash mismatch) are terminal `Err` and, like every fixpoint error,
leave the box live on the gen-0 seed.

### Static pre-close (keep the loop short)

Before iteration 0, `ast_requires_closure` seeds `working_set` with the
**publish-time AST scan** over-approximation (`config.<path>` / `options.<path>`
access patterns; `module-system.md` §"Requires"). This is conservative
(misses computed `config.${name}` paths) but pre-fetches the common providers
so K (extra evals) is usually 0–1 (`operability.md` §"warm vs cold"). The
fixpoint is the **backstop** for what the scan misses.

## 5. Cycle detection, iteration cap, and the non-convergence trace

Two distinct cyclic hazards, two guards:

1. **Package `requires` cycle** — already handled by the path stack in
   `resolve_with_requires` (`resolve.rs:267-271`): `bail!("package requires
   cycle: a -> b -> a")`. Terminal.
2. **Eval read cycle** — provider X reads `tls.*`, pulling tls, which reads
   `firewall.zone`, pulling firewall, which reads back into X's root. The
   *working_set* still grows each step, so this terminates by the cap; but if a
   provider is fetched yet the **same** option stays missing
   (`provider ∈ working_set` already at the lookup), that is `Unsatisfiable` —
   fetching cannot help, fail immediately rather than spin.

**Iteration cap.** `ITER_CAP` bounds total re-evals. It is derived from the
size of the **working/installed set**, not from any registry index (there is
none): recommend `ITER_CAP = |working_set closure over structural + shared-root
providers| + 8`, with an absolute ceiling (e.g. 64) so a pathological seed
cannot make the loop unbounded. Because
`working_set` is append-only over a finite package universe, the loop is
*guaranteed* to terminate at or before the cap even without cycle detection;
the cap exists to convert "slow/divergent" into a **legible dump** rather than
a hang.

**Non-convergence dump.** On hitting the cap, emit the causal chain from
`trace` (`operability.md` §"Non-convergence / cycle"):

```text
config eval did not converge after N iterations:
  iter 0: seed {web}
  iter 1: web writes firewall.* (undeclared)        → +firewall   [case A: web/config.nix]
  iter 2: firewall reads config.tls.mode (absent)   → +tls        [case B: firewall/config.nix:88]
  iter 3: tls reads config.firewall.zone (absent)   → firewall already present  ← cycle
hint: firewall.zone is declared by 'firewall' but left unset; this is a read cycle,
      not a missing provider. Break it in host.nix or fix the provider.
```

Each `IterRecord` carries `(iter, missing_path, case_kind, provider_added,
read_by_file)` so the dump names *why* each provider entered and where the
chain closed. This is a terminal `Err`, hence a no-op on the live system.

## 6. Interaction with the `module_abi` pre-eval gate

`module_abi` is checked **before** the fixpoint runs, and is *not* part of the
loop. The base lib shipped in the image owns the structural roots the renderer
consumes and carries an ABI integer (`manifest.module_abi`, `architecture.md`
§"The manifest"; `module-system.md` §"Namespacing"). A fetched `config` module
declares the `module_abi` it was published against.

Pre-eval gate (run once, on the assembled `working_set` after the static
pre-close, and again on each newly-fetched provider before it enters
`entry.nix`):

```text
for pkg in working_set:
    if pkg.module_abi != image.module_abi
       and pkg.module_abi not in image.compat_abis:
        return Err(AbiMismatch{ pkg, want: image.module_abi, got: pkg.module_abi })
```

Properties the implementer must preserve:

- The gate is **upstream of `nix-instantiate --eval`**: an ABI-incompatible config module
  must never be placed into `entry.nix`, because a stale interface would throw
  a *misleading* undeclared/missing-option error that the fixpoint would
  misread as "fetch a provider" — fetching cannot fix an ABI skew. Gate first,
  so the operator sees `AbiMismatch`, not a spurious `NoProvider`.
- Shared roots each carry their **own** `module_abi` (`firewall.*` versions
  independently of base lib; `module-system.md`), so the check is per-declared-
  root, not one global number: a fetched provider is gated against the ABI of
  the root it *declares*, and against the base-lib ABI for any base root it
  *reads*.
- The gate is terminal and a no-op on the live system, same as every other
  fixpoint error — there is no "re-eval to recover from ABI mismatch."
- `module_abi` is recorded in `manifest.inputs` so the off-host CI preflight
  (`checks.config-eval`, `operability.md`) reproduces the same gate decision
  the box would make.

## 7. The P1→P2 seam (what this contract guarantees stays stable)

Everything above is the P1 stand-in for capabilities stock Nix lacks. P2
aos-nix (RFC-0007) replaces the *internals* without touching the contract
boundary:

- **String parsing (`classify`, §2) → structured errors.** aos-nix returns a
  typed `MissingOption{ path, kind: Read|Write, read_by }` directly, so Cases A
  and B arrive pre-distinguished and the regex table is deleted. The driver's
  `match` arms are unchanged.
- **The fixpoint loop (§1) → one pass.** aos-nix's one-shot read-tracing and
  the first-class option read/write graph let the resolver close the provider
  set from a *single* eval, so K → 1 and `ITER_CAP` becomes a safety net rather
  than the common path.
- **Cgroup kill channel (§3) → in-engine bounding.** Timeouts/limits become
  structured engine results, not OOM-kill inference.

The seam is exactly `eval(working_set, host_nix, base_lib) → Result<Manifest,
EvalClass>`. The resolver, the `SystemRoots` derivation and root dispatch (§4),
the fetch order (§4), the `module_abi` gate (§6), and the manifest contract are
**identical** on both evaluators;
swapping P1↔P2 changes only how `EvalClass` is produced. None of this touches
the registry format, the module contract, or the generations
(`architecture.md` §"P2").

---

Files referenced (absolute):
- `lib/modules.nix` (undefined-declared and strict-undeclared errors,
  assertions, options-only evaluation, and base-lib injection)
- `crates/aos-package/src/resolve.rs` (closure resolution, cycle guards, and
  expose-requires/uses traversal — the machinery the fixpoint drives)
- `docs/rfcs/0011-on-host-config-eval/{module-system,architecture,operability}.md`

Suggested filename for the drop-in: `docs/rfcs/0011-on-host-config-eval/resolve-eval-fixpoint.md`.


---

# Systemd unit-graph compiler + apm subverbs

Here is the drop-in RFC markdown.

---

# CONTRACT: the systemd unit-graph compiler

This is the implementation contract for the graph compiler specified in
[`orchestration.md`](orchestration.md). It is normative: an agent implementing
`crates/aos-package/src/graph_compile.rs`, the new `apm` subverbs, and the
gen-0 template units in `modules/systemd/` MUST satisfy every clause here.
Where a clause says MUST it is a gate; SHOULD is a strong default a reviewer
may waive with rationale.

Grounding: `modules/base/apm.nix` (units being replaced, `:385-406`),
`modules/systemd/presets.nix` (the `aos-preset.service` that runs *after* this
graph), `crates/aos-systemd/src/client.rs` (the only systemd-control surface
permitted), `modules/base/activate.sh.in` (the atomic commit, reused
unchanged), `crates/aos-package/src/{desired,config_artifact,install,exposed_units}.rs`
(the existing fetch/render plumbing the subverbs wrap).

---

## 0. Vocabulary and invariants

- **Template** — a static `aos-pkg-*@.service` baked into gen-0 (`/usr/lib/systemd/system`). Body, sandboxing, slice, restart policy live here; never synthesized at runtime.
- **Instance** — `aos-pkg-fetch@<pkg>.service`, materialized at runtime by enabling the template against an instance name `%i = <pkg>`.
- **Dropin** — a generated `…@<pkg>.service.d/10-edges.conf` carrying only per-instance ordering/dependency edges.
- **The two inputs** — `/run/aos/manifest.json` (data contract, the resolved package set + config) and `/run/aos/graph.json` (the cross-package read/write DAG). Both are produced by `aos-eval.service` and are read-only to the compiler.
- **`<pkg>`** — an APM package name. It MUST match `packageNameRegex` = `[A-Za-z0-9][A-Za-z0-9+._=-]*` (from `apm.nix:24`). The compiler MUST reject any manifest entry that fails this, because the name is interpolated into a systemd instance name and a `/run` path.

**I1 (no `/etc` pollution).** Every runtime artifact the compiler writes lives under `/run/systemd/system/`. The compiler MUST NOT write to `/etc` or `/usr`. `/run/systemd/system` is tmpfs, outranks both, and is outside the composefs `/etc` overlay.

**I2 (single control surface).** The compiler drives systemd ONLY through `aos_systemd::SystemdClient`: `daemon_reload`, `start_unit_no_wait`, `reset_failed_unit`, `list_units_by_patterns`. It MUST NOT shell out to `systemctl` (except the display-only `systemctl_status` already in the client) and MUST NOT use `StartTransientUnit`.

**I3 (pure function of inputs).** The set of `/run/systemd/system` artifacts after a compile MUST be a deterministic function of `(manifest.json, graph.json)`. Re-running the compiler over identical inputs MUST produce byte-identical dropins and an identical `.wants/` symlink set (idempotent; safe to re-run).

---

## 1. Static baked template units (gen-0, typed `systemd.*` tree)

Declared in a new `modules/systemd/graph.nix` (or extending `presets.nix`) using the typed unit/template options (`lib/modules/systemd/unit-options.nix:178,198` support templates). These five units are the **entire** static surface; nothing in this section is generated at runtime.

All `ExecStart=` invoke the wrapped `${pkgs.aos}/bin/apm` (the subverbs shell out to `nix-store`/registry and need the wrapper's PATH; this is unlike `activate.sh.in`, which uses `.apm-unwrapped` only because it runs with `PATH=`).

### 1.1 `aos-pkg-fetch@.service` (template)

```ini
[Unit]
Description=Fetch AOS package closure %i
# Fetch is network-only and carries NO config edges (downloads are
# order-independent; see §3). The only ordering is "after the net is up".
After=network-online.target
Wants=network-online.target
# Best-effort node: never abort the target. No Requires= anywhere.

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/apm fetch %i
Restart=on-failure
RestartSec=5s
# Bounded retry budget so a permanently-bad package degrades rather than
# spins forever (the recovery ladder's rung 1, orchestration.md §Recovery).
StartLimitIntervalSec=120s
StartLimitBurst=5
TimeoutStartSec=180s
# Hardened scope (network fetch + store import only).
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/nix /run/aos
NoNewPrivileges=yes
```

Notes:
- `RemainAfterExit=yes` is REQUIRED so a converged fetch is `active` and the reconfiguration delta path (§5) treats unchanged packages as no-ops.
- `Restart=on-failure` + `StartLimit*` give rung-1 auto-retry; after the burst is exhausted the instance is `failed` and the recovery ladder moves to manual `reset-failed`/`start` (rung 2) or re-eval (rung 3).
- `/usr/bin/apm` is the rootfs symlink farm path; if the farm omits the unwrapped companion (see `apm.nix:413-421`) the template MUST instead hardcode the store path via a `@apm@` substitution. The implementer MUST verify the wrapper resolves under systemd's `PATH` in a VM smoke test.

### 1.2 `aos-pkg-install@.service` (template)

```ini
[Unit]
Description=Render AOS package config %i
# Per-instance config edges (After=/Wants= mirroring graph.json) and the
# After=aos-pkg-fetch@%i.service self-edge are added by a generated dropin.
# The static body intentionally declares NEITHER, so the template carries no
# package-specific knowledge.

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/apm render-one %i
# Render is local (validate config against signed expose.config, write the
# artifact + credential handles). No network Restart loop; a render failure is
# a config error, not a transient.
TimeoutStartSec=60s
PrivateTmp=yes
NoNewPrivileges=yes
```

The compiler MUST add, in the generated dropin (§2.1), a hard `After=aos-pkg-fetch@%i.service` so a package's render never runs before its own closure is local. (This is `After=` only on the install side; see §3 for why the fetch→install self-edge is ordering, not a hard `Requires=`.)

### 1.3 The three targets (static, passive)

```ini
# aos-fetch.target
[Unit]
Description=AOS package fetch wing
# .wants symlinks to aos-pkg-fetch@<pkg> are generated at runtime (§2.2).

# aos-config-render.target
[Unit]
Description=AOS package render wing
After=aos-fetch.target
# .wants symlinks to aos-pkg-install@<pkg> are generated at runtime.

# aos-config.target
[Unit]
Description=AOS on-host config applied
After=aos-config-render.target
Wants=aos-config-render.target aos-fetch.target
```

Targets MUST NOT statically `Wants=` any instance — the instance set is unknown at image build time. All target→instance edges are runtime `.wants/` symlinks (§2.2), and they are **`Wants=` only** (§3, I-degraded): one failed instance never fails its target.

`aos-config.target` is the single thing the compiler `start`s (§2.4). `aos-activate.service` (declared in `apm.nix`, the atomic commit) is wired `After=aos-config-render.target` and `aos-preset.service` stays `After=aos-activate.service` — those two live outside this compiler and are untouched here beyond the `After=` wiring.

---

## 2. Runtime-generated artifacts (what the compiler writes)

The compiler runs as `aos-graph-compile.service` (`After=aos-eval`, `ConditionPathExists=/run/aos/manifest.json`). Its whole job is: parse the two inputs → write dropins + `.wants` symlinks → `daemon_reload` → `start_unit_no_wait("aos-config.target")`. It writes **nothing heavyweight**.

### 2.1 Per-instance dropin — format and path

For each package `p` in the manifest, and for the `aos-pkg-install@<p>` instance only (fetch has no config edges), the compiler writes:

```
/run/systemd/system/aos-pkg-install@<p>.service.d/10-edges.conf
```

Exact content (this is the on-disk format contract):

```ini
# Generated by aos-graph-compile from /run/aos/{manifest,graph}.json.
# Do not edit; regenerated on every `apm switch`/`upgrade`.
[Unit]
After=aos-pkg-fetch@<p>.service
After=aos-pkg-install@<dep1>.service aos-pkg-install@<dep2>.service …
Wants=aos-pkg-install@<dep1>.service aos-pkg-install@<dep2>.service …
```

Rules:
- The `<depK>` set is exactly the out-neighbors of `p` in `graph.json` (packages `p` reads config from — `nginx → firewall`). Order them **lexicographically** so the file is deterministic (I3).
- If `p` has no config dependencies, the dropin still gets written but contains only the `After=aos-pkg-fetch@<p>.service` self-edge line (so render-after-fetch always holds). An empty `[Unit]` section is never emitted.
- The fetch instance (`aos-pkg-fetch@<p>`) gets **no dropin** — it has no edges (§3). Its only ordering, `After=network-online.target`, is in the template body.
- Directory mode `0755`, file mode `0644`. Parent `…service.d/` created with `create_dir_all`.

### 2.2 `.wants/` symlinks

For each package `p`:

```
/run/systemd/system/aos-fetch.target.wants/aos-pkg-fetch@<p>.service          → ../aos-pkg-fetch@.service
/run/systemd/system/aos-config-render.target.wants/aos-pkg-install@<p>.service → ../aos-pkg-install@.service
```

- The symlink **target** is the template unit (relative `../<template>`), exactly as `systemctl enable` of a templated instance would write it. systemd instantiates `%i` from the symlink name.
- These are `Wants=` edges by construction (`.wants/` directory semantics). There is no `.requires/` directory anywhere in this graph (I-degraded).
- The compiler creates the `.target.wants/` dirs if absent.

### 2.3 daemon-reload

After all dropins + symlinks are on disk, the compiler calls `SystemdClient::daemon_reload()` **exactly once**. It MUST NOT reload per-instance. If `daemon_reload` errors, the compile fails (the units are not yet visible to systemd); `aos-graph-compile.service` exits non-zero and the system stays on the gen-0 seed (recovery ladder rung 4).

### 2.4 start

After the reload, the compiler calls `start_unit_no_wait("aos-config.target")` (matching `systemctl start --no-block`). It MUST use the no-wait variant: the compiler returns immediately and systemd drives the wing asynchronously; the compiler does not block on dozens of fetch jobs. The compiler MUST NOT `start` individual instances — pulling `aos-config.target` (which `Wants=` the render target, which `Wants=` every install instance, each `After=` its fetch) lets systemd schedule the whole graph with maximal parallelism.

### 2.5 Write ordering (crash-safety)

The compiler MUST write in this order: (1) all dropins, (2) all `.wants` symlinks, (3) `daemon_reload`, (4) `start`. Writing edges before the symlinks that pull the units guarantees that the instant a unit becomes wanted, its ordering constraints are already loadable. Symlinks SHOULD be created via write-to-temp + `rename` where atomicity matters; dropins are plain files (idempotent rewrite is acceptable since systemd does not read them until the reload).

---

## 3. Edge rules: `Wants=` vs `Requires=`

This is the lever that turns a one-bad-package failure into degraded-not-failed boot. The compiler MUST apply exactly these mappings and MUST NOT emit `Requires=`/`BindsTo=`/`Requisite=` anywhere.

| Edge | Where | Directive | Rationale |
|---|---|---|---|
| `aos-fetch.target` → `aos-pkg-fetch@<p>` | `.wants/` symlink (§2.2) | **`Wants=`** | a failed fetch must not fail the target |
| `aos-config-render.target` → `aos-pkg-install@<p>` | `.wants/` symlink | **`Wants=`** | a failed render must not fail the target |
| config edge `p → dep` (provisioning order) | dropin `[Unit]` (§2.1) | **`After=` + `Wants=`** | order render(p) after render(dep); soft so dep's failure isolates |
| `aos-pkg-install@<p>` → `aos-pkg-fetch@<p>` (self) | dropin `[Unit]` | **`After=` only** | render must follow its own fetch; an unmet fetch leaves render inactive (not failed) — degrades |
| `aos-pkg-fetch@<p>` → `network-online.target` | template body | `After=`+`Wants=` | static; network readiness |

Why the fetch→install self-edge is `After=` only and not `Requires=`: if `aos-pkg-fetch@nginx` exhausts its retry budget and goes `failed`, an `After=`-only dependent simply never has its start condition met and stays `inactive`; the render-target it is `Wants=`-pulled from still reaches `active`. A `Requires=` here would propagate the fetch failure into the render and (via `Wants=`-but-failed semantics on a required dep) is exactly the abort we are avoiding. The package is **dropped**, not fatal.

`Requires=`/`BindsTo=` are reserved for true substrate edges, which live **outside** this compiler:
- initrd substrate (repart/cryptsetup/mount-var) — hard edges → `emergency.target` on loss;
- a package main unit → its own MAC/eBPF sidecar — a genuine `BindsTo=` rendered by `exposed_units.rs` into committed `/etc`, not by this compiler.

The compiler operates only on the `aos-pkg-*@` plane and emits only soft edges there.

**Cycle safety.** The compiler MAY assume `graph.json` is a DAG (a non-converging eval fixpoint fails `aos-eval` with an iteration trace before any graph exists). The compiler MUST nonetheless detect a cycle defensively (e.g. Kahn / DFS back-edge) and, on finding one, fail the compile with the cycle path rather than emitting an ordering loop systemd would reject at reload. Independent packages (no edges) get empty dep lists and run fully parallel.

---

## 4. New `apm` subverbs

Two thin subverbs back the template `ExecStart=`s. They are the only new CLI surface. Both are per-package and idempotent.

### 4.1 `apm fetch <pkg>`

Download + verify one package's NAR closure into the store; do **not** switch generations, render config, or activate.

- **Inputs:** `<pkg>` (positional, validated against `packageNameRegex`); the resolved closure for `<pkg>` is read from `/run/aos/manifest.json` (the manifest pins exact store paths + narinfo references, so `fetch` does not re-resolve from the registry — it materializes what eval already resolved). Registry/trust config from `/etc/apm`.
- **Behavior:** reuse the existing download path (`download::{fetch_narinfo_closure, download_nars, import_nar}` from `install.rs` step 3) restricted to `<pkg>`'s closure members not already present (`store::filter_missing`). Verify both the compressed download hash and the NAR hash, exactly as `install` does. No profile generation is created (the install/activate split is the whole point).
- **Outputs:** store paths imported into `/nix`. A per-package completion marker `/run/aos/fetch/<pkg>.ok` (so `render-one` and the re-projection step in §5 can cheaply test "did this materialize" without re-walking the store). The marker MUST be written only after every closure path verifies and imports.
- **Exit codes:**
  - `0` — closure fully present and verified (including the already-present no-op case; idempotent).
  - non-zero — any narinfo fetch, download, hash-verify, or import failure. The process MUST exit non-zero so the template's `Restart=on-failure` engages. A non-zero exit MUST NOT leave a `.ok` marker.
- The subverb MUST be safe to run concurrently for distinct `<pkg>` (parallel fetch is a design goal); store import is already concurrency-safe via the AOS store.

### 4.2 `apm render-one <pkg>`

Render one package's config artifact(s) + credential handles into the staging area, against the signed `expose.config` metadata; do **not** activate.

- **Inputs:** `<pkg>`; the package-scoped `config.<pkg>` and `credentials.<pkg>` blocks from `/run/aos/manifest.json`; the package's signed `ExposeMeta`/`ConfigArtifactMeta` from the profile metadata (`config_artifact.rs` already validates desired config against signed `expose.config`).
- **Precondition:** `<pkg>`'s closure is local. The template enforces this with `After=aos-pkg-fetch@<pkg>.service`; `render-one` SHOULD additionally assert `/run/aos/fetch/<pkg>.ok` exists and fail fast (exit code below) if not, so a manually-started render without its fetch errors cleanly instead of rendering against an absent store path.
- **Behavior:** reuse `config_artifact.rs` materialization restricted to one package — validate field names/values against signed schema, write the artifact under the staging root, and stage credential handles. Render is **local and side-effect-isolated**: it MUST write only into the per-package staging area consumed later by `aos-activate`, and MUST NOT touch live `/etc` (the commit is `activate.sh.in`'s job).
- **Outputs:** rendered artifact files + credential handles in staging; a marker `/run/aos/render/<pkg>.ok` written only on full success.
- **Exit codes:**
  - `0` — artifact(s) validated and written (idempotent re-render is a no-op-equivalent overwrite).
  - `2` (config-error) — desired config fails validation against the signed schema (bad field name/value/type). This is a permanent error; the template deliberately has **no** `Restart=`, so the instance fails once and the package drops.
  - non-zero other — missing fetch marker / staging I/O error.

Both subverbs MUST honor `--json` for machine output consistent with the rest of `apm`, and MUST emit human diagnostics on stderr (stdout reserved for any structured output), matching `Printer` conventions.

---

## 5. The degraded re-projected-manifest commit

When the pre-commit wing finishes with some packages dropped (fetch exhausted its budget, or render hit a config error), `aos-config.target` still reaches `active` (all edges soft) and `aos-activate.service` runs. It MUST NOT commit `/etc` from "whatever happened to materialize" under the full manifest's identity — that would be a generation whose content depends on transient fetch outcomes, breaking content-addressing (`generations.md`). Instead it commits a **re-projected manifest**. This section is the contract for computing it.

### 5.1 Computing the materialized subset

The materialized set `M` is computed from the on-disk markers, not from systemd unit states (markers are the authoritative "this package is fully present + rendered" signal and survive a unit going inactive):

```
M = { p ∈ manifest.packages :
        exists(/run/aos/fetch/<p>.ok) ∧ exists(/run/aos/render/<p>.ok) }
D = manifest.packages \ M        # the drop-set
```

A package is in `M` **iff both** its fetch and render markers exist. A package whose fetch succeeded but render failed (config error) is dropped, and vice-versa.

### 5.2 Closure / dependency consistency of the subset

`M` MUST be **dependency-closed under the config graph**: if `p ∈ M` but some `dep` that `p` requires (a `graph.json` out-neighbor whose artifact `p`'s rendered config references) is in `D`, then `p` MUST also be moved to `D`. The compiler/activate computes the transitive closure of "depends on a dropped package" and removes those packages from `M` before committing, so the committed subset never contains a package whose declared dependency was dropped. This MUST iterate to a fixpoint (removing `p` can drop something that depended on `p`).

The drop-set recorded (§5.4) is the **final** `D` after this closure, so the recorded reason distinguishes *direct* drops (own fetch/render failed) from *cascade* drops (a dependency was dropped).

### 5.3 Re-hashing into a content-addressed generation

The committed config-generation's identity MUST be `hash(re-projected-manifest)`, where the re-projected manifest is the full manifest **restricted to `M`** (same package pins, same config blocks, drop-set removed). Concretely:

- Build `manifest'` = `manifest` with `packages`, `config`, `credentials`, and any `graph` projection filtered to `M`.
- Canonicalize `manifest'` deterministically (same canonical-JSON form eval uses) and hash it. This hash names the generation (`generations.md`).
- The generation is therefore reproducible from `(authenticated inputs + recorded drop-set)`: a verifier re-derives `manifest'` by removing exactly `D` from the authenticated full manifest and re-hashing.

A **full** boot (empty `D`) MUST re-hash to exactly `hash(full-manifest)` — the re-projection is the identity when nothing drops, so the happy path is unchanged and indistinguishable from a non-degraded eval.

### 5.4 Recording the drop-set in the generation

The committed generation MUST record, durably alongside its other metadata:

- `dropped`: the final drop-set `D`, each entry as `{ package, reason }` where `reason ∈ { fetch_failed, render_failed, dependency_dropped:<dep> }`;
- `source_manifest_hash`: `hash(full-manifest)` (the un-projected eval output), so the relationship "this degraded gen N was projected from full manifest H by dropping D" is auditable and reproducible;
- `projected`: a boolean / the fact that this gen is a re-projection (`projected = (D ≠ ∅)`).

`aos-activate` exits `EX_DEGRADED=6` (`activate.sh.in:46`) when `D ≠ ∅` so `apm` surfaces a non-zero code and `systemctl is-system-running` reports `degraded` — multi-user still reached, SSH/DHCP and every `p ∈ M` live. This reuses the existing degraded exit path; the swap itself is authoritative and stands.

### 5.5 Recovery is a new generation, never a mutation

Re-running fetch for a dropped package later (rung 2 manual `reset-failed`+`start`, or rung 3 `apm switch`/`upgrade`) produces a **new** config-generation via the normal reconcile path (§Reconfiguration in orchestration.md) — a fresh `hash(manifest'')` with a smaller (or empty) `D`. It MUST NOT mutate the degraded generation in place. Rollback to the degraded gen remains a pointer switch whose recorded `D` makes it exactly reproducible.

---

## 6. Reconfiguration delta (steady state)

On `apm switch`/`upgrade`, `aos-eval` re-emits `manifest.json`+`graph.json` and `aos-graph-compile` re-runs. The compiler MUST diff old vs new manifest (reuse `unit_diff` plumbing) and:

- **added** packages: write fresh dropins + `.wants` symlinks (§2);
- **removed** packages: delete their `/run/systemd/system/aos-pkg-*@<p>.service.d/` dropins and `.target.wants/…@<p>.service` symlinks, then call `SystemdClient::reset_failed_unit` for each removed instance;
- **changed edges**: rewrite the affected `10-edges.conf` dropins;
- then exactly one `daemon_reload`, then `start_unit_no_wait("aos-config.target")`.

Because unchanged packages are already-`active` `RemainAfterExit` oneshots, re-driving the target is a no-op for them; only the delta fetches/renders. The whole `/run` surface remains a pure function of the current manifest (I3), so reconfiguration is idempotent and the resulting generation is content-addressed and rollback-capable.

---

## 7. Acceptance gates (tests the implementer MUST land)

- `tests/fleet/apm-desired-sequencing.nix` — assert (via `/proc`+`/sys`, no grep/sed in guest; `requiredSystemFeatures=["kvm"]`): independent packages fetch concurrently; a `graph.json` edge `nginx→firewall` makes `aos-pkg-install@nginx` start `After=` `aos-pkg-install@firewall`; the generated dropin at `/run/systemd/system/aos-pkg-install@nginx.service.d/10-edges.conf` contains the `After=`/`Wants=` lines; `systemctl cat` shows the instance.
- `tests/fleet/apm-system-activation-fail.nix` — one package's fetch is forced to exhaust its budget; assert `aos-fetch.target`/`aos-config.target` still reach `active`, `aos-activate` commits a re-projected manifest whose generation records the dropped package with reason `fetch_failed`, `is-system-running == degraded`, multi-user reached, the healthy packages' own units are live, and the box stays SSH-reachable. Then `reset-failed`+`start` the dropped fetch and assert recovery produces a *new* generation (rung-2 ladder).
- A unit test for the re-projection: full manifest with empty `D` re-hashes to `hash(full-manifest)` (identity); with `D ≠ ∅` the dependency-closure fixpoint cascades correctly and the recorded `source_manifest_hash` reproduces `manifest'`.

---

Files an implementer touches: `modules/systemd/graph.nix` (new, the §1 templates+targets, baked gen-0); `modules/base/apm.nix` (replace `aos-install-packages.service:385-406` with `aos-eval`/`aos-graph-compile`/`aos-activate`, keep `aos-preset.service` `After=aos-activate.service`); `crates/aos-package/src/graph_compile.rs` (new, sibling to `exposed_units.rs`/`config_artifact.rs` — §2/§3/§6 compiler over the `aos_systemd` client) plus the `fetch`/`render-one` subverbs (§4) and the §5 re-projection in the activate-commit path. `modules/base/activate.sh.in` is reused unchanged (§5.4 already exits `EX_DEGRADED=6`).


---

# Metadata and one-time provisioning implementation contract

> [`provisioning.md`](provisioning.md) is authoritative: literal authenticated
> `host.nix`, restricted `aos.provisioning` evaluation, strict Rust validation
> of the evaluated result, and a pending/committed GPT provenance protocol.

Returning the drop-in RFC markdown contract.

---

# `aos metadata` agent — implementation contract

> Historical scope only. This is not an implementation contract.

The agent acquires bytes, applies the selected host trust policy, and preserves
exact accepted `host.nix` bytes. A restricted Nix invocation evaluates only the
closed `aos.provisioning` projection in initrd, after which Rust validates and
renders storage. With no host input, that same projection supplies defaults.

## 1. Command surface

```text
aos metadata detect      # DMI/SMBIOS/ISO → /run/aos-metadata/platform.env (+ need-network, +cidata mount)
aos metadata fetch       # platform → exact host.nix transport + facts
aos metadata authorize   # platform|signed policy → exact accepted host.nix
aos metadata eval-provisioning # restricted Nix → validated transient repart.d
aos metadata persist-provisioning # first-commit evidence + reusable definitions
aos metadata cache-runtime       # cache only an input that produced a manifest
aos metadata restore-runtime     # hash-check and restore last evaluated input
```

- `detect` absorbs `pkgs/boot/aos-platform-detect.nix` verbatim (the asset-tag → vendor → bios → product table at lines 64–123) into `std::fs` reads of `/sys/class/dmi/id/*`. It writes `platform.env` and, for network-dependent platforms, touches the `need-network` flag the `aos-metadata-network` gate keys off (replacing today's `/run/ignition/need-network`).
- `detect` also performs the **config-drive probe** (the net-new mount helper, [§8](#8-net-new-pieces)) so that an offline ISO/vfat channel short-circuits the cloud path exactly as `aos-platform-detect.nix:51` does today for the `aos-metadata` label.
- `fetch` selects a `Box<dyn PlatformFetcher>` from `PLATFORM_ID` and writes only under `/run/aos-metadata`.
- `authorize` accepts platform delivery by default or verifies exact
  `host.nix` with the `aos-config` SSHSIG namespace in signed mode.
- `eval-provisioning` evaluates only the schema bundled in the base library;
  strict Rust validation rejects unsafe evaluated values before rendering.

The initrd graph is `aos-metadata-detect.service` →
`aos-metadata-network.service` → `aos-metadata-fetch.service` →
`aos-metadata-authorize.service` → `aos-provisioning-eval.service` →
`aos-repart.service`. Every phase uses
`DefaultDependencies=no` and `RemainAfterExit=yes`; authorization failure is
fatal before repart.

## 2. The `PlatformFetcher` trait

The trait isolates the thin per-platform knowledge layer (endpoint, header, label, encoding) over the reused `aos-net` plumbing. All fetchers share one `TransferEngine` and one `RetryConfig`.

```rust,ignore
/// A cross-cloud user-data + instance-metadata acquisition strategy.
///
/// Implementors encode one platform's documented contract (endpoint
/// paths, required headers, payload encoding, facts locations) over the
/// shared `aos_net::TransferEngine`. The trait is the only seam the
/// dispatcher knows about; selection is by `PLATFORM_ID` from `detect`.
#[async_trait::async_trait]
pub trait PlatformFetcher: Send + Sync {
    /// Stable platform identifier, matching `PLATFORM_ID` in platform.env
    /// (e.g. "aws", "nocloud", "config-drive", "qemu", "aos-metadata").
    fn platform_id(&self) -> &'static str;

    /// Acquires literal `host.nix`, or a pinned pointer to those exact bytes,
    /// plus a detached host SSHSIG when available.
    ///
    /// Returns `Ok(None)` when the platform has no user-data attached
    /// (a valid, non-error state ⇒ gen-0-only). Returns `Err` only on
    /// transport failure after retries are exhausted. Acquisition does not
    /// authorize the result; the following initrd phase owns that decision.
    async fn fetch_user_data(
        &self,
        engine: &TransferEngine,
        retry: &RetryConfig,
    ) -> anyhow::Result<Option<UserData>>;

    /// Acquire instance facts (hostname, ssh authorized keys, MAC→iface
    /// map, disk IDs, static network config) as a normalized struct.
    ///
    /// Facts are RECORDED PLATFORM INPUT (`facts_hash` in the
    /// manifest); a fetcher MUST NOT promote any fact into a security
    /// decision. Returns `Ok(Facts::default())` when a platform exposes
    /// no metadata document.
    async fn fetch_facts(
        &self,
        engine: &TransferEngine,
        retry: &RetryConfig,
    ) -> anyhow::Result<Facts>;
}

/// Operator user-data acquired before policy authorization.
pub enum UserData {
    /// Literal `host.nix`, including any aos.provisioning declarations.
    Inline { payload: Vec<u8>, sig: Option<String> },
    /// A size-cap pointer resolved with a mandatory content pin.
    Pointer {
        host_nix_url: String,
        sha256: String,
        sig_url: Option<String>,
    },
}

/// Normalized platform-supplied instance facts. Rendered to
/// `host-facts.nix` as `host.facts.*` (see §5).
#[derive(Default)]
pub struct Facts {
    pub hostname: Option<String>,
    pub ssh_authorized_keys: Vec<String>,
    pub instance_id: Option<String>,
    pub region: Option<String>,
    pub availability_zone: Option<String>,
    /// Stable MAC → kernel interface name, for networkd Match=.
    pub mac_to_iface: Vec<(String, String)>,
    /// Disk serial/wwn identifiers, for repart device matching.
    pub disk_ids: Vec<String>,
    /// Parsed static network config for DHCP-less clouds (see §6).
    /// `None` ⇒ the gen-0 DHCP seed is sufficient.
    pub network: Option<StaticNetwork>,
}
```

### Reuse map (binding)

| Need | Reused symbol | Location |
|---|---|---|
| GET/PUT + custom headers + plain `http://` | `TransferEngine::execute(TransferRequest)`; `TransferRequest::{get,put,with_header}` | `aos-net/src/transfer.rs:132`, `types.rs:125,151,218` |
| Read body | `TransferResult::body`, `body_string()`, `header()` | `aos-net/src/types.rs` |
| Retry/backoff | `RetryConfig` (default `max_attempts=3`, jitter on); engine auto-retries transient | `aos-net/src/retry.rs:13` |
| Content-pin on pointer fetch | `TransferRequest::with_hash(HashAlgorithm::Sha256, &pin)` | `aos-net/src/types.rs:209` |
| Per-request timeout | `tokio::time::timeout` shim wrapping `execute` | net-new, [§8](#8-net-new-pieces) |

The engine's `AuthStore` and `AuthStore::refresh_token` (OAuth2, `auth.rs:219`) are **not** used — IMDS auth is per-request `with_header`. The S3/SFTP protocol handlers and the git-object signature paths (`verify_commit_signature`, `check_downgrade`) are out of scope.

## 3. Offline-channel fetcher contracts

All offline channels resolve to a **mounted directory** under `/run/aos-metadata` produced by `detect`'s config-drive mount helper ([§8](#8-net-new-pieces)). The fetcher then reads files from that directory — no network. The mount helper records the resolved mountpoint in `platform.env` as `METADATA_DIR=<path>`.

### 3.1 `aos-metadata` ISO (AOS-native channel)

- **Detect:** `blkid -L aos-metadata` (already done by `aos-platform-detect.nix:51`); mount read-only at `/run/aos-metadata/media`. Sets `PLATFORM_ID=aos-metadata`, `METADATA_DIR=/run/aos-metadata/media`. Never sets `need-network`.
- **`fetch_user_data`:** read `${METADATA_DIR}/host.nix` plus optional
  `${METADATA_DIR}/host.nix.sig` as exact operator input.
- **`fetch_facts`:** read optional `${METADATA_DIR}/facts.json` if the operator pre-baked it; else `Facts::default()`.

### 3.2 NoCloud `cidata`

- **Detect:** `blkid -L cidata` (ISO9660 **or** vfat); mount RO at `/run/aos-metadata/media`. `PLATFORM_ID=nocloud`.
- **`fetch_user_data`:** read `${METADATA_DIR}/user-data` as literal
  `host.nix` (not cloud-init YAML); a sibling `user-data.sig` supplies the
  detached exact-input SSHSIG when present.
- **`fetch_facts`:** parse `${METADATA_DIR}/meta-data` (YAML — the vendored crate, [§8](#8-net-new-pieces)): `local-hostname` → `hostname`, `instance-id` → `instance_id`. `${METADATA_DIR}/network-config` (NoCloud netplan-v1/v2 YAML), when present, parses into `Facts::network` ([§6](#6-static-networking-seed)).

### 3.3 config-drive `config-2` (OpenStack)

- **Detect:** `blkid -L config-2`; mount RO at `/run/aos-metadata/media`. `PLATFORM_ID=config-drive`.
- **`fetch_user_data`:** read `${METADATA_DIR}/openstack/latest/user_data` as
  literal `host.nix`; use sibling `user_data.sig` as the exact-input signature.
- **`fetch_facts`:** parse `${METADATA_DIR}/openstack/latest/meta_data.json` (JSON, `serde_json`): `.hostname`, `.uuid` → `instance_id`, `.keys[].data` / `.public_keys` → `ssh_authorized_keys`, `.devices` → `disk_ids`. Parse `${METADATA_DIR}/openstack/latest/network_data.json` → `Facts::network` ([§6](#6-static-networking-seed)) — this is the metadata-delivered network for OpenStack.

### 3.4 QEMU `fw_cfg`

- **Detect:** QEMU DMI classification. `PLATFORM_ID=qemu`; no mount or network.
- **`fetch_user_data`:** read the `fw_cfg` blob via `std::fs` from
  `/sys/firmware/qemu_fw_cfg/by_name/<name>/raw`. AOS convention:
  `<name>` is `opt/org.andyl/host-nix` or
  `opt/org.andyl/host-nix.sig`.
- **`fetch_facts`:** `Facts::default()` (fw_cfg carries no standard facts document); hostname/keys, if needed, ride in `host.nix`.

## 4. AWS IMDSv2 fetcher (cloud exemplar)

The cloud exemplar; the GCP / Azure / DigitalOcean / OpenStack-IMDS fetchers follow the same shape (different base URL, header, encoding) and are recorded-fixture tested off-box.

- **Base:** `http://169.254.169.254` (plain HTTP, link-local). Every IMDS call is wrapped in the `tokio::time::timeout` shim ([§8](#8-net-new-pieces)) and the shared `RetryConfig`.
- **Token dance (mandatory):**

  ```rust,ignore
  // PUT the token request; 6h TTL.
  let token = engine.execute(
      TransferRequest::put("http://169.254.169.254/latest/api/token", Vec::new())
          .with_header("X-aws-ec2-metadata-token-ttl-seconds", "21600"),
  ).await?.body_string().ok_or_else(|| anyhow!("IMDSv2 token: empty body"))?;
  ```

  Every subsequent GET carries `.with_header("X-aws-ec2-metadata-token", &token)`.
- **`fetch_user_data`:** GET `/latest/user-data`.
  - HTTP 200 → body is literal `host.nix` or a
    `{ host_nix_url, sha256, sig_url }` transport pointer. Resolve pointers
    with `with_hash(Sha256, sha256)` before authorization.
  - HTTP 404 → `Ok(None)` (no user-data attached; **not** an error).
  - AWS uses the pointer form when `host.nix` exceeds the user-data size cap.
- **`fetch_facts`:** GET under `/latest/meta-data/`:
  - `instance-id`, `placement/region`, `placement/availability-zone`,
  - `public-keys/0/openssh-key` (iterate indices) → `ssh_authorized_keys`,
  - `local-hostname` → `hostname`,
  - `network/interfaces/macs/` listing → `mac_to_iface`.
  - AWS provides DHCP, so `Facts::network` is normally `None`.

## 5. Stash format

The stash is a child of the initrd `/run` so it survives `mount --move /run /sysroot/run` during switch_root (same rationale as `modules/services/ignition.nix:62–65`). Stage-2 stages it into the evaluator root `/run/aos-eval/`.

```text
/run/aos-metadata/
├── platform.env            # PLATFORM_ID=<id>  [+ METADATA_DIR=<path>]  [need-network adjacent]
├── user-data               # exact acquired input bytes
├── user-data.sig           # detached whole-input SSHSIG, when supplied
├── host.nix                # exact policy-accepted operator config
├── provisioning-plan.json  # canonical validated early projection
├── repart-targets          # stable device → definition directory index
├── repart.d/               # rendered transient per-device definitions
├── storage-coherence       # coherent | divergent | unavailable after commit
├── facts.json              # normalized Facts (see §2), serde_json
├── network/                # rendered networkd seed for DHCP-less clouds (see §6)
│   └── 10-aos-seed.network
├── .metadata-result.json   # acquisition record
└── .provisioning-result.json # authorization and accepted-content record
```

`platform.env` (consumed via systemd `EnvironmentFile`, same as today):

```text
PLATFORM_ID=aws
METADATA_DIR=/run/aos-metadata/media   # only for offline channels
```

`.metadata-result.json` — the acquisition marker:

```json
{
  "platform_id": "aws",
  "fetched_user_data": true,
  "user_data_source": "imds",
  "user_data_sha256": "…",
  "sig_present": false,
  "facts_hash": "…",
  "network_seed_written": false,
  "timestamp": "2026-06-26T00:00:00Z"
}
```

`.provisioning-result.json` records `trust_mode`, `platform_id`,
`input_sha256`, `host_nix_sha256`, optional `signer`, and
`storage_plan_rendered`. Those fields bind stage-2 to the initrd decision.

Stage-2 staging: `aos-eval.service` links `host.nix`, `facts.json`, and the
validation record into `/run/aos-eval/`, confirms the accepted host hash, and
renders `host-facts.nix` ([§5.1](#51-factsjson--host-factsnix)).

The durable state directory is `/var/lib/aos-provisioning`:

```text
audit.json                    # immutable first-commit evidence
initial-plan.json             # immutable normalized first-commit plan
desired/provisioning-plan.json
desired/repart-targets
desired/repart.d/             # usable for explicit later-device provisioning
current/host.nix
current/host.nix.sig
current/facts.json
current/.metadata-result.json
current/.provisioning-result.json
```

`desired/` is atomically replaced after a valid current projection.
`current/` is atomically replaced only after full stage-2 evaluation produced
a manifest. Restore verifies the recorded host hash before copying anything
back into the runtime stash.

### 5.1 `facts.json` → `host-facts.nix`

Facts enter eval **only** as typed `host.facts.*` declared inputs (D9), keeping eval a pure function of `(modules + host.nix + facts)`. Stage-2 renders `/run/aos-eval/host-facts.nix` from `facts.json`:

```nix
# /run/aos-eval/host-facts.nix — rendered, not operator-authored.
{
  host.facts = {
    hostname = "ip-10-0-1-22";
    instanceId = "i-0abc…";
    region = "us-east-1";
    availabilityZone = "us-east-1a";
    sshAuthorizedKeys = [ "ssh-ed25519 AAAA… op@host" ];
    macToIface = [ { mac = "0a:1b:…"; iface = "ens5"; } ];
    diskIds = [ "nvme-Amazon_Elastic_Block_Store_vol0abc" ];
  };
}
```

Binding constraints:

- The agent does **not** write `/etc/hostname` or `authorized_keys` imperatively; those become manifest outputs (so they participate in generations/rollback).
- **No pre-authorization SSH keys from the facts channel** (review M-gen0key): `host.facts.sshAuthorizedKeys` is a separate platform fact and must never be seeded into `/var/etc` in initrd for gen-0 login. Gen-0 reachability comes only from an image-baked key or one carried in policy-accepted provisioning input.
- `host.facts.*` is recorded under `facts_hash`; any module consuming it must treat it as data, never as an authorization.

## 6. Static-networking seed (DHCP-less clouds)

On clouds with no DHCP server (DigitalOcean static/anchor IPs, OpenStack `network_data.json`), the gen-0 DHCP seed (`modules/services/ignition.nix:795` `80-dhcp.network`) gets no lease, so stage-2 has no route to the registry and eval deadlocks. The **initrd `fetch` phase** therefore parses the platform network config and seeds a minimal static networkd config — a *substrate fact*, not operator config.

- **Parsed inputs:** OpenStack `network_data.json` (`.networks[]`: `link`, `ip_address`, `netmask`/cidr, `gateway`; `.links[]`: `ethernet_mac_address`); NoCloud `network-config` (netplan v1/v2 YAML); DigitalOcean IMDS `/metadata/v1/interfaces/public/0/{ipv4,anchor_ipv4}` + `/dns/nameservers`. Normalized into `Facts::network` (`StaticNetwork { iface_match, addresses, routes, dns }`).
- **Output (two locations):**
  1. `/run/aos-metadata/network/10-aos-seed.network` (recorded in the stash for attestation).
  2. The gen-0 `/var/etc` lower (so stage-2 networkd reads it before any config-gen): `mount-var`-time write of `/sysroot/var/etc/systemd/network/10-aos-seed.network`. This is the only `/var/etc` write the agent performs, and it carries **no security decision** (just an IP/route — like the IP itself).
- **networkd file written:**

  ```ini
  # 10-aos-seed.network — substrate-fact static seed (DHCP-less cloud).
  [Match]
  MACAddress=0a:1b:2c:3d:4e:5f
  [Network]
  Address=203.0.113.10/24
  Gateway=203.0.113.1
  DNS=67.207.67.2
  ```

- **Supersession:** the operator's *declared* network config in `host.nix` takes effect at the first `activate.sh.in` /etc swap and supersedes the seed. The seed exists only to give stage-2 a route to fetch config modules; it is not authoritative.
- The seed is written **only** when `Facts::network.is_some()`; DHCP clouds (AWS/GCP) skip it (recorded as `network_seed_written: false`).

## 7. Authenticated one-time provisioning projection

`host.nix` may define `aos.provisioning.storage.partitions`, an attribute set
whose closed schema is declared by `modules/base/provisioning.nix`. The initrd
imports the ABI-pinned base library and exact authorized host module under
`restrict-eval=true` and `allow-import-from-derivation=false`. It does not load
runtime package modules. Undeclared runtime definitions remain lazy and cannot
affect the early result.

Rust deserializes the evaluated `aos.provisioning-plan/v1` JSON with unknown
fields denied. It permits `null` for the root disk or stable
`/dev/disk/by-id/...` targets, validates labels/sizes/UUIDs, rejects protected
partition types and the reserved sentinel GUID, and permits at most one grow
partition per device. Measured-boot `var` remains raw; the unmeasured default is
ext4.

The hard ordering is:

```text
durable-state-detect → metadata-fetch → authorize exact host.nix
  → restricted aos.provisioning eval → Rust validate/render
  → dry-run every disk → mutate every disk → commit GPT provenance marker
  → aos-var-crypt/mount-var → switch_root → full aos-eval
```

The renderer adds `aos-provisioning-pending-v1` using the reserved GPT type GUID
in the same transaction as the root-disk definitions and orders the root target
before every secondary device. Only after every device succeeds does the unit
relabel it to `aos-provenance-operator-v1` or
`aos-provenance-fallback-v1`. A pending marker fails closed for recovery. A
committed marker freezes all future disk mutation, while metadata acquisition,
restricted advisory evaluation, dry-run comparison, and full runtime
evaluation continue. With no host input, the same schema defaults are evaluated
and committed as fallback provenance; there is no image-baked parallel layout.

## 8. Net-new pieces (the bounded build)

Everything else is reuse; these four are the genuinely-new code, all small and independently testable.

1. **Config-drive mount helper** — the only capability with no aos primitive. Probe `blkid -L {aos-metadata,cidata,config-2}` (ISO9660/vfat), mount RO, record `METADATA_DIR`. Implementation: shell out to `pkgs.util-linux` `blkid`/`mount` (as `aos-platform-detect.nix:51-54` does) or bind `libblkid`. Must run in `detect`, before the cloud path, so an offline channel short-circuits the network.
2. **Vendored YAML crate** — no YAML crate in `Cargo.lock`; vendor one to parse NoCloud `meta-data` / `network-config` and any cloud-config-shaped facts. JSON (`serde_json`) and TOML (`toml`) are already present.
3. **`tokio::time::timeout` shim** — `aos-net`'s client is a process-wide singleton with only a 10s `connect_timeout`, and `HttpProtocol::with_client` isn't wired through the engine. Wrap each IMDS `engine.execute(...)` in `tokio::time::timeout` so a black-hole metadata endpoint can't wedge boot.
4. **Per-platform fetchers** — thin `PlatformFetcher` impls (facts-from-docs over `TransferEngine` + `with_header` + `RetryConfig`), recorded-fixture tested off-box. AWS IMDSv2 ([§4](#4-aws-imdsv2-fetcher-cloud-exemplar)) is the reference impl; GCP (`Metadata-Flavor: Google`), Azure (`Metadata:true` + base64 + OVF), DigitalOcean, OpenStack-IMDS follow.

All advertised offline and cloud fetchers are native and recorded-fixture
tested. Ignition compatibility is not part of the end-state contract.

---

Grounding files: `docs/rfcs/0011-on-host-config-eval/provisioning.md`, the
historical Ignition service and platform-detection package removed by this RFC,
`crates/aos-net/src/{transfer.rs,types.rs,retry.rs,protocol/http.rs}`, and
`crates/aos-package/src/security.rs`.


---

# Trust + secrets implementables (attestation, secretRef, F1 wiring)

Based on the RFC and grounding code, here is the drop-in RFC markdown.

# Contract: trust + secrets implementables

This document is the implementation contract for the trust, measured-boot, and
secrets implementables specified in [`trust-and-secrets.md`](trust-and-secrets.md),
incorporating the **F1** locked decision (dm-verity-protected erofs root with the
roothash on the measured UKI `.cmdline`). It pins exact schemas, field
derivations, the verifier algorithm, the `secretRef` type and its activation
resolution steps, provisioning authorization and stage-2 binding, and the F1 dm-verity wiring
at implementation depth. Each clause names the code it lands in.

Grounding files:
`modules/base/secure-boot.nix`, `modules/security/verity.nix`,
`crates/aos-package/src/security.rs`, `crates/aos-package/src/verify.rs`,
`crates/aos-package/src/registry/verify.rs`,
`crates/aos-package/src/credential_artifact.rs`,
`crates/aos-package/src/types.rs`,
`lib/build/{rootfs.nix,package-root-image.nix}`,
`pkgs/boot/aos-uki.nix`, `modules/image/_builder.nix`,
`modules/base/{boot.nix,filesystems.nix,system.nix}`,
`modules/services/ignition.nix`.

---

## 1. The `aos.gen-attestation/v1` record

### 1.1 Producer

A new module in `aos-package` (`crates/aos-package/src/attestation.rs`) emits the
record after a generation is materialized and `activate <N>` succeeds. It is a
serde struct serialized to **canonical JSON** (BTreeMap key ordering, no
insignificant whitespace — the same canonicalization the manifest hash uses).
Each completed activation has a fresh random identity, so reactivating an old
generation produces new evidence without changing that generation's manifest
identity.

### 1.2 Wire schema

```text
aos.gen-attestation/v1  (canonical JSON; field order below is the struct order)

  schema          : "aos.gen-attestation/v1"            # literal discriminator
  activation_id   : "sha256:<hex>"  # unique identity of this activation attempt
  generation_id   : "sha256:<hex>"  # content hash of the materialized config-generation
  manifest_hash   : "sha256:<hex>"  # canonicalized manifest, verify.rs::sha256 form
  inputs:
    base_lib:
      pcr11_expected      : "sha256:<hex>" | null  # predicted PCR-11 for a measured image
      abi_hash            : "sha256:<hex>"   # hash(base-lib module API ++ module_abi)
      module_abi          : <u32>            # AOS_MODULE_ABI from /etc/os-release
      root_verity_roothash: "<64-hex>" | null  # F1: Merkle root of the erofs root (dm-verity)
      root_verity_uuid    : "<uuid>"         # F1: optional; omitted when unavailable
    evaluator:
      store_path          : "/nix/store/<hash>-aos-eval-<ver>"
    config_modules:
      registry            : "<name>"
      release_tag         : "<semver>"       # verify_tag_chain target
      tag_signer_key      : "<fingerprint>"  # security.rs::key_fingerprint, 8 hex
      realization         : "sha256:<hex>"   # hash of consumed signed store/ subset
    host_nix:
      content_hash        : "sha256:<hex>"   # sha256 of the operator config bytes
      trust_mode          : "<platform|signed|image>"
      platform            : "<aws|gcp|...|image>"  # platform/image mode
      signer_key          : "<fingerprint>"  # signed mode only
    instance_facts:
      facts_hash          : "sha256:<hex>"   # canonical host.facts.* tree
      platform            : "<aws|gcp|...>"
  eval_mode       : "pure-eval"
  quote_status    : "quoted" | "unquoted-tpm-unavailable"
  quote           : <TPM2 quote blob>        # see §1.4
```

`root_verity_roothash` and `root_verity_uuid` under `inputs.base_lib` are the
**F1 extension**. Everything else is the `trust-and-secrets.md` schema made
concrete.

`quoted` requires both a TPM and authenticated dm-verity metadata for the
running image. The v1 literal `unquoted-tpm-unavailable` is retained whenever
that complete binding is unavailable, including a TPM host running an image
without an immutable root binding. When measured-image policy requires a
quote, either missing prerequisite fails activation closed instead of
producing an unquoted record.

The quote decision is normative:

| Quote required | TPM | Root verity | Result |
|---|---|---|---|
| no | no | either | unquoted record |
| no | yes | no | unquoted record |
| no | yes | yes | quoted record |
| yes | no | either | activation fails closed |
| yes | yes | no | activation fails closed |
| yes | yes | yes | quoted record |

Quote policy is required when either `expected_pcr11` is present, or both the
seed image's observed `initrd_pcr11` and `root_verity_roothash` are present.
An observed initrd PCR alone proves only that a TPM is available; it does not
turn an unmeasured image into measured-image policy.

### 1.3 Field derivation (exactly how each is computed)

- `generation_id` — the content hash APM already assigns the materialized
  generation directory; read from the generation record, not recomputed.
- `activation_id` — `sha256:` plus 32 bytes from the OS CSPRNG, generated for
  every successful activation. A crash retry reuses the transaction's retained
  value; a later reactivation or same-ABI rollback always gets a new value.
- `manifest_hash` — `verify::sha256_stream` over the canonicalized manifest JSON.
  Format `sha256:<hex>` (`verify.rs:55`).
- `base_lib.pcr11_expected` — read from the authenticated image record. For a
  registry image this is the stable `ready`-phase PCR-11 prediction in the
  signed release catalog (`registry-catalog.md:42-52`). For the seed image,
  `aos-uki.nix` computes the prediction from the finalized UKI sections and
  emits a sidecar signed by the PCR-policy key and bound to the SHA-256 of the
  exact UKI. The image builder copies those derivation outputs to the ESP by
  Nix interpolation, and `aos-image-measurement-index.service` verifies the
  signature, embedded public key, and UKI hash before importing the value into
  the seed image record. It is never recomputed from, or replaced by, a live
  TPM reading.
- `base_lib.abi_hash` — `sha256` over the canonicalized base-lib module option
  schema (the options-only eval surface) concatenated with `module_abi`.
- `base_lib.module_abi` — parsed from `AOS_MODULE_ABI` in `/etc/os-release`
  (running image, no network trust). Produced by `aos.system.moduleAbi`
  (`modules/base/system.nix`).
- `base_lib.root_verity_roothash` — **F1**: read from `/proc/cmdline`'s
  `roothash=<hex>` token (which sd-stub measured into PCR 11; §4). The on-host
  producer does not derive it — it reports the value the kernel was given, and
  the verifier independently confirms it equals the published image's
  `root.roothash` (§4.5). Validated `^[0-9a-f]{64}$`.
- `base_lib.root_verity_uuid` — read from `veritysetup status root` (the verity
  superblock UUID) when the mapper device is present.
- `evaluator.store_path` — the resolved store path of the `aos-eval` binary
  consumed by `aos-eval.service`; this path is ⊂ the measured UKI's covered
  closure only transitively via the root (F1) — recorded for re-derivation.
- `config_modules.origins` — one `registry` or `image` origin aligned with each
  module path. `image` means the exact config companion came from the active
  image-seeded package profile. The evaluator resolves the booted toplevel's
  `package-profile-seed` through `/nix.lower/store`, requires the mutable
  profile record to exactly match that immutable seed record, requires all
  referenced outputs to exist in the immutable lower store, and hashes the
  lower-store NAR bytes. A remote verifier independently reconstructs the same
  image-module catalog and requires an exact tuple match; a claimed
  `origin=image` value absent from that catalog fails closed.
- Registry-origin `config_modules.*` — from the resolver's `TrustContext`: `registry`,
  `release_tag` (the `verify_tag_chain` target, `registry/verify.rs:99`),
  `tag_signer_key` (`security.rs::key_fingerprint`), `realization` (sha256 of the
  signed `store/` graph subset consumed, the blessed set `verify.rs::verify_nar_blessed`
  validated). Sync publishes a cache-local release receipt only after tag-chain
  verification and invalidates any older receipt before replacing extracted
  registry data. The receipt is transport evidence, not a trust anchor: remote
  verification independently checks the tag, signer roster, realization, and
  exact module catalog. Branch/commit/default or otherwise unsigned syncs do
  not produce a receipt and therefore cannot attest a non-empty
  registry-origin module subset. A generation may mix this one authenticated
  registry release with measured image-local modules; the release identity and
  realization cover only the registry-origin subset while `closure_hash`
  covers the complete ordered input set.
- `host_nix.content_hash` — `sha256` of the exact `host.nix` bytes that were fed
  to the evaluator (the store-path-pinned content; §3, §F1-Q5).
- `host_nix.trust_mode` plus `platform` or `signer_key` — evidence for the
  policy that accepted the input. Exactly the policy-appropriate field is
  present; no record is emitted when authorization fails. The `image` mode is
  reserved for `platform = "image"` and the evaluator's exact image-authored
  empty module. It is not an operator-input authorization mode, and verifier
  step 10 is mandatory for it.
- `instance_facts.facts_hash` — `sha256` of the canonical `host.facts.*` tree
  (M-facts); `platform` the IMDS platform tag.
- `eval_mode` — literal `"pure-eval"`; asserts the determinism precondition.

### 1.4 Quoting into a PCR

The record is bound to the TPM by **extending its hash into application PCR 15**,
then taking a quote over the boot PCRs plus 15:

1. Canonicalize the record **without** the `quote` field → `record_bytes`.
2. `record_hash = sha256(record_bytes)`.
3. Append the canonical event to the shared AOS CEL, then extend PCR 15 with
   `record_hash`: `TPM2_PCR_Extend(15, record_hash)` (sd's app-PCR convention;
   PCR 15 is the agreed application slot — distinct from the sealed-`/var` PCRs
   7 and 11 so the seal policy is untouched).
4. `quote = TPM2_Quote(PCR { 7, 11, 12, 15 }, nonce)`. The `nonce` is the verifier's
   challenge (online attestation) or `record_hash` itself (offline/self-describing).
5. Serialize `quote` (TPM2B_ATTEST + TPMT_SIGNATURE, AK-signed) into the record's
   `quote` field and persist the full record alongside `gen-N/manifest.json`.

The producer writes a durable, input-bound attestation transaction marker,
including `activation_id`, before appending the CEL event. CEL append is fsynced
before PCR extension. On retry, the producer validates the marker and exact CEL
event, replays the CEL prefix, and compares it with live PCR 15: it extends only
when the event is logged but not yet reflected in PCR 15, skips extension when
already reflected, and fails closed on any ambiguous history or later event.
Quote artifacts may then be regenerated without extending again. The marker is
removed durably only after both the quote directory and canonical record are
published. A later activation has no marker to resume, so it creates a fresh
identity, appends another CEL event, extends PCR 15 again, and replaces the
generation's current evidence. Repeated `generation_id` values are therefore
valid; repeated `activation_id` values are not.

The seal mechanism is **unchanged**: `/var` stays sealed to PCR 11 (signed) + PCR
7 (pinned) per `secure-boot.nix`. The roothash rides inside PCR 11 for free (§4);
no new sealed PCR is introduced. PCR 15 carries only the attestation evidence,
never the seal.

### 1.5 Verifier algorithm

A remote verifier (or `aos attest verify`) confirms a box derived its generation
only from trusted inputs:

```text
verify(record, ak_pubkey, registry_catalog, trusted_config_keys, trusted_platforms, expected_facts?):
  1. schema == "aos.gen-attestation/v1"
       AND activation_id is canonical and unique in the CEL     else FAIL(schema)
  2. quote signature valid under ak_pubkey over (PCR{7,11,12,15}, nonce)  else FAIL(quote)
  3. validate the CEL prefix preceding this generation event;
     replay its ordered SHA-256 event digests from the validated CEL PCR
     baseline (or the all-zero reset value when no baseline event exists),
     then extend sha256(record\quote);
     PCR15 in quote == the replayed result                       else FAIL(record-binding)
  4. PCR7  in quote == catalog.expected_pcr7  (SB-state pin)     else FAIL(sb-state)
  5. PCR11 in quote == record.inputs.base_lib.pcr11_expected
        AND == catalog.expected_pcr11 for that UKI               else FAIL(pcr11)
  6. F1 root binding:
       extract roothash token from the UKI .cmdline the catalog published;
       record.inputs.base_lib.root_verity_roothash == that token
         == catalog.image.root.roothash (root.roothash file)     else FAIL(root-verity)
  7. config_modules.release_tag is signed by a roster key in catalog,
       not revoked: verify_tag_chain(release_tag) succeeds        else FAIL(tag)
       AND tag_signer_key ∈ catalog roster fingerprints
       AND strict receipt registry/tag/commit/signer fields equal the
           independently reverified release object
       AND module membership, NAR hashes, and realization are reconstructed
           from that signed commit
       AND every image-origin module exactly matches the verifier's immutable
           image package-seed catalog (path, NAR identity, ABI, and authorized
           option roots); no uncataloged image tuple is accepted
  8. host_nix.trust_mode == "platform"
       AND host_nix.platform ∈ trusted_platforms
     OR host_nix.trust_mode == "signed"
       AND host_nix.signer_key ∈ trusted_config_keys fingerprints
     OR host_nix.trust_mode == "image"
       AND host_nix.platform == "image"
       AND host_nix.signer_key is absent
                                                                  else FAIL(host-config-trust)
  9. eval_mode == "pure-eval"                                    else FAIL(eval-mode)
 10. (optional for platform/signed; REQUIRED for image, full re-derivation)
       given the authenticated inputs
       (base-lib@pcr11_expected, evaluator@store_path,
        config_modules@realization, host_nix@content_hash,
        instance_facts@facts_hash), re-run the pure eval and check
        sha256(canonical(manifest)) == record.manifest_hash      else FAIL(rederive)
 11. before blessing a counted boot, the local boot-commit verifier validates
       the stored TPM quote signature and nonce, requires PCR 7 and ready-phase
       PCR 11 in that quote to equal the live values, and requires PCR 11 to
       equal the independently published image value. A missing or failed
       systemd-pcrphase ready transition prevents evaluation and blessing.
  => PASS
```

Steps 4–6 are the heart of the F1 closure: PCR 11 covers the `.cmdline`, the
`.cmdline` carries `roothash=<hex>`, and `<hex>` is the Merkle root over every
byte of the erofs root carrying base-lib + evaluator. Step 6 lets the verifier
independently confirm the booted roothash equals the published image's root
without trusting the box. Step 10 upgrades attestation to full re-derivation, the
property the manifest's signature-free trust model rests on.
For the no-input `image` arm, step 10 is also the authorization proof: the
PCR-bound evaluator must reproduce the manifest from its exact empty host
module. A verifier that cannot re-derive MUST reject `trust_mode = "image"`.

---

## 2. The `secretRef` type and the activation resolution contract

### 2.1 Inhabitants

`secretRef` is the **only** secret-bearing value the evaluator may produce. It is
`Serialize`-compatible with `CredentialMeta` (`types.rs:690`,
`#[serde(deny_unknown_fields)]`), so no manifest schema change is required — a
`secretRef` *is* a `CredentialMeta` plus an optional resolver discriminator.

```text
secretRef (Nix value graph) ≡ CredentialMeta + ref:

  name      : str            # systemd credential id (the handle)
  source    : str            # credstore PATH (never a value)
  encrypted : bool           # at-rest sealed (default true)
  units     : [str]          # units that consume it (restart targets)
  ref       : str?           # resolver discriminator (NEW, optional)
  ciphertext: str?           # inline sealed payload (existing CredentialMeta field)
```

`ref` ∈ a closed, extensible discriminator set:

| `ref` value         | resolver | bytes come from |
|---------------------|----------|-----------------|
| `tpm2-credstore`    | vendored/build-time-sealed `encryptedFile` blob already in the credstore | image |
| `desired-toml`      | `credential_artifact.rs::reconcile_desired_credentials` | `desired.toml [credentials]` |
| `system-credential` | pass-through from `/run/credentials/@system/` | platform (`desired.rs`) |
| `vault` / `aws-sm`  | reserved for the future secret system (deferred) | external backend |

When `ref` is absent the resolver is inferred exactly as
`credential_artifact.rs` does today: inline `ciphertext` ⇒ image-sealed;
`source` under `/etc|/run/credstore*` ⇒ desired/credstore; `DesiredCredentialValue::Source`
⇒ `system-credential`.

### 2.2 Type-level enforcement of the no-plaintext invariant

The `{pkg}.credentials.*` option and the `aos.host.credentials.*` option are thin
wrappers that construct a `secretRef`. They expose **no** `value=`/`text=`
constructor — there is no plaintext field in `CredentialMeta` and
`deny_unknown_fields` rejects one on deserialize. This is the type-level
enforcement of: *secret material must never appear in any value the evaluator
produces.* TPM2/PCR-11-sealed `ciphertext` is permitted (inert without the host
TPM in the right measured state); plaintext is structurally unrepresentable.

The publish-time lint (`module-system.md`, the `config`-output probe-eval) is the
backstop: it `deepSeq`s each rendered `config` value and fails publish if any
reachable string's `getContext` indicates a derivation, but a `secretRef`
contributes only stable identifiers, so it always passes.

### 2.3 Activation resolution contract

Given a `secretRef`, **before the consuming unit starts**, the resolver MUST:

```text
resolve(secretRef sr, root):                          # reuses credential_artifact.rs
  1. validate sr.name           -> validate_credential_name(sr.name)
  2. require sr.source          -> else FAIL("does not declare a credstore source")
  3. validate provisionable     -> validate_provisionable_source(pkg, sr, sr.source)
       (reject /usr/lib/credstore*, reject /run/credstore.encrypted/aos/*,
        reject when ciphertext already inline)
  4. obtain plaintext bytes by ref:
       desired-toml      -> DesiredCredentialValue::Plaintext | ::Source
       system-credential -> read /run/credentials/@system/<name> (regular file only)
       tpm2-credstore    -> bytes already present; no-op materialization
  5. if sr.encrypted:
       bytes = run_systemd_creds_encrypt(sr.name, pcr_pub_key, plaintext)
         args: encrypt --name=<name> --with-key=tpm2
               --tpm2-public-key=<pcr_pub_key> --tpm2-public-key-pcrs=11
       pcr_pub_key defaults to /etc/aos/pcr-sign.pem (credential_pcr_public_key)
     else bytes = plaintext
  6. write bytes to the credstore path(s) for sr.source, mode 0600,
       parent dirs 0700, atomic temp+rename       -> write_credential_source
       (for /etc/credstore* this dual-writes var/etc/... AND etc/...;
        for /run/credstore* it writes only the live root)
  7. if bytes changed on disk: restart_units.extend(sr.units)
  8. after all secretRefs resolved: for unit in restart_units:
       systemctl restart <unit>                    -> apply_credential_reconciliation
```

Steps 1–8 are **exactly** `credential_artifact.rs::reconcile_desired_credentials`
→ `materialize_package_credentials` → `write_credential_source` →
`CredentialReconciliation::apply`. The contract names the existing
`desired.toml` resolver as the reference implementation; the future secret system
slots in at step 4 by adding a `ref` arm without touching steps 5–8. **systemd
credentials are the universal delivery interface**, so no package depends on
which backend produced the bytes.

The encryption PCR is pinned to **11** (`systemd_creds_encrypt_args`,
`credential_artifact.rs:476`), matching the signed-policy seal of `/var` and
`secure-boot.nix`'s `signedPcrs = "11"`. Encrypted credentials therefore require
`/etc/aos/pcr-sign.pem` (the `pcrKeyForInitrd` material, `secure-boot.nix:303`),
and resolution **fails closed** when it is absent — never falling back to
plaintext at rest.

### 2.4 Determinism

A `secretRef` contributes only `{name, source, encrypted, units, ref}` to the
hashed graph. Rotating a value changes bytes on disk but not the manifest store
path. The generation hash is a function of references, never of secret material.

---

## 3. Provisioning authorization and stage-2 binding

### 3.1 Boundary

The initrd fetches literal `host.nix`, or resolves a hash-pinned transport
pointer to those exact bytes. The image policy is `platform` by default or
`signed` in secure mode. Platform mode accepts delivery by the detected
control-plane channel. Signed mode verifies a detached SSHSIG over exact
`host.nix` bytes against public anchors included in the measured initrd.
`trust_mode` is measured boot configuration, is not accepted from user-data,
and cannot fall back from `signed` to `platform`.
If no operator input exists and no operator-backed generation has been
committed, stage 2 may evaluate only the image-authored empty module and records
that distinct no-input case as `trust_mode = "image"`; it is never a fallback
from a failed platform or signed authorization.

Authorization occurs before restricted evaluation. Stage-2 does not repeat
the trust decision over mutable input: it verifies that `/run/aos-eval/host.nix`
has the content hash recorded by initrd, then evaluates those exact bytes.

### 3.2 Verification algorithm

```text
authorize_host(host_nix_bytes, detached_sig, policy, platform, key_store):
  1. if policy == "platform":
       require detected platform channel and successful acquisition
       return Trusted(mode = platform, platform, sha256(host_nix_bytes))
  2. require policy == "signed" and detached_sig is present
  3. keys = key_store.lookup_all(operator_id)
  4. for key in keys:
       ok = verify_payload_signature(
              payload = host_nix_bytes,
              signature = detached_sig,
              trusted_key = key.key_line(),
              namespace = "aos-config")
       if ok: return Trusted(mode = signed, signer_key, sha256(host_nix_bytes))
  5. FAIL("host.nix is not signed by a trusted config key")
```

This reuses `security.rs::verify_payload_signature` (`security.rs:639`) and the
`KeyStore` (`security.rs:73`) unchanged. The operator id `<op>` is the
`KeyStore` "registry" field; the trust file is
`trusted-config-keys.d/<op>.pub` carrying `<op>:Ed25519:<base64>` lines,
mirroring `trusted-keys.d` and `trusted-sb-certs.d` written by
`modules/base/apm-registries.nix`. Key rotation, multi-key overlap, and
`# revoked:` masking come for free from `lookup_all`.

### 3.3 SSHSIG namespace

The detached signature is an armored SSHSIG produced by
`security.rs::sign_payload_signature(key, "aos-config", host_nix_bytes)`
(HashAlg::Sha512, `security.rs:619`) — the same OpenSSH format `ssh-keygen -Y
sign -n aos-config` emits. The namespace string is the literal
**`aos-config`**,
distinct from the `git` namespace used by `verify_commit_signature` /
`verify_tag_signature` so a config signature can never be replayed as a tag/commit
signature and vice versa. Verification uses the same namespace; a namespace
mismatch yields `Ok(false)` and fails closed.

### 3.4 Failure behavior

An unavailable platform channel or signed-mode authentication failure is
fail-closed. The initrd stops before evaluating `aos.provisioning` or mutating
GPT; it never falls back to an unauthenticated storage plan. Without accepted
`host.nix`, stage 2 produces no manifest and leaves the prior generation live.
Facts must never seed security decisions before the selected policy accepts
provisioning input.

### 3.5 Pinning (F1-Q5)

The authenticated `host.nix` bytes are recorded as a **store path / content
hash** in the config-gen record's `host_nix_ref` field and GC-rooted by the
per-gen `gen-N/cfgsrc/<hash>` root. Image-rollback re-eval feeds that exact store
path back into the evaluator (cache-hit, deterministic) — never a mutable git
ref. A non-authoritative git-commit-sha MAY also be recorded as provenance
metadata, but the binding-of-record is the content hash. `host_nix.content_hash`
in the attestation record (§1.3) is this value.

---

## 4. F1: dm-verity / roothash wiring

The on-host evaluator and base lib live as large store paths on the **erofs
root**, not in the UKI. F1 anchors that root to measured boot by dm-verity-
protecting it and baking the verity root hash into the UKI's `.cmdline` PE
section, so it is measured into PCR 11 (covered by the signed PCR policy) and by
the whole-PE Authenticode signature.

### 4.1 Build side — `lib/build/rootfs.nix` (gated `verity` sub-step)

Add param `verity ? false` (set true only for the production erofs path;
ext4/VM-test images unchanged). After `root.img` is finalized:

1. Derive `$SALT` and `$VUUID` deterministically from image identity via the
   existing `mkUuid`/substring-of-sha256 seed pattern
   (`package-root-image.nix:24-33`), so the roothash is reproducible across two
   builds.
2. `veritysetup format --salt "$SALT" --uuid "$VUUID" root.img root.verity`.
3. Parse `Root hash:` from `veritysetup` output into `root.roothash`
   (the `gawk -F:` recipe at `package-root-image.nix:154-169`); validate
   `^[0-9a-f]{64}$`.
4. When an SB db key is supplied (deployment overlay), sign the roothash —
   identical to `package-root-image.nix:170-186`:
   `openssl cms -sign -binary -in root.roothash -signer $CERT -inkey $KEY
   -outform DER -out root.roothash.p7s -nosmimecap -noattr`, then
   `openssl cms -verify` and `veritysetup verify` self-checks.
5. Emit `$out/{root.verity, root.roothash, root.roothash.p7s,
   root-verity-size-bytes}` alongside `root.img`.

erofs needs no shrink/normalize step (it is content-sized, `-T0 -U` fixed), so
the hash tree is over stable bytes. The unsigned base image stays reproducible
and key-free: the anchoring needs only `root.roothash` (key-independent); the
`root.roothash.p7s` is the optional SB-db-keyed in-kernel roothash signature that
`pkgs/security/aos-verity-root-guard.nix` validates against the SB db.

### 4.2 Build side — `pkgs/boot/aos-uki.nix` (the load-bearing append)

Add optional arg `rootHashFile ? null`. In the build phase, when set, append the
**build-time** hash to the materialized cmdline before ukify
(`aos-uki.nix:103`):

```text
printf '%s roothash=%s' "${cmdline}" "$(cat ${rootHashFile})" > cmdline
```

The roothash is a build-output (Merkle root of `root.img`), unknowable at Nix
eval, so it cannot travel through `aos.boot.kernelParams`. Injecting it here puts
it into the same `.cmdline` section that ukify measures
(`--pcr-private-key=${pcrPrivateKey}`, `aos-uki.nix:68,124`) and that the db key
Authenticode-signs — so the roothash is simultaneously in PCR 11 and under the
whole-PE signature.

### 4.3 Build side — `modules/image/_builder.nix`

1. Thread `rootHashFile = "${rootfs}/root.roothash"` into the `pkgs.aos-uki { … }`
   call.
2. Add GPT partition 3 `root-a-hash`: size from `${rootfs}/root-verity-size-bytes`,
   place immediately after `root-a` in the `sfdisk` table, `dd` `root.verity`
   into it, bump `disk_sectors`/`root_start_sector` accounting, record it in
   `image-info.json` (leave trailing free space for ignition's var/swap/root-b).
   Use the Linux-filesystem type GUID or the DPS root-verity GUID
   `2c7357ed-ebd2-46d9-aec1-23d437ec2bf5`; device discovery is by partlabel so
   either works.

### 4.4 Eval side — `modules/security/verity.nix` (rewritten)

Replace the current dracut-style `verity.data=/verity.hash=/verity.roothash=`
params (`verity.nix:74-79`, wrong for a systemd initrd) and drop the eval-time
`rootHash` option from kernelParams (the roothash is supplied by the build-time
UKI append, §4.2). New eval-side params use the **systemd-veritysetup-generator**:

```text
aos.boot.kernelParams += [
  "systemd.verity=yes"
  "systemd.verity_root_data=/dev/disk/by-partlabel/root-a"
  "systemd.verity_root_hash=/dev/disk/by-partlabel/root-a-hash"
]
```

The generator unions `roothash=<hex>` (from the measured `.cmdline`) with these
device params to assemble `/dev/mapper/root`. Keep `dm_verity` in
`aos.boot.initrd.modules` (`verity.nix:83-89`).

### 4.5 Eval side — make `root=` follow the mapper device

1. Parameterize `modules/base/boot.nix`'s hardcoded
   `root=/dev/disk/by-partlabel/root-a` off
   `config.aos.filesystems.rootDevice` (default
   `/dev/disk/by-partlabel/root-a`).
2. `verity.nix` sets `aos.filesystems.rootDevice = "/dev/mapper/root"` and the
   matching fstab device in `modules/base/filesystems.nix`. This flips `root=`
   to the verity-assembled device without `mkForce` list surgery.
3. Guard ignition's grow-root unit (`modules/services/ignition.nix`) to
   ext4-only (`rootFsType == "ext4"`): an erofs+verity root must never be grown
   (growing would change bytes and break the roothash).

### 4.6 Eval side — implemented production image wiring

The production-integrity variant is `systems/server-verity.nix`. It imports
`systems/server-measured-boot.nix`, inherits its erofs root, and enables:

```text
aos.security.verity.enable = true;
# server-measured-boot -> server supplies rootFsType = "erofs"
# the image builder derives verity = true from aos.security.verity.enable
```

Ordinary VM tests may keep `ext4` + verity off; `checks.fleet.measured-boot`
boots `systems.server-verity` and verifies the live mapper, command-line root
hash, GPT hash partition, attestation binding, and tamper rejection.

### 4.7 PCR-11-covers-root proof

sd-stub measures `.cmdline` (now containing `roothash=<hex>`) into PCR 11; `<hex>`
is the Merkle root over every byte of the erofs root carrying base-lib +
evaluator. To make a tampered root mountable, an attacker must change `<hex>` →
change `.cmdline`, which (i) breaks the whole-PE db Authenticode signature
(enforcing SB firmware refuses to load it; attacker lacks the db key) and (ii)
changes PCR 11 to a value the signed PCR policy does not bless (attacker lacks the
release PCR-policy key) → sealed `/var` will not unseal (the
`aos-var-crypt` TPM2 unlock fails closed, `secure-boot.nix:382-397`). Tampering
without changing `<hex>` is caught by the kernel dm-verity target at first read
(EIO) → fail closed. PCR 11 therefore transitively covers the producer (evaluator
+ base lib), closing the C1/F1 gap.

### 4.8 Reproducibility, A/B, and the seal

- The roothash is a deterministic function of the reproducible erofs image given
  pinned salt/uuid (gated identical-across-two-builds by the
  `package-root-image` checks). The UKI stays byte-reproducible. The P0
  byte-identical-toplevel gate is unaffected (the UKI/image layer is below
  toplevel).
- A/B is naturally supported: each UKI is self-describing about its root —
  slot A = `{root-a, root-a-hash, UKI-A(cmdline→hash-A)}`; a sysupdate slot B
  builds `{root-b, root-b-hash, UKI-B(cmdline→hash-B with
  systemd.verity_root_*=…root-b*)}`. The only A/B follow-on (sysupdate-side, not
  blocking F1's first-boot install which ships slot A) is making the device
  partlabels per-slot in the B-slot UKI's cmdline.
- Seal mechanism unchanged: PCR 11 (signed) + PCR 7 (pinned); the roothash rides
  inside PCR 11 for free, no new PCR or step. `apr publish --image <uki>` already
  records the ukify-predicted PCR 11 from the signed UKI; because the roothash is
  in that UKI's cmdline, the recorded `expected_pcr11`/`base_lib.pcr11_expected`
  now genuinely covers the root.

### 4.9 Measured locus and retention (F1-Q1/Q2)

- `modules/base/system.nix` os-release adds `AOS_MODULE_ABI=${toString
  cfg.moduleAbi}` and `AOS_BASELIB_DIGEST=${baselibDigest}` next to
  `AOS_STATE_VERSION`; this file is passed to ukify as `--os-release=@${osRelease}`
  (`aos-uki.nix:125`) and lands in the `.osrel` PE section measured into PCR 11.
  Add `aos.system.moduleAbi` (int, default 1). The on-host resolver reads
  `AOS_MODULE_ABI` from `/etc/os-release` for the pre-eval ABI gate.
- Retention: a per-image-gen GC root `baselib/<module_abi>` pins only the
  base-lib/evaluator closure (not kernel/initrd/UKI). Keep ≥1 prior distinct
  `module_abi` beyond the running one so cross-pruned-image rollback re-eval is
  always satisfiable from `/var` without network.

---

## 5. Cross-references and invariants summary

- The manifest needs **no signature**: it is `f(inputs)` under `--pure-eval`;
  reproducibility from authenticated, recorded inputs is stronger than a
  manifest signature, and
  the `gen-attestation/v1` record (§1) makes it falsifiable.
- The input-set binding distinction — *which inputs the evaluator consumed* —
  is covered by §1
  (config-modules + host.nix + facts in the record) and §4 (root anchored to PCR
  11).
- Secret material never enters the value graph: §2's `secretRef` carries only
  references; TPM2/PCR-11-sealed ciphertext is permitted, plaintext is
  structurally unrepresentable.
- `host.nix` is the operator-authored input authenticated by the selected
  platform or signed policy (§3); instance facts are separately
  recorded-and-attested.


---

# Generation data structures, GC roots, rollback

Below is drop-in RFC markdown — a new document, `generations-contract.md`, specifying the data structures and lifecycle. It is self-consistent with `generations.md` / `operability.md` and folds in the locked F1/F2/F3 and five-OQ decisions.

---

# Generation data structures and lifecycle contract

This document is the normative data-structure + lifecycle contract for RFC-0011
generations. It refines the conceptual split in
[`generations.md`](generations.md) into concrete persisted records, names the
storage location of every field, fixes the GC-root set from
[`operability.md`](operability.md), and locks the upgrade/rollback ordering. It
incorporates the locked decisions F1 (dm-verity-anchored base lib), F2
(`jobScripts` text-carrying manifest), F3 (`contributable` authorization), and
the five generations-`§Open questions` resolutions (retention depth, measured
locus, `stateVersion` orthogonality, first-boot re-eval, content-pinned
`host.nix`).

Grounding: `crates/aos-package/src/types.rs:3081-3112` (`SystemGeneration` /
`SystemGenerationState`), `crates/aos-package/src/profile/{mod.rs,meta.rs}`
(`Profile`/`Generation`/`ProfileState`), `crates/aos-package/src/store.rs:251`
(`create_gc_roots`), `modules/base/activate.sh.in` (staged swap),
`modules/image/_builder.nix` (ESP/GPT assembly), `modules/base/system.nix:132`
(`stateVersion`).

## 1. Splitting `SystemGeneration` into two records

Today one bundled `SystemGeneration` (`types.rs:3083-3100`) carries
`{ number, toplevel, version, package_name, registry, created_at, kernel_path }`
and is the unit of switch. RFC-0011 replaces it with **two** record types on
**two** axes (a tree: each `ConfigGeneration` is a child of exactly one
`ImageGeneration`). Neither record is a rename of `SystemGeneration`; the old
type is retired once both replacements land (a one-shot migration reads any
legacy `state.json` and seeds an `ImageGeneration` + `ConfigGeneration` pair from
its fields).

### 1.1 `ImageGeneration` — the measured, signed substrate

The base-lib/evaluator/render-core substrate, delivered as an A/B UKI partition
swap and carried in the boot chain + TPM PCR-11 policy. It is **not** persisted
in `/var` as the authority of record — the ESP UKI set + `/etc/os-release` of the
running image are. The `/var` record below is a userspace *index* over what is
installed in the ESP slots, used by APM to reason about A/B state and retention.

```rust
/// One measured, signed image-generation: the kernel + initrd + base lib +
/// evaluator + render-core, delivered as an A/B UKI and tracked in the TPM
/// PCR-11 policy. Persisted in `/var/lib/profiles/image/state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageGeneration {
    /// Image-generation number (names the `image-gen-N/` directory).
    pub number: u32,
    /// A/B slot this UKI occupies: `A` or `B`.
    pub slot: ImageSlot,
    /// ESP-relative path of this generation's UKI, e.g.
    /// `EFI/Linux/aos-2026.06.1+3.efi` (the `+N` is the sd-boot
    /// boot-counting tries-suffix; see §5.2).
    pub uki_path: String,
    /// Store path of the sysroot toplevel this image was built from.
    pub toplevel: String,
    /// Sysroot package name, version, source registry (provenance only —
    /// migrated verbatim from the old `SystemGeneration`).
    pub package_name: String,
    pub version: String,
    pub registry: String,
    /// Resolved kernel store path (kernel-change detection across A/B).
    #[serde(default)]
    pub kernel_path: Option<String>,
    /// Store path of the base-lib + evaluator closure carried *inside* this
    /// image. This is the ABI artifact and the GC-root target for
    /// `image-gen-N/baselib/<module_abi>` (§4, OQ1).
    pub evaluator_ref: String,
    /// The monotonic shared-option-schema ABI this image's base lib exports
    /// (§3). Mirrors `AOS_MODULE_ABI` in this image's `/etc/os-release`.
    pub module_abi: u32,
    /// SHA-256 of the base-lib closure, mirrored as `AOS_BASELIB_DIGEST` in
    /// `/etc/os-release` and measured into PCR-11 via the `.osrel` section
    /// (OQ2). Pairs with `root_verity_roothash` for the byte-level binding.
    pub baselib_digest: String,
    /// dm-verity Merkle root over the erofs root that carries the base lib
    /// (F1). Baked into the UKI `.cmdline` as `roothash=<hex>`, hence
    /// measured into PCR-11. Tampering the base lib changes this hash,
    /// changes `.cmdline`, breaks both the Authenticode signature and the
    /// sealed-`/var` PCR-11 policy. `None` for unsigned/VM (ext4) images.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_verity_roothash: Option<String>,
    /// ukify-predicted PCR-11 for this UKI (RFC-0006 phase 4); the recorded
    /// value now genuinely covers the root because the roothash rides in
    /// `.cmdline` (F1). `None` when `systemd-measure` was unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_pcr11: Option<String>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// A/B slot discriminant for an image-generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageSlot { A, B }
```

**Storage location.** `/var/lib/profiles/image/state.json` holds an
`ImageGenerationState { running: u32, default: u32, pending: Option<u32>,
generations: Vec<ImageGeneration> }`:
- `running` — the image-gen the live kernel booted (cross-checked against
  `/etc/os-release` `AOS_MODULE_ABI` / `AOS_BASELIB_DIGEST`, never trusted from
  the network).
- `default` — the slot `bootctl set-default` currently points at (the *durable*
  next-boot selection; see §5.2). Distinct from `running` during a staged-but-
  not-yet-rebooted upgrade or a pending rollback.
- `pending` — a staged image-gen whose UKI is in the ESP but which has not been
  booted yet (set by step 1 of §5.1, cleared on its first successful boot).

`module_abi`, `baselib_digest`, and `root_verity_roothash` are the on-`/var`
mirror of the **authoritative** copies that live in the image's
`/etc/os-release` and PCR-11; APM reads the authoritative copies at boot and
asserts equality (a mismatch is a tamper/rollback-confusion signal, fail-closed).

### 1.2 `ConfigGeneration` — the pure-data overlay

Pure derived `/etc` produced by on-host eval, committed by the existing
`current → gen-N` pointer switch (`activate.sh.in`). A config-gen is the pair
`(image_gen_parent, manifest_hash)` and is a **child** of the image-gen it was
evaluated against.

```rust
/// One config-generation: the materialized `/etc` overlay produced by
/// evaluating the installed set's config modules + `host.nix` against a
/// specific image-gen's base lib. Persisted in
/// `/var/lib/profiles/system/state.json` (extends today's record).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGeneration {
    /// Config-generation number (names the `gen-N/` directory; this is the
    /// pointer `activate.sh.in` commits — unchanged role).
    pub number: u32,
    /// The `ImageGeneration::number` this config-gen was evaluated against.
    /// Establishes the parent edge; rollback re-binding is gated on it (§6).
    pub image_gen_parent: u32,
    /// The `module_abi` value in effect at eval time (== the parent image-gen's
    /// `module_abi`). The rollback pin (§6) compares this against the running
    /// image's ABI; same-ABI ⇒ free re-activation, different-ABI ⇒ re-eval.
    pub module_abi_pinned: u32,
    /// Content-address of the canonicalized manifest JSON
    /// (`gen-N/manifest.json`). Identifies the config-gen's *output*.
    pub manifest_hash: String,
    /// Store path of the config-module **source** closure the evaluator read
    /// (the eval *input*, distinct from package runtime outputs). GC-rooted by
    /// `gen-N/cfgsrc/<hash>` (§2, M-gc-inputs); required for cross-ABI re-eval.
    pub config_module_closure: String,
    /// Store path / content hash of the exact `host.nix` this config-gen was
    /// evaluated from (OQ5: content-pin, NOT a mutable git ref). GC-rooted by
    /// the same `gen-N/cfgsrc/<hash>` root. Image-rollback re-eval feeds this
    /// exact path back in, reproducing the intended config (cache-hit), never
    /// forking HEAD.
    pub host_nix_ref: String,
    /// Optional non-authoritative provenance: the git commit `host.nix` came
    /// from, recorded for operator traceability only. The binding of record is
    /// `host_nix_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_nix_commit: Option<String>,
    /// Content-address of the resolved instance facts (`facts.json`) the eval
    /// consumed. Part of the reproducible input set.
    pub facts_hash: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}
```

**Storage location.** `/var/lib/profiles/system/state.json` — today's
`SystemGenerationState` becomes `ConfigGenerationState { current: u32,
next: u32, generations: Vec<ConfigGeneration> }`, preserving the existing
`current`/`next` counters (`types.rs:3104-3111`) and the `Profile`/`Generation`
machinery (`profile/mod.rs`). The `current → gen-N` symlink and `switch_to` /
`new_generation` semantics are **unchanged**; only the per-generation record
grows the five RFC-0011 fields. `gen-N/manifest.json` (the `aos.config-manifest/v1`
value, including F2's `jobScripts` map) remains a plain file in the gen dir,
content-addressed by `manifest_hash`, traveling with the generation and deleted
with it.

### 1.3 Field-to-storage map (authority of record)

| Datum | `ImageGeneration` (`/var/lib/profiles/image`) | `ConfigGeneration` (`/var/lib/profiles/system`) | Authoritative copy elsewhere |
|---|---|---|---|
| `module_abi` | `module_abi` | `module_abi_pinned` (copy at eval) | `/etc/os-release` `AOS_MODULE_ABI`; PCR-11 via `.osrel` |
| base-lib identity | `evaluator_ref`, `baselib_digest` | — | `/etc/os-release` `AOS_BASELIB_DIGEST`; PCR-11 |
| base-lib byte integrity | `root_verity_roothash` | — | UKI `.cmdline` `roothash=`; PCR-11; dm-verity target |
| eval inputs | — | `config_module_closure`, `host_nix_ref`, `facts_hash` | the store paths themselves (GC-rooted, §2) |
| eval output | `toplevel` | `manifest_hash` → `gen-N/manifest.json` | the realized `/etc` store paths (GC-rooted, §2) |
| boot selection | `slot`, `uki_path`, `default`, `pending` | — | ESP UKIs + `bootctl set-default` (§5.2) |

## 2. GC roots: `gen-N/{usr,src,cfg,cfgsrc}/`

`create_gc_roots` (`store.rs:251`) today writes two symlink farms per
config-gen; RFC-0011 extends it to **four**. Each is a directory of
`<hash> → <target>` symlinks that `nix-store --gc` honors. The four roots and
exactly what each pins:

| Root | Target | What it keeps alive | Why it cannot be dropped |
|---|---|---|---|
| `gen-N/usr/<hash>` | package output store path | installed package **runtime** outputs | rollback safety: a package stays pinned even if a later eval drops it from `/etc` |
| `gen-N/src/<hash>` | source `.drv` | package source derivations | rebuild/provenance |
| `gen-N/cfg/<hash>` | config **output** store path | the realized manifest outputs: rendered `/etc` trees, unit files, F2 job-script texts, the `toplevel` | makes same-ABI rollback a pure pointer switch (output already on disk) |
| `gen-N/cfgsrc/<hash>` | config-module **source** closure **+** `host_nix_ref` store path | the eval **inputs** | **M-gc-inputs**: `cfg/` pins outputs, which reference package *runtime* closures, **not** the config-module source NARs nor `host.nix`; without `cfgsrc/` a plain `apm gc` collects the inputs and breaks cross-ABI re-eval (§6) |

`cfgsrc/` is the load-bearing addition. It pins **both** the
`ConfigGeneration::config_module_closure` **and** the
`ConfigGeneration::host_nix_ref` store path (OQ5: `host.nix` is content-pinned,
so it is a real store path the root can hold). Because cross-ABI re-eval feeds
exactly these two inputs plus `facts.json` (also pinned via `cfgsrc/`) into the
rolled-back image's evaluator, retaining them guarantees the re-eval is
satisfiable from `/var` **without network** — never relying on re-download
(OQ1).

A fifth, **image-scoped** root lives outside `gen-N/`:

| Root | Target | What it keeps alive |
|---|---|---|
| `image-gen-N/baselib/<module_abi>` | the base-lib + evaluator closure (`ImageGeneration::evaluator_ref`) | the ABI artifact for one image-gen, independent of the whole UKI and independent of the ESP ×2 slot count (OQ1) |

`baselib/<module_abi>` pins **only** the base-lib/evaluator closure — not the
kernel/initrd/whole UKI. Its retention rule (§4) is what makes cross-pruned-image
rollback re-eval always satisfiable from `/var`.

**Retention / pruning.** Unchanged shape (`prune_generations`,
`apm clean --generations`): while `gen-N` is retained all four of its roots keep
their closures alive (rollback = pointer switch); when pruned, the whole `gen-N/`
dir is removed, dropping `usr/`/`src/`/`cfg/`/`cfgsrc/` at once, and the now-
unreferenced store paths become collectable on the next `apm gc` (`clean.rs`)
*unless still referenced by a retained generation* (Nix computes reachability
across all roots). The ephemeral `/run/etc/upper-N` overlay uppers are not store
paths and are reclaimed by reboot/tmpfs + generation GC
(`activate.sh.in` cleanup stage), untouched by config GC.

## 3. The `module_abi` binding and pre-eval gate

A single monotonic integer **`module_abi`** versions the shared option schema
exported by the base lib. It is a property of the image-gen (the base lib ships
in the image), surfaced two ways:

1. **Persisted / measured.** `aos.system.moduleAbi` (new int option in
   `modules/base/system.nix`, default `1`, sibling to `stateVersion` at
   `system.nix:132`) is written into `/etc/os-release` as
   `AOS_MODULE_ABI=<K>` next to `AOS_STATE_VERSION` (`system.nix:257`), and the
   base-lib digest as `AOS_BASELIB_DIGEST=<sha256>`. That os-release file is
   passed to `aos-uki.nix` as `--os-release=@…` and lands in the `.osrel` PE
   section, which systemd-stub measures into **PCR-11** (OQ2). The base-lib
   *bytes* are additionally bound to PCR-11 by F1's dm-verity `roothash=` on the
   measured `.cmdline`. So "ABI integrity for free" holds: you cannot move the
   ABI or the base lib without moving PCR-11 and failing the sealed-`/var`
   policy.
2. **Read on-host without network trust.** The on-host resolver reads
   `AOS_MODULE_ABI` from the **running** image's `/etc/os-release` — never from
   the registry — to learn `K`.

**`stateVersion` stays orthogonal (OQ3).** `aos.system.stateVersion` (string,
state-migration trigger, applied at *activate*) and `aos.system.moduleAbi` (int,
shared-option-schema gate, applied *pre-eval*) are two independent os-release
fields gating different things at different times. Their bumps often coincide
but neither implies the other; they are not collapsed.

**The pre-eval gate.** Each downloaded config module declares
`module_abi_compat = { min, max }` (analogous to `SbatEntry`'s
`(component, generation)` floors, `types.rs:3015-3024`). The resolver **refuses,
before eval produces any manifest, any config module whose range excludes the
running image's `K`** — a hard, fail-closed check with the same shape as
`trust_ctx.enforce_totality()` (`sysroot.rs:192-204`). On refusal the old
config-gen stays live (no `gen-N`, no `/etc` touch). The produced config-gen
records `module_abi_pinned = K` (§1.2), which the rollback pin (§6) checks.

Per-package private roots (`{pkg}.*`) are **not** subject to `module_abi`: a
package's private schema ships with the package. Only the shared base tree needs
the ABI contract; each fetched shared-root extension carries its own interface
ABI so interfaces evolve independently of the base.

## 4. Retention depth (OQ1) — keep ≥1 prior base lib on `/var`

Config-gens are cheap (`/var`, many); image-gens are expensive (ESP ×2 → 2
slots). To keep cross-ABI rollback re-eval (§6) satisfiable without re-download,
the `image-gen-N/baselib/<module_abi>` root (§2) is retained iff **either**:

- (a) it is one of the ESP-resident image-gens (the 2 A/B slots), **or**
- (b) at least one retained config-gen records `module_abi_pinned` equal to that
  base lib's `module_abi`,

with a **hard floor of ≥1 prior distinct `module_abi`** beyond the running one.
A `baselib/` root is pruned only when neither (a) nor (b) holds and the floor is
already met. The pruned set is base-lib-closure-only — the kernel/initrd/UKI of a
non-ESP image-gen are *not* retained; only the ABI artifact is. This makes
"cross-pruned-image rollback re-eval is always satisfiable from `/var`, never
re-download" a guarantee, not a hope.

## 5. Upgrade ordering and durable image rollback

### 5.1 Image-first, then re-eval, then `/etc` switch (no cross-reboot transaction — OQ4)

Invariant: **the substrate providing the base-lib/evaluator must be live before
the eval targeting it runs.** Therefore:

1. **Stage the image-gen (offline, no activation).** `apm` downloads the new UKI
   and writes it into the free A/B ESP slot (`EFI/Linux/aos-<newver>+3.efi`,
   with the `+3` boot-counting tries-suffix, §5.2) alongside the old. It records
   a **pending-image marker** on `/var` — `ImageGeneration` appended with
   `pending = Some(new_number)`, capturing the target image-gen ref and the
   desired config intent. It then `bootctl set-default`s the new UKI and
   reboots/advises per `KernelUpgradeMode` (`sysroot.rs:80-90`). **No config eval
   yet.** This is *not* an apm-driven reboot-spanning two-phase transaction;
   there is no cross-reboot transaction object.
2. **Reboot into the new image-gen.** Kernel/base-lib/evaluator swap, reboot-
   class by nature. Measured boot: new PCR-11 (now covering the new base lib via
   F1's roothash), signed policy unseals `/var` (RFC-0006, unchanged).
3. **First-boot re-eval service.** A systemd oneshot
   `aos-firstboot-reeval.service`, ordered early, guarded by the predicate
   *"running image-gen ref ≠ the live config-gen's `image_gen_parent`"* (read
   from `/etc/os-release` vs `state.json`). When true it performs
   generations.md steps 3–4: the **new** evaluator runs over **new base lib (in
   image) + downloaded config modules + the recorded `host_nix_ref`**; the §3
   pre-eval ABI gate fires here; output is a new config-gen parented to the new
   image-gen. It is **idempotent and re-entrant** — on a clean boot the predicate
   is false and it is a no-op.
4. **Materialize + atomic `/etc` switch.** `apm` renders the manifest into the
   content-addressed `gen-N/` dir (including F2's per-gen
   `gen-N/job-scripts/<unit>/<slot>.<idx>` texts and the placeholder rewrite),
   creates the four GC roots (§2), and invokes `activate <N>` — overlay compose,
   pre-swap reconcile, `mount --move --beneath`, post-swap reconcile — committing
   the config-gen pointer.

A **config-only change** (no image change) short-circuits to steps 3–4 against
the *running* image-gen's base lib; no reboot. Failure atomicity is inherited:
an ABI-gate failure (step 3) or an `EX_PREPARE`/`EX_COMPOSE` failure (step 4)
aborts **before** the `/etc` swap with the old config-gen live
(`activate.sh.in:161-214`); a failed new image (step 2) is auto-demoted by
boot-counting (§5.2).

### 5.2 Durable image rollback — `bootctl set-default` + boot-counting, NOT the glob

Image rollback boots the other A/B UKI slot. It is **not** "just boot the other
slot" because the ESP `loader.conf` `default aos-*.efi` lexically-highest glob
(`modules/image/_builder.nix:176-183`) always re-selects the *newer/suspect* UKI
on the next reboot (review M-rollback-glob). The durable mechanism is therefore:

- **Roll forward with boot-counting.** A newly staged UKI is named with an
  sd-boot tries-suffix (`aos-<ver>+3.efi`). sd-boot decrements the counter each
  attempt; a UKI that fails to boot is **auto-demoted** to `aos-<ver>+0-3.efi`
  (bad) without operator action, and sd-boot falls back to the other slot. This
  is the atomicity for a bad new image (step 2 above).
- **Durable rollback is `bootctl set-default`** to the older UKI, updating
  `ImageGeneration::default` (`/var/lib/profiles/image/state.json`). This pins
  the next-boot selection against the glob's lexical preference. The
  `default aos-*.efi` glob remains **only the first-install fallback**, never the
  steady-state selector.

Config rollback and image rollback are two independent verbs because the axes
are independent: config rollback is a pure `Profile::switch_to` + `activate <N>`
pointer switch among config-gens parented to the running image-gen (no eval, no
reboot); image rollback is the bootloader-level `set-default` above, independent
of APM's config pointer.

## 6. The pinning rule and the cross-ABI re-eval path

A config-gen is **pinned to the `module_abi` it was evaluated against**
(`module_abi_pinned`, §1.2) — the manifest is the *output* of evaluating config
modules against a *specific* base-lib option schema; replaying it against a
different schema is undefined. Re-activation branches on the comparison between
`module_abi_pinned` and the running image-gen's `module_abi`:

- **Same ABI ⇒ direct re-activation.** Same-ABI image upgrades (kernel/package
  change, no option-schema change — the common case) satisfy the pin, so a
  config-gen **freely re-activates**: a pure pointer switch over the retained
  `cfg/` outputs (§2). No eval, no reboot.
- **Different ABI ⇒ refuse direct activation, re-eval instead.** The old
  config-gen is **not** blindly replayed. The system re-evaluates the triple
  `(old_base_lib, config_module_closure, host_nix_ref)` — all three retained on
  `/var` by `image-gen-N/baselib/<module_abi>` (§4) and `gen-N/cfgsrc/<hash>`
  (§2) — under the rolled-back image's evaluator, with `facts.json` (also
  `cfgsrc/`-pinned) as the instance facts. Because eval is pure and content-
  addressed, this recomputation is deterministic and usually **cache-hits**. It
  produces a *fresh* config-gen pinned to the rolled-back image-gen's ABI. The §3
  pre-eval ABI gate still applies — a config module incompatible with the rolled-
  back ABI is refused fail-closed, old gen stays live.

The cross-ABI path is exactly why `cfgsrc/` (inputs) and `baselib/<module_abi>`
(the old ABI artifact) must be GC-rooted rather than merely recorded, and why
`host_nix_ref` is content-pinned (OQ5): re-eval after an image rollback reads the
**exact** `host.nix` store path the rolled-back-to config-gen recorded, feeds it
to the evaluator, and reproduces the intended config deterministically — never
forking HEAD.

**Net.** A config-gen is pinned to its ABI, freely portable across image-gens of
the *same* ABI (pointer switch over `cfg/`), and recomputable — never blindly
replayed — across image-gens of *different* ABI (re-eval over `cfgsrc/` +
`baselib/`), with the inputs guaranteed present on `/var` by the §2/§4 retention
contract.

---

The relevant source loci for implementation are: `crates/aos-package/src/types.rs:3081-3112` (replace `SystemGeneration`/`SystemGenerationState` with `ImageGeneration`/`ImageGenerationState` + `ConfigGeneration`/`ConfigGenerationState`), `crates/aos-package/src/store.rs:251` (`create_gc_roots`: add `cfg/` + `cfgsrc/`, plus a new image-scoped `baselib/<module_abi>` root writer), `crates/aos-package/src/profile/mod.rs` (`Generation` accessors for the two new root dirs), `modules/base/system.nix:132,257` (`moduleAbi` option + `AOS_MODULE_ABI`/`AOS_BASELIB_DIGEST` os-release lines), `modules/base/activate.sh.in` (unchanged swap; the new `aos-firstboot-reeval.service` orders before it), and `modules/image/_builder.nix:176-183` (boot-counting tries-suffix + `bootctl set-default` durability over the `default aos-*.efi` glob).

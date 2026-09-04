# Package contract and maintenance inventory

## Contract requirements

Package declarations must answer these questions without URL, filename, or
attribute-name heuristics:

1. Which upstream family and maintained stream owns this source?
2. Which release policy selects a newer candidate?
3. Which source and fixed-output values form one atomic update?
4. Which package outputs and targets consume those values?
5. Which literal fields may the updater change?
6. Which validation and human gates apply?
7. If the package is not automatically maintained, why and who reviews that
   decision?

The contract is AOS-specific. Similar-looking package syntax creates no
compatibility requirement with nixpkgs or its update conventions.

## `mkUpstream`

Add a pure `mkUpstream` helper to the package arguments injected by
[`pkgs/default.nix`](../../../pkgs/default.nix). It validates a closed schema,
constructs AOS-local source fetchers, and returns the ordinary values used by a
recipe plus normalized primitive maintenance metadata.

An automatic conventional source has this shape:

```nix
{
  mkDerivation,
  mkUpstream,
  gnumake,
}: let
  upstream = mkUpstream {
    schema = "aos.package-update/v1";
    unitId = "zlib-1";
    family = "zlib";
    stream = "1";
    owner = "pkgs/compression/zlib.nix";
    classification = "automatic";

    package = {
      currentVersion = "1.3.1";
      versionProjection = {
        kind = "component-field";
        component = "main";
        field = "comparisonVersion";
      };
    };

    components.main = {
      current = {
        upstreamId = "v1.3.1";
        comparisonVersion = "1.3.1";
      };

      discovery.primary = {
        provider = "github-tags";
        repository = "madler/zlib";
        tagPrefix = "v";
      };

      discovery.advisors.repology.project = "zlib";

      releasePolicy = {
        strategy = "latest-in-series";
        versionScheme = "semver";
        series.major = 1;
        allowPrerelease = false;
        minimumAgeDays = 3;
      };

      sources.source = {
        fetcher = "fetchurl";
        urlTemplates = [
          {
            scheme = "https";
            authority = "zlib.net";
            path = [
              "fossils"
              {
                parts = [
                  {literal = "zlib-";}
                  {
                    componentField = {
                      component = "main";
                      field = "comparisonVersion";
                    };
                  }
                  {literal = ".tar.gz";}
                ];
              }
            ];
          }
        ];
        hash = "sha256-...";
        hashMode = "flat";
        allowedRedirectHosts = ["zlib.net"];
      };
    };

    policy = {
      lifecycle = "supported";
      riskFloor = "normal";
      repairScope = [];
    };
  };
in
  mkDerivation {
    pname = "zlib";
    inherit (upstream) version;
    src = upstream.components.main.sources.source;
    update = upstream.forPackage {
      member = "zlib";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
  }
```

The exact field spelling is fixed during the schema-fixture implementation, but
these semantics are normative:

- automatically writable current values and hashes are literals inside the
  `mkUpstream` attrset;
- unit, owner, source-slot, and artifact-slot identifiers are stable;
- URL templates compile to a typed URL-template AST, substitute only into
  declared path/query components with context-specific encoding, and cannot
  change scheme, authority, or port;
- the helper returns real AOS `fetchurl`/source derivations;
- the derivation receives normal `version`, `src`, and artifact values;
- update-only metadata is visible to evaluation but not to the package builder;
- agent repairs may change only package-builder attribute values named by the
  plan-frozen `policy.repairScope`; an empty list disables patch proposals;
- functions, derivations, paths, secrets, or arbitrary executable update hooks
  are not serializable maintenance metadata.

## Package and component version forms

Keep the package version separate from each component's two upstream forms:

- `package.currentVersion`: the AOS derivation and registry version;
- `upstreamId`: the exact release/tag/ref identity;
- `comparisonVersion`: the normalized value consumed by the selected version
  ordering scheme.

The package declaration also has a typed `versionProjection` that derives the
next package version from one component field or a closed composite rule. A
provider adapter preserves raw values even if normalization or policy rejects
them. Two different raw identities that normalize to the same comparison key
are quarantined unless the unit explicitly declares a canonical-alias rule that
proves which identity is equivalent and preferred.

URL templates are parsed, not interpolated as strings. A placeholder occupies a
declared path-segment or query-value position and is percent-encoded for that
component. Structural delimiters such as `/`, `?`, `#`, user info, scheme,
host, and port cannot be injected through a tag or version value.

## Maintained streams

Every independently maintained major, minor, LTS, branch, or snapshot line is a
separate update unit. For concurrent Bazel releases:

```nix
{
  unitId = "bazel-8";
  family = "bazel";
  stream = "8";
  classification = "assisted";

  package = {
    currentVersion = "8.4.2";
    versionProjection = {
      kind = "component-field";
      component = "main";
      field = "comparisonVersion";
    };
  };

  components.main = {
    current = {
      upstreamId = "8.4.2";
      comparisonVersion = "8.4.2";
    };

    releasePolicy = {
      strategy = "latest-in-series";
      versionScheme = "semver";
      series.major = 8;
      allowPrerelease = false;
    };
  };

  policy = {
    lifecycle = "supported";
    successorUnit = "bazel-9";
    riskFloor = "high";
  };
}
```

Reports distinguish:

- whether `bazel-8` is current within major 8;
- whether the Bazel family has another supported upstream stream that AOS has
  not introduced;
- whether an existing unit's lifecycle should change to security-only,
  frozen, or retiring.

A new upstream major never causes the updater to replace or remove an older AOS
package. Stream introduction, default-alias changes, and retirement are
human-planned source changes with their own dependency impact.

## Independently versioned components

A component has its own current upstream/comparison identities, primary and
advisory discovery, stream selector, candidate projection, and source slots.
The unit target is a component-version vector plus the projected package
version:

```json
{
  "unitId": "composite-example",
  "packageVersion": "2026.9.0",
  "components": {
    "application": {
      "upstreamId": "v2026.9.0",
      "comparisonVersion": "2026.9.0"
    },
    "bundler": {
      "upstreamId": "v0.25.9",
      "comparisonVersion": "0.25.9"
    }
  }
}
```

Component targets can be selected independently only when the unit declares a
typed compatibility rule. Otherwise a provider-supplied compatibility manifest
or a maintainer-selected vector is required. A plan always closes the entire
vector, including unchanged components, so source and artifact identities
cannot drift during execution.

A composite `package.versionProjection` is one of a small reviewed set: one
component field, a delimiter-joined tuple, a provider-declared release version,
or manual. Arbitrary Nix/string code is not an automatic projection.

## Shared sources and members

Shared `_source.nix` files are the natural owner of an update unit. The Linux
source record should expose `version`, named sources, and a per-member update
record consumed by both `linux` and `linux-headers`.

Conceptually:

```nix
{mkUpstream}: let
  upstream = mkUpstream {
    unitId = "linux-6.18";
    family = "linux";
    stream = "6.18";
    owner = "pkgs/kernel/_source.nix";
    # current, discovery, policy, and sources
  };
in {
  inherit (upstream) version components;
  updateFor = member:
    upstream.forPackage {
      inherit member;
    };
}
```

The inventory collects member names from evaluated derivations rather than
duplicating them in the shared declaration. Every member must expose the same
unit and complete current component/source identities. A duplicated archive/
version in several recipes is a migration signal: either consolidate it into
shared ownership or declare why the units are independent.

## Source and artifact slots

One unit may contain several upstream components and several fixed-output
artifacts. A generated Go input has this conceptual shape:

```nix
upstream = mkUpstream {
  # identity and policy

  components.main.sources.source = {
    fetcher = "fetchurl";
    urlTemplates = [
      {
        scheme = "https";
        authority = "example.invalid";
        path = [
          "project"
          "archive"
          {
            parts = [
              {
                componentField = {
                  component = "main";
                  field = "upstreamId";
                };
              }
              {literal = ".tar.gz";}
            ];
          }
        ];
      }
    ];
    hash = "sha256-source";
    hashMode = "flat";
  };

  artifacts.goModules = {
    kind = "go-modules";
    inputs = [{component = "main"; source = "source";}];
    hash = "sha256-go-modules";
    parameters = {
      sourceRoot = ".";
      moduleRoots = ["."];
      patches = [];
    };
  };
};

goModules = fetchGoModules {
  src = upstream.components.main.sources.source;
  hash = upstream.artifacts.goModules.hash;
};
```

Artifact slots form a declared acyclic dependency graph. Initial typed kinds
follow AOS's existing builders:

- flat and recursive URL sources;
- Cargo dependency/vendor artifacts;
- one or more Go module artifacts;
- npm artifacts and reviewed local lock/manifest transformations;
- Bazel dependency artifacts;
- target-conditioned source or dependency slots;
- patch inputs tied to the upstream identity.

Each artifact records every builder parameter that can affect its output,
including source root, module roots, target, patch set, lockfile mode, and
builder/tool identity. An omitted or changed parameter changes the artifact
contract rather than silently reusing the hash.

If a materializer writes a repository file, the slot also declares every
output's normalized path, format, expected preimage digest, typed transformation,
and postcondition. Lockfiles and manifests cannot be written merely because the
materializer produced them. Any undeclared output or preimage mismatch blocks
the attempt.

Unknown artifact kinds cannot execute a package-supplied shell callback. They
remain assisted or manual until AOS adds and tests a bounded materializer.

## Classification

Every evaluated package root has exactly one classification:

| Classification | Meaning |
| --- | --- |
| `automatic` | Candidate selection and all normal mutations are deterministic |
| `assisted` | Discovery/materialization is deterministic, but patch, dependency, or build repair may need an agent |
| `manual` | A maintainer must select or lead the update because generic automation is unsafe |
| `frozen` | Intentionally pinned with a reason, owner, and review-after date |
| `local` | AOS-owned code/data without an independent upstream release |
| `generated` | Output owned by another unit and not independently schedulable |
| `alias` | Compatibility/default alias to another package and not independently schedulable |

`frozen` is not a permanent ignore flag. Expired review dates are maintenance
alerts. Historical compiler rungs can be frozen while the active rung remains a
supported unit.

Bootstrap, kernel-stream migrations, init, crypto roots, Secure Boot,
QEMU/Crucible, and curated SDKs begin as manual or assisted even when some hash
edits are mechanical.

## Classified root universe

The canonical universe is the union, across every supported target package set,
of all roots consumed by package lint/build/publication inventories plus every
explicitly exported alias and stdenv-provided root. PR 4 first reconciles the
current discovery, lint, build, and publication surfaces; differing counts are
an error to explain, not a choice of whichever list is convenient.

Add AOS-local constructors/registries for non-upstream roles:

- `mkLocalPackage` or equivalent normalized metadata for AOS-owned sources;
- `mkGeneratedPackage` referencing its owner unit/member;
- `mkPackageAlias` recorded in an explicit package-set alias registry, because
  an alias sharing a derivation cannot carry alias-specific passthru;
- `mkFrozenUpstream` retaining upstream/source identity plus reason, owner, and
  review date;
- explicit records for stdenv/package-set roots that bypass an ordinary package
  constructor.

The inventory preserves the root role and target set. Aliases/generated roots
are visible in release and reverse-dependency reporting but cannot be scheduled
as independent updates.

## Derivation integration

Add `update ? null` to the AOS-local `mkDerivation` in
[`lib/derivations.nix`](../../../lib/derivations.nix). Remove it before invoking
`builtins.derivation` and expose only normalized primitive data under:

```nix
passthru.aos.maintenance = {
  schema = "aos.package-update/v1";
  unitId = "...";
  member = "...";
};
```

Every AOS-local higher-level package constructor must forward the argument. A
fixture for each constructor prevents metadata from silently disappearing.

Maintenance metadata must not change builder environment variables or add a
runtime/build dependency. The source derivations returned by `mkUpstream` are
ordinary AOS fixed-output inputs and retain the existing hermetic build model.

Every AOS source/fixed-output constructor also exposes a typed
`passthru.aos.fixedOutput` identity containing its kind, hash mode, source
inputs, builder parameters, and output derivation identity. `mkDerivation` and
higher-level package constructors expose the normalized declared maintenance
inputs they receive.

Opt-in metadata alone cannot prove that a recipe did not embed another
fixed-output derivation inside a phase string. `aos maintain inventory --check`
therefore has two layers:

1. pure Nix validates all declared slots and constructor metadata;
2. the local tool inspects every member's evaluated derivation input graph,
   identifies reachable fixed-output derivations, and requires each one to map
   to a declared source/artifact slot or an explicit manual exception.

The graph audit records builder-specific parameters such as source root,
module roots, patches, target, and lockfile mode. A reachable unannotated or
unmapped fixed-output derivation blocks automatic/assisted coverage. This
effectful derivation audit, not pure evaluation alone, enforces completeness.

## Maintenance inventory v1

Pure Nix evaluation emits canonical primitive JSON:

```json
{
  "schema": "aos.maintenance-inventory/v1",
  "units": [
    {
      "unitId": "bazel-8",
      "family": "bazel",
      "stream": "8",
      "classification": "assisted",
      "package": {
        "currentVersion": "8.4.2"
      },
      "components": {
        "main": {
          "current": {
            "upstreamId": "8.4.2",
            "comparisonVersion": "8.4.2"
          }
        }
      },
      "owner": "pkgs/toolchain/bazel-8.nix",
      "members": ["bazel-8"],
      "platforms": [
        "aarch64-darwin",
        "aarch64-linux",
        "x86_64-darwin",
        "x86_64-linux"
      ],
      "sources": [],
      "artifacts": [],
      "checks": [],
      "dependencies": [],
      "reverseDependencies": [],
      "policy": {}
    }
  ]
}
```

Pure Nix emits content only; it does not claim a Git identity. The local CLI
creates `aos.maintenance-inventory-envelope/v1` containing the canonical
repository/clone identity, exact commit and tree, dirty-state/content digest,
inventory bytes/digest, target evaluations, and controller/tool identity. A
write plan requires a clean envelope whose commit/tree matches the worktree
base. A dirty checkout may be inventoried for diagnosis but cannot be mislabeled
as `HEAD` or used as a write base.

Target evaluation can produce different members, sources, or artifacts. The
CLI evaluates the configured supported target package sets, merges them by
stable unit/component/slot identity, and rejects target-invariant disagreement.
Legitimate target-conditioned fields remain explicit in the merged envelope.

The full record contains provider identities, release policy, URL templates,
origins, hashes, artifact edges, member outputs, aliases, target support,
package-authored checks, dependency/reverse-dependency edges, lifecycle, risk,
cohort, ownership, and exceptional gates.

Serialization is canonical and bounded so the document has a stable digest.
The Rust model rejects unknown fields, duplicate identifiers, invalid paths,
oversized collections, dangling references, artifact cycles, and incompatible
schema versions.

## Mutation identity

`builtins.unsafeGetAttrPos` is diagnostic, not a durable editor locator.
Existing wrappers can point a final derivation attribute into
`lib/derivations.nix` or an `inherit` site rather than the original literal.

The stable mutation identity is:

```text
(schema, update unit ID, package/component/artifact scope, owner path,
 field ID, expected old value)
```

For an automatic field, the editor:

1. validates a normalized repository-relative owner under an allowed package
   root;
2. parses Nix into a comment-preserving syntax tree;
3. finds exactly one literal `mkUpstream` with the unit ID;
4. finds exactly one schema-defined field path;
5. compares its literal value with the plan;
6. makes the minimal replacement;
7. formats the file through AOS tooling;
8. re-evaluates the before/after inventories;
9. requires an exact authored delta for planned literal/generated-output fields;
10. computes the resulting derived-effect closure—expanded URLs, fetcher and
    package derivation identities, artifacts, checks, and impact—and matches it
    against typed plan expectations;
11. rejects authored changes in unrelated units and unexpected derived effects;
12. rejects unexpected file, mode, symlink, submodule, or binary changes.

There is no line-number, filename-guessing, regex, or first-match fallback.
Dynamic Nix remains assisted or manual.

## Fail-closed evaluation checks

Migration begins with reports and ends with evaluation failures for:

- a package without exactly one classification;
- a schedulable member without exactly one unit;
- an alias/generated package with no valid owner unit;
- duplicate unit, family/stream, component, source-slot, or artifact-slot IDs;
- a current component identity outside its declared stream;
- missing primary upstream identity for an automatic/assisted unit;
- an unknown URL placeholder, origin, hash mode, or artifact kind;
- a fixed-output derivation reachable in the audited member graph but absent
  from its unit or explicit manual exceptions;
- an artifact cycle or missing dependency;
- a generated repository output without path/format/preimage/transformation
  ownership;
- members of one unit disagreeing on current/source identity;
- a missing/invalid owner path or non-literal automatic field;
- a frozen/manual unit without a reason and owner;
- an expired frozen review date;
- an invalid cohort, platform, check, or exceptional-gate reference;
- failure to round-trip through the closed Rust inventory model.

## Relationship to release inventory

The maintenance inventory and RFC-0017 release inventory share stable package,
update-unit, version, and resolved source/artifact identities. The release view
does not contain editor locators, advisory-provider policy, ignored versions,
agent configuration, or local run state.

After merge, the release planner evaluates those identities again from the
protected commit. It does not accept the maintainer tool's inventory as release
authority.

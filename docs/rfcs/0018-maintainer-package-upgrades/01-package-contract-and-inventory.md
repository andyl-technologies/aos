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

    current = {
      packageVersion = "1.3.1";
      upstreamId = "v1.3.1";
      comparisonVersion = "1.3.1";
    };

    discovery = {
      primary = {
        provider = "github-tags";
        repository = "madler/zlib";
        tagPrefix = "v";
      };

      advisors.repology.project = "zlib";
    };

    policy = {
      lifecycle = "supported";
      release = {
        strategy = "latest-in-series";
        versionScheme = "semver";
        series.major = 1;
        allowPrerelease = false;
        minimumAgeDays = 3;
      };
      riskFloor = "normal";
    };

    sources.main = {
      fetcher = "fetchurl";
      urls = [
        "https://zlib.net/fossils/zlib-{packageVersion}.tar.gz"
      ];
      hash = "sha256-...";
      hashMode = "flat";
      allowedRedirectHosts = ["zlib.net"];
    };
  };
in
  mkDerivation {
    pname = "zlib";
    inherit (upstream) version;
    src = upstream.sources.main;
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
- URL templates use only schema-defined version placeholders;
- the helper returns real AOS `fetchurl`/source derivations;
- the derivation receives normal `version`, `src`, and artifact values;
- update-only metadata is visible to evaluation but not to the package builder;
- functions, derivations, paths, secrets, or arbitrary executable update hooks
  are not serializable maintenance metadata.

## Version forms

Keep three distinct current and candidate fields:

- `packageVersion`: the AOS derivation and registry version;
- `upstreamId`: the exact release/tag/ref identity;
- `comparisonVersion`: the normalized value consumed by the selected version
  ordering scheme.

They may be equal but cannot be assumed equal. A provider adapter preserves raw
values even if normalization or policy rejects them. URL templates can
reference a declared form but cannot perform arbitrary evaluation.

## Maintained streams

Every independently maintained major, minor, LTS, branch, or snapshot line is a
separate update unit. For concurrent Bazel releases:

```nix
{
  unitId = "bazel-8";
  family = "bazel";
  stream = "8";
  classification = "assisted";

  current = {
    packageVersion = "8.4.2";
    upstreamId = "8.4.2";
    comparisonVersion = "8.4.2";
  };

  policy = {
    lifecycle = "supported";
    successorUnit = "bazel-9";
    release = {
      strategy = "latest-in-series";
      versionScheme = "semver";
      series.major = 8;
      allowPrerelease = false;
    };
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
  inherit (upstream) version sources;
  updateFor = member:
    upstream.forPackage {
      inherit member;
    };
}
```

The inventory collects member names from evaluated derivations rather than
duplicating them in the shared declaration. Every member must expose the same
unit and current source identity. A duplicated archive/version in several
recipes is a migration signal: either consolidate it into shared ownership or
declare why the units are independent.

## Source and artifact slots

One unit may contain several upstream components and several fixed-output
artifacts. A generated Go input has this conceptual shape:

```nix
upstream = mkUpstream {
  # identity and policy

  sources.main = {
    fetcher = "fetchurl";
    urls = ["https://example.invalid/project/archive/{upstreamId}.tar.gz"];
    hash = "sha256-source";
    hashMode = "flat";
  };

  artifacts.goModules = {
    kind = "go-modules";
    source = "main";
    hash = "sha256-go-modules";
  };
};

goModules = fetchGoModules {
  src = upstream.sources.main;
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

## Maintenance inventory v1

Pure Nix evaluation emits canonical primitive JSON:

```json
{
  "schema": "aos.maintenance-inventory/v1",
  "sourceCommit": "<git-commit>",
  "units": [
    {
      "unitId": "bazel-8",
      "family": "bazel",
      "stream": "8",
      "classification": "assisted",
      "current": {
        "packageVersion": "8.4.2",
        "upstreamId": "8.4.2",
        "comparisonVersion": "8.4.2"
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
(schema, update unit ID, owner path, field ID, expected old value)
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
9. requires the planned unit/fields—and only those—to change;
10. rejects unexpected file, mode, symlink, submodule, or binary changes.

There is no line-number, filename-guessing, regex, or first-match fallback.
Dynamic Nix remains assisted or manual.

## Fail-closed evaluation checks

Migration begins with reports and ends with evaluation failures for:

- a package without exactly one classification;
- a schedulable member without exactly one unit;
- an alias/generated package with no valid owner unit;
- duplicate unit, family/stream, component, source-slot, or artifact-slot IDs;
- a current version outside its declared stream;
- missing primary upstream identity for an automatic/assisted unit;
- an unknown URL placeholder, origin, hash mode, or artifact kind;
- a fixed-output hash consumed by a package but absent from its unit;
- an artifact cycle or missing dependency;
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

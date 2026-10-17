# 1. Package metadata and inventory

## 1.1. Authoring and publication

Package scan declarations MUST be authored beside the package's existing
`mkUpstream` component/discovery contract. Existing primary providers, release
streams, version projections, and lifecycle policy MUST be reused. Hub MUST
NOT require a second manually maintained upstream identity map.

The evaluated contract is projected into versioned package metadata available
without building the package. A published package version MUST bind the digest
of its scan definition. Platform artifacts additionally bind a component
inventory/SBOM where build configuration changes component presence. The
registry signer authenticates these references under the normal publication
contract. This RFC does not confer authenticity on unsigned imported metadata.

Scan results MUST NOT be embedded as mutable fields in an immutable published
package version. Metadata MAY bind the publication-time assessment digest;
the Hub API supplies later assessments with their original input binding.
Neither a later advisory nor a new scan rewrites the published declaration.

## 1.2. Scan definition contract

`aos.package-scan-definition/v1` has the following fields. All are required
except fields explicitly marked optional.

| Field | Type and constraint | Meaning |
| --- | --- | --- |
| `schema` | Exact schema string | Contract version |
| `unitId` | Bounded RFC-0018 identity | Compatible update-unit identity |
| `family` | Bounded nonempty string | Cross-stream upstream family |
| `stream` | Bounded nonempty string | Maintained release stream |
| `classification` | `automatic`, `assisted`, `manual`, `frozen`, `generated`, `alias`, `local` | Preserved RFC-0018 controller classification |
| `lifecycle` | `supported`, `security-only`, `frozen`, `retiring` | Preserved package support posture |
| `components` | Sorted component array; nonempty for upstream classes | Declared software components |
| `versionProjection` | Existing closed RFC-0018 projection; required for upstream classes, absent otherwise | Derives package version from the component vector |
| `ownerRef` | Required for generated/alias classes, absent otherwise | Exact owner unit/member and admitted definition reference |
| `reason`, `reviewAfter` | Reason required for manual/frozen; review time required for frozen | Preserved maintenance rationale/review boundary |
| `cohort` | Optional existing RFC-0018 cohort identity | Compatible multi-unit selection constraint |
| `metadataOrigins` | Sorted admitted origin identities | Provenance of declarations, without credentials |

A component contains `componentId`, `current`, `discovery`, `releasePolicy`,
and `security`. `current` preserves the exact `upstreamId`, comparison version,
and optional immutable upstream commit. `discovery` and `releasePolicy` retain
RFC-0018 semantics; a Repology advisor does not become a primary selector.

Upstream classes are `automatic`, `assisted`, `manual`, and `frozen`. Generated,
alias, and local declarations preserve the current inventory's absence of an
independent upstream component/projection. Owner references are resolved through
admitted inventory with bounded traversal and cycle rejection. They cannot
redirect provider credentials to a new project. A local package still receives
vulnerability coverage for its admitted contained components; its own unmapped
upstream identity is explicit.

Manual/frozen components may omit a primary provider as permitted by RFC-0018.
The canonical projection omits that optional member rather than copying an
older `null` field. That conversion does not invent release coverage. Security
identity and dependency assessment are independent of whether automatic source
updates are authorized.

`security` contains the following independently useful declarations:

| Field | Required? | Contract |
| --- | --- | --- |
| `identities` | Yes | Sorted nonempty identities or an explicit unmapped disposition |
| `advisorySources` | Yes | Supported provider/source IDs and their exact project mappings |
| `versionScheme` | Yes | Scheme used for advisory applicability, which may differ from release ordering |
| `dependencyCoverage` | Yes | Declared inventory coverage: complete, partial, or unknown, with basis |
| `dispositionRefs` | No | Digests of scoped reviewed statements; trust is checked independently |

Identity variants are closed records:

- `ecosystem`: exact provider-recognized ecosystem and package name;
- `purl`: parsed Package URL with its type/namespace/qualifiers retained;
- `git`: canonical upstream repository and immutable commit, or exact tag
  with provider-specific resolution evidence;
- `cpe`: explicit part, vendor, product, and relevant edition/platform
  constraints under the admitted CPE matching profile;
- `unmapped`: a reason code and explanation requiring visible unknown coverage.

Two identities MUST NOT be treated as interchangeable without an explicit
mapping. An arbitrary `pkg:generic` or `pkg:nix` identity MUST NOT be translated
to a language ecosystem or an OSV project by name guessing. Mapping review
attests the product association; it does not prove a particular build affected.

## 1.3. Authoring example

The following fragment illustrates a proposed extension of the existing
component contract. It is not executable under today's closed schema.

```nix
components.main = {
  current = {
    upstreamId = "v1.3.2";
    comparisonVersion = "1.3.2";
  };

  discovery = {
    primary = {
      provider = "github-releases";
      repository = "madler/zlib";
      tagPrefix = "v";
    };
    advisors.repology.project = "zlib";
  };

  releasePolicy = {
    strategy = "latest-in-series";
    versionScheme = "semver";
    series.major = 1;
    allowPrerelease = false;
    minimumAgeDays = 3;
  };

  security = {
    identities = [
      {
        kind = "cpe";
        part = "a";
        vendor = "zlib";
        product = "zlib";
      }
    ];
    advisorySources = [{provider = "nvd";}];
    versionScheme = "dotted-numeric";
    dependencyCoverage = {
      state = "complete";
      basis = "reviewed-component-inventory";
    };
  };
};
```

Real mappings MUST be validated against provider identity and package source
before publication. The example's coverage claim applies to the declared
component inventory, not all undisclosed software in the build or fleet.

## 1.4. Separation of package and deployment policy

Package metadata declares identities, supported observation methods, stream
constraints, and component relationships. It MUST NOT carry secrets, shell
commands, uploaded programs, arbitrary regular expressions, request headers,
notification URLs, scheduler leases, or permission grants.

The deployment owns provider credentials, approved private-provider origins,
request budgets, polling cadence, concurrency, notification destinations, and
release-policy enforcement. Package metadata MAY request stricter freshness;
the deployment MUST either satisfy it or show that the required evidence is
unknown. It MUST NOT silently weaken the package's identity or stream policy.

Existing package minimum-age settings remain selection constraints, not a
request to sleep in a Worker. The coordinator schedules reevaluation at the
next policy boundary using durable first-observed history.

## 1.5. Inventory revision

`aos.scan-inventory/v1` contains `schema`, ordered `subjects`, ordered
`components`, ordered `relationships`, and `coverage`. Its digest excludes
execution location and database IDs. Subject and component identities are
content-bound, not inferred from a store-path basename.

A subject names its package coordinate, raw package version, target platform,
named output or aggregate kind, artifact digest when available, scan-definition
digest, and component-inventory digest. A source-only subject instead records
an explicit source-content digest and MUST NOT claim a built artifact identity.

Each component instance names its logical component, identity/version,
scan-definition digest, and the containing subject. Separate instances are
retained when the same upstream version appears in multiple artifacts with
different patches, target configuration, or provenance.

Relationships use the closed kinds `contains`, `runtime-depends-on`,
`build-depends-on`, and `source-of`. A runtime exposure report MUST NOT mix
build-only components into the shipped closure. A supply-chain report MAY
include them, but MUST label the relationship and report scope. Cyclic runtime
graphs are allowed; traversal deduplicates instances and has explicit bounds.

Aggregate subjects bind their exact member set. Changing the package selection,
platform, optional feature set, or dependency graph creates a new revision.
A resolved channel name is replaced by its pinned release/artifact identity
before execution; channel movement cannot retarget an admitted scan.

## 1.6. Bundled dependencies and build evidence

A Nix runtime closure enumerates store objects, not every library embedded in
them. Inventories MUST account for static and bundled dependencies where
admitted build evidence exists. Cargo, Go, npm, and other vendor/lockfile
materializers SHOULD emit their resolved component identities and classify
which are actually included in distributed outputs.

A lockfile alone is not proof of runtime inclusion. Unknown inclusion MUST
remain visible; it cannot turn every development dependency into confirmed
runtime exposure or silently discard it. Build configuration and patch
evidence MUST bind the exact artifact assessed.

SPDX output MUST retain existing NAR identities and gain supported external
component identities and relationships. A generic source artifact with version
`source` is not an upstream software version. Unsupported SBOM fields MUST
produce an explicit coverage diagnostic rather than guessing their meaning.

## 1.7. Hub ingestion and source provenance

The ingestion adapter validates publisher authority, schema, digests,
association with package versions, and platform membership before committing
an inventory revision. Malformed new metadata MUST NOT replace the last valid
revision. The affected package is marked ingestion-blocked/unknown with a
diagnostic; older evidence stays attached to its own input revision.

Source provenance is a separate envelope. It MAY identify a signed registry
release, an admitted package publication, an imported SBOM, or a local
repository observation. Hub scanning consumes the same normalized inventory
for each origin and MUST NOT require fabricated local Git roots.

Local source envelopes retain clean commit/tree or dirty-content identities.
Dirty source MAY be assessed, but MUST remain ineligible for a write plan under
RFC-0018. Absolute local paths MUST NOT enter portable inventory or public
assessment payloads.

## 1.8. Missing metadata and rollout

Legacy packages are ingested with explicit `unmapped`/unknown scan coverage.
They remain browseable under existing publication policy, but cannot satisfy
a gate requiring complete assessment. A migration MAY populate declarations
through reviewed package edits. Same-name Repology probing remains an
explicit non-authoritative fallback and never silently upgrades identity trust.

Scan-definition support is advertised separately from supported providers.
Reader-first rollout MUST cover registry consumers, shared Hub indexers,
Worker object parsers, release builders, and the local inventory evaluator.
Older readers that cannot understand the new metadata MUST reject the
affected format, rather than ignore fields required by a security policy.

# Discovery and version policy

## Authority hierarchy

Discovery gathers evidence; it does not define package truth. Candidate
authority is:

1. the primary upstream source declared by each update-unit component;
2. Repology as a cross-repository advisory and discrepancy signal;
3. an optional secondary observation source for upstreams without a sufficient
   direct adapter;
4. a maintainer when identity, ordering, or source evidence remains ambiguous.

Only a component's declared primary upstream can produce its selectable
candidate. Repology can trigger investigation or corroborate a result, but it
cannot override stream policy, construct source URLs, choose a compatible
component vector, or authorize bytes.

## Provider contract

Provider adapters return bounded candidate sets and immutable observation
records rather than a single `latest` string:

```json
{
  "schema": "aos.upstream-observation/v1",
  "provider": "github-releases",
  "project": "Kitware/CMake",
  "retrievedAt": "<timestamp>",
  "request": {
    "url": "https://api.github.com/...",
    "cacheValidator": "<etag-or-null>"
  },
  "coverage": {
    "kind": "through-current",
    "boundary": "v3.31.6",
    "truncated": false
  },
  "responseDigest": "sha256:...",
  "candidates": [
    {
      "rawId": "v4.4.3",
      "rawVersion": "4.4.3",
      "publishedAt": "<timestamp-or-null>",
      "firstObservedAt": "<timestamp>",
      "prerelease": false,
      "yanked": false,
      "releaseUrl": "https://example.invalid/release",
      "sourceClaims": []
    }
  ]
}
```

The closed adapter interface includes:

- a typed provider/project configuration;
- bounded pagination, response bytes, candidate count, and string sizes;
- a proof that results are complete, cover all releases through the current
  identity or a stream lower bound, or are truncated/unknown;
- conditional request state and cache freshness;
- stable error classes;
- raw IDs and versions preserved without normalization loss;
- optional release time, prerelease/yanked state, release/source links,
  checksum/signature links, and VCS identity;
- no executable package-authored callback.

For a provider ordered newest-first, the adapter paginates until it observes the
current immutable identity or a stream-specific lower bound that proves every
potentially newer candidate was seen. For unordered providers, it needs a
provider-specific completeness proof. Hitting a page/count/byte limit before
that boundary yields a truncated observation and `unknown`, never `no-change`.
Fixtures interleave several maintained majors so a busy mainline cannot hide a
newer release on an older supported stream.

Initial direct adapters should be chosen from the evaluated package inventory,
not a generic ecosystem wish list. Expected high-value classes are GitHub and
GitLab releases/tags, GNU directory conventions, kernel.org release data,
ecosystem registries already consumed by AOS, a constrained JSON/directory
index, and explicit VCS snapshot observation.

Adapters are reviewed AOS Rust code. Package metadata cannot inject arbitrary
URLs beyond its declared origins, unbounded regular expressions, shell
commands, scripts, or request headers. Credentials, where a public provider
requires them for reasonable rate limits, belong to the local discovery command
configuration and are not serialized into the inventory, cache, plan, logs, or
agent task.

## GitHub release handling

Do not use the GitHub `releases/latest` result as a version decision. GitHub
excludes draft/prerelease entries but selects the most recent release by
`created_at`, which reflects the tagged commit date rather than the greatest
version or the desired maintenance line. A backport release can therefore be
temporally latest but belong to a lower line.

List bounded pages until the adapter proves coverage through the current
identity/stream boundary, retain release times and raw tags, and let the
component's pure version policy choose. A configured safety limit that prevents
that proof returns `unknown`. Use conditional requests and ETags; GitHub
recommends them to avoid unnecessary rate-limit usage. See the
[release API](https://docs.github.com/en/rest/releases/releases#get-the-latest-release)
and [conditional-request guidance](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests).

## Repology integration

Repology contributes valuable cross-distribution normalization and statuses
including `newest`, `devel`, `unique`, `outdated`, `legacy`, `rolling`,
`noscheme`, `incorrect`, `untrusted`, and `ignored`. Its records distinguish a
sanitized `version` from repository-native `origversion`. The public lookup key
is a Repology project, not an AOS package or update-unit ID.

Its API contract requires conservative local behavior:

- no more than one request per second;
- more than 1,000 requests per day is discouraged;
- a bulk client user agent must identify the source repository with an
  accessible issue tracker;
- API stability is not guaranteed.

These constraints and status definitions are documented in Repology's pinned
[API source](https://github.com/repology/repology-rs/blob/4f10afe4209e8d8e28d9622090a6ddded4a901fc/repology-webapp/templates/api.html)
and [status list](https://github.com/repology/repology-rs/blob/4f10afe4209e8d8e28d9622090a6ddded4a901fc/repology-webapp/templates/_includes/versionclass/list.html).

`aos maintain scan` therefore uses host-wide provider state beneath the XDG
state root rather than a per-checkout timer. A cross-process lease/token bucket
persists the one-second spacing, daily request budget, and `Retry-After`
deadline across scans and clones. Budget exhaustion makes advisory evidence
`unknown`; it never violates Repology's policy. The command also:

- sends a compliant AOS source/issue-tracker user agent;
- persists raw response digest, retrieval time, cache state, and parser version;
- reuses sufficiently fresh cache entries across units and scans;
- keeps all returned records and statuses used in the decision;
- reports missing mappings, ambiguous projects, suspicious status, and
  disagreement explicitly;
- treats timeout, rate limiting, parser incompatibility, and outage as
  `unknown`, never `current`;
- cannot select a release solely because Repology marks it `newest`.

Daily Repology PostgreSQL dumps are not part of the local workflow. Their
published instructions describe version-coupled imports exceeding 10 GB after
decompression. If public API use later becomes unsuitable, changing the
observation source is an adapter/cache decision rather than a package-contract
change. See the [dump README](https://dumps.repology.org/README.txt).

## Local observation cache

Each network response is stored by content digest under the XDG cache root.
Mutable provider cache metadata maps the normalized request identity to:

- content digest;
- response status and validation headers;
- retrieval and expiry times;
- adapter/schema version;
- sanitized request identity;
- parse success or typed failure.

Cached response bytes remain untrusted and pass the same size/schema parser on
every use. A `304 Not Modified` observation creates a new retrieval record that
references the existing bytes; it does not rewrite their history.

`--offline` succeeds only when every required primary observation is present,
valid, and fresh under the unit policy. Advisory data may be stale or missing if
policy explicitly permits that state and reports it. The resulting plan records
the precise freshness decision.

Observation freshness and candidate stabilization are separate clocks:

- every provider policy declares `observationMaxAge`, with a repository
  default fixed by schema/policy version;
- `minimumAgeDays` declares its allowed basis: authenticated provider
  publication time, immutable VCS commit time, or durable local
  `firstObservedAt`;
- a required but missing/invalid time basis makes selection `unknown`;
- `firstObservedAt` is kept in durable host-wide provider state rather than the
  disposable response cache, and is keyed by provider/project/raw immutable
  identity;
- wall-clock rollback or implausible future time stops age-based selection for
  inspection.

## Normalization and ordering

Supported version schemes should initially include:

- SemVer;
- calendar versions;
- Nix-style loose versions;
- a small set of ecosystem-specific schemes justified by current packages;
- opaque/VCS identities that require explicit ordering data.

Nix's `builtins.compareVersions` is a useful loose-version baseline but cannot
identify compatibility lines, prerelease semantics, epochs, or project-specific
ordering alone. See the
[Nix builtins reference](https://nix.dev/manual/nix/2.35/language/builtins.html#builtins-compareVersions).

Each normalizer returns either:

- a comparison key plus the preserved raw identity;
- a typed rejection explaining why the candidate cannot be ordered.

Never silently strip arbitrary prefixes/suffixes or coerce an invalid version
into a plausible one. Package, upstream, and comparison forms remain visible in
the plan and PR.

Each component declares one closed stream selector:

- `version-range`: version scheme plus major/minor/range and prerelease rules;
- `channel`: an exact provider feed/channel identity whose records carry the
  channel provenance;
- `vcs-lineage`: repository, named branch/ref policy, current immutable commit,
  and required ancestry/order evidence;
- `manual`: no automatic ordering or selection.

A VCS observation resolves names to immutable commit IDs and proves the target
is a descendant of the current commit under the declared lineage. Force-push,
unreachable current commits, ambiguous ancestry, or inability to obtain the
required graph quarantines the candidate. Commit timestamp alone is not
lineage/order proof.

The component also declares a typed candidate projection from provider fields
to `upstreamId`, `comparisonVersion`, and any URL version form. The unit's typed
package-version projection then consumes the closed component target vector.
Two raw identities mapping to one comparison key quarantine unless an explicit
canonical-alias rule identifies equivalent releases and a deterministic
preferred identity.

## Candidate selection

Selection is pure and deterministic per component, followed by the unit's
compatibility and package-version projections. It consumes the update unit plus
observation documents and produces:

- `no-change`;
- `candidate` with a complete explanation;
- `unknown` because required evidence is unavailable;
- `quarantined` because evidence conflicts or violates trust policy;
- `manual` because the lifecycle or scheme requires maintainer selection.

Policy applies in this order:

1. validate provider/project identity and observation bounds;
2. require coverage/completeness sufficient for `candidate` or `no-change`;
3. project and normalize without discarding raw values;
4. quarantine unapproved normalization collisions;
5. reject yanked, malformed, or disallowed prerelease candidates;
6. apply the declared range/channel/VCS-lineage selector;
7. apply explicit ignored-release and project-specific typed filters;
8. require a candidate to be newer under the declared scheme/evidence;
9. enforce the declared stabilization basis and observation freshness;
10. evaluate advisory corroboration/disagreement policy;
11. select the greatest acceptable candidate deterministically;
12. resolve a compatible complete component vector and projected package
    version;
13. record every rejected candidate and reason.

For concurrent majors, each unit selects only inside its own stream. Family-
level reporting can show a newly available major, but introducing or retiring a
stream requires a separate maintainer plan. It never becomes an in-place
version edit.

## Source resolution

After candidate selection, the local tool evaluates the component's parsed URL-
template AST. It percent-encodes values in their declared path-segment or
query-value position and cannot substitute into scheme, authority, port, user
info, or structural delimiters. It then fetches sources through the existing
AOS transfer machinery. For each source slot it records:

- requested URL and ordered mirrors;
- redirects and final origin;
- bounded transport metadata useful for diagnosis;
- size and digest;
- upstream release/tag/ref identity;
- checksum, signature, or provenance identity and verification outcome;
- trust-policy version.

The source resolver, not the agent, computes hashes and assurance outcomes.
A new Nix hash gives future immutability but does not establish that the first
downloaded bytes were authentic.

Every source gets one explicit assurance result:

- `verified-authentic`: an independently anchored signature, checksum, or
  provenance identity verified under pinned key/rotation policy;
- `origin-integrity`: allowlisted HTTPS origin and newly recorded digest, with
  no independent authenticity anchor;
- `failed`: required assurance or origin policy failed;
- `unknown`: evidence needed by policy is unavailable or indeterminate.

Only `verified-authentic` is described as authenticated. A unit may explicitly
permit `origin-integrity` to prepare a candidate PR, but risk and human-source-
review gates remain visible. Losing a previously required verification path
quarantines the source. Key identity, rotation, and checksum-origin policy must
be declared before a source can produce `verified-authentic`.

Quarantine rather than update when:

- bytes change for the same supposedly immutable release identity;
- mirrors disagree;
- a redirect leaves the allowed origin set;
- an expected signature/checksum disappears or becomes invalid;
- archive identity conflicts with the selected version;
- source type or size changes beyond policy;
- primary and advisory identities indicate a likely project mapping error.

The maintainer can inspect preserved digests and sanitized origin evidence, then
create a new explicit plan if the change is legitimate.

## Discovery snapshots

One scan produces content-addressed `aos.discovery-snapshot/v1` containing:

- repository/inventory-envelope digest;
- adapter, parser, and normalization versions;
- sanitized request identities and raw response digests;
- retrieval time and cache/freshness decision;
- parsed primary and advisory candidates;
- candidate normalization and filtering reasons;
- provider errors, discrepancies, and quarantines.

Changing policy re-evaluates an immutable snapshot into a new decision record.
It does not rewrite why the earlier decision was made. A fresh network scan
creates a new snapshot.

## Closed campaign plan

A selected compatible component vector becomes
`aos.package-update-plan/v1` before worktree creation or mutation. The default
campaign has one unit; an explicit cohort or approved dependency expansion has
an ordered set of unit target vectors. One campaign plan binds:

- run/campaign ID and ordered update-unit IDs;
- clean base commit/tree and inventory-envelope/discovery-snapshot digests;
- every unit's current/target package version and complete component vector;
- selected primary record and advisory disposition;
- source/artifact slots and expected old values;
- allowed owner paths and semantic fields;
- member packages, platforms, checks, dependency/reverse-dependency impact,
  and exceptional gates;
- materialization DAG;
- risk and required maintainer decisions;
- attempt, elapsed-time, compute, disk, download, and agent-token limits;
- tool/policy versions and expiry conditions.

The plan expires if its base, inventory, current unit identity, expected old
values, discovery freshness, or policy changes. The executor validates the plan
before every effect rather than only at creation.

## Grouping

Default to a one-unit campaign per run, branch, and PR. Expand the campaign only
for:

- members already owned by one shared-source unit;
- units in an explicit atomic cohort;
- a dependency cycle that cannot build separately;
- a maintainer-authored migration plan;
- a newly required AOS dependency whose unit must land in the same change.

Family, ecosystem, maintainer, release date, or discovery batch are not grouping
reasons. `bazel-7`, `bazel-8`, and `bazel-9` remain separate unless a deliberate
default-alias or bootstrap migration creates a temporary cohort.

## Risk

Risk has a package-authored floor and deterministic escalation. Neither an
agent nor an updated package declaration inside the worktree can lower the
plan's original floor.

Inputs include:

- patch/minor/major/snapshot/stream-lifecycle change;
- bootstrap, toolchain, kernel, init, crypto, Secure Boot, QEMU/Crucible,
  system-image, or release-closure membership;
- direct and transitive reverse-dependency reach;
- source, origin, redirect, checksum, signature, or provenance changes;
- number and kind of regenerated artifacts;
- patch additions/removals/fuzz and generated-code changes;
- build/runtime dependency, feature, license, and output changes;
- target-specific divergence;
- total semantic and filesystem diff;
- upstream security relevance.

Suggested classes:

| Class | Treatment |
| --- | --- |
| Low | Conventional leaf patch update; ordinary owner review and complete final suite |
| Normal | Minor update or meaningful reverse dependencies; broader quick canaries |
| High | Major update, new dependency, crypto/init/kernel/toolchain, or substantial patch churn; explicit specialist review and full affected closure |
| Exceptional | Bootstrap migration, QEMU/Crucible boundary, release/signing behavior; human-led campaign with mandatory special gates |

Reports prioritize confirmed security updates and unsupported streams, then
staleness age weighted by exposure, risk, and deterministic success likelihood.
The number of version components skipped is not an adequate priority by itself.

## Precedents, not dependencies

Renovate usefully separates datasource, manager, and versioning concepts, but
its [Nix manager](https://docs.renovatebot.com/modules/manager/nix/) targets
flake inputs. A regex manager cannot safely coordinate version, several hashes,
generated inputs, patches, and validation; its own
[regex documentation](https://docs.renovatebot.com/modules/manager/regex/)
describes per-file capture-based replacement.

nix-update contains useful fixed-output and generated-dependency techniques,
but its documented source replacement can select the wrong text in complex
files and its execution environment is tied to nixpkgs/Python. AOS may adapt a
reviewed MIT-licensed algorithm, but no nix-update or nixpkgs code is needed at
runtime. See its pinned
[README and known limitations](https://github.com/Mic92/nix-update/blob/4f9f53413ba6e8b19de1b3a0500f17910320eda4/README.md).

nvchecker is a useful catalogue of source/filter concepts but stops at version
detection. See its [usage reference](https://nvchecker.readthedocs.io/en/latest/usage.html).
These comparisons validate an AOS-owned provider/policy boundary; they do not
define the implementation.

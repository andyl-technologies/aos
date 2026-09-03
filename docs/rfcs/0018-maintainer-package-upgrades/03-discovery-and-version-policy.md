# Discovery and version policy

## Authority hierarchy

Discovery gathers evidence; it does not define package truth. Candidate
authority is:

1. the primary upstream source declared by the update unit;
2. Repology as a cross-repository advisory and discrepancy signal;
3. an optional secondary observation source for upstreams without a sufficient
   direct adapter;
4. a maintainer when identity, ordering, or source evidence remains ambiguous.

Only the declared primary upstream can produce a selectable release. Repology
can trigger investigation or corroborate a result, but it cannot override the
unit's maintained stream, construct source URLs, or authorize bytes.

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
  "responseDigest": "sha256:...",
  "candidates": [
    {
      "rawId": "v4.4.3",
      "rawVersion": "4.4.3",
      "publishedAt": "<timestamp-or-null>",
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
- conditional request state and cache freshness;
- stable error classes;
- raw IDs and versions preserved without normalization loss;
- optional release time, prerelease/yanked state, release/source links,
  checksum/signature links, and VCS identity;
- no executable package-authored callback.

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

List a bounded candidate window, retain release times and raw tags, and let the
unit's pure version policy choose. Use conditional requests and ETags; GitHub
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

`aos maintain scan` therefore:

- paces all Repology requests through one local limiter;
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

## Candidate selection

Selection is pure and deterministic over the update unit plus observation
documents. It produces:

- `no-change`;
- `candidate` with a complete explanation;
- `unknown` because required evidence is unavailable;
- `quarantined` because evidence conflicts or violates trust policy;
- `manual` because the lifecycle or scheme requires maintainer selection.

Policy applies in this order:

1. validate provider/project identity and observation bounds;
2. normalize without discarding raw values;
3. reject yanked, malformed, or disallowed prerelease candidates;
4. constrain candidates to the declared major/minor/branch/LTS stream;
5. apply explicit ignored-release and project-specific typed filters;
6. require a candidate to be newer under the declared scheme;
7. enforce minimum age or stabilization delay;
8. evaluate advisory corroboration/disagreement policy;
9. select the greatest acceptable candidate deterministically;
10. record every rejected candidate and reason.

For concurrent majors, each unit selects only inside its own stream. Family-
level reporting can show a newly available major, but introducing or retiring a
stream requires a separate maintainer plan. It never becomes an in-place
version edit.

## Source resolution

After candidate selection, the local tool expands the unit's schema-defined URL
templates and fetches sources through the existing AOS transfer machinery. For
each source slot it records:

- requested URL and ordered mirrors;
- redirects and final origin;
- bounded transport metadata useful for diagnosis;
- size and digest;
- upstream release/tag/ref identity;
- checksum, signature, or provenance identity and verification outcome;
- trust-policy version.

The source resolver, not the agent, computes hashes and authenticity outcomes.
A new Nix hash gives future immutability but does not establish that the first
downloaded bytes were authentic.

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

One scan produces immutable `aos.discovery-snapshot/v1` containing:

- repository source commit and inventory digest;
- adapter, parser, and normalization versions;
- sanitized request identities and raw response digests;
- retrieval time and cache/freshness decision;
- parsed primary and advisory candidates;
- candidate normalization and filtering reasons;
- provider errors, discrepancies, and quarantines.

Changing policy re-evaluates an immutable snapshot into a new decision record.
It does not rewrite why the earlier decision was made. A fresh network scan
creates a new snapshot.

## Closed update plan

A selected candidate becomes `aos.package-update-plan/v1` before worktree
creation or mutation. It binds:

- run and update-unit IDs;
- base commit, inventory digest, and discovery-snapshot digest;
- current and target version forms;
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

Default to one update unit per run, branch, and PR. Group only:

- members already owned by one shared-source unit;
- units in an explicit atomic cohort;
- a dependency cycle that cannot build separately;
- a maintainer-authored migration plan.

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

# 07 — CI caches on GCP spot runners

This file describes how AOS uses Terrane as the shared cache for continuous
integration: one warehouse over a Google Cloud Storage bucket, spot-VM
runners on Google Compute Engine holding ephemeral caches, and three
protocol surfaces (`nix-cache`, `reapi`, `gha-cache`) over one tree. It is
the second and third consumer of the MVP
([`05-implementation-plan.md`](05-implementation-plan.md) §The MVP); the
sandbox view service is the first. Requirement IDs use the prefix `CI`.

## Why one system

A Nix binary cache, a Bazel remote cache, and a GitHub Actions cache are
three protocols over the same need: a job reads everything a trusted
baseline has, writes results visible only to itself, and has those results
folded into the baseline when its change merges, without copying anything.
In Terrane that is one tree with three roots, one branch per change, and
one merge per accepted change (spec ALG-32 to ALG-35). The three surfaces
differ only in schema and credential mapping (spec SURF-20 to SURF-23).

## Deployment shape

```text
                  GCS bucket (authority: refs, packs, indexes)
                          ▲ conditional writes, presigned reads
                          │
        terrane serve ────┴──── terrane serve       GCE, behind an internal
        guard(bucket(gcs://ci))                     load balancer; stateless
                          ▲ wire protocol (control only)
                          │
   spot runner ── terrane realize ── routed[disk(ephemeral), remote(warehouse)]
   nix / bazel / actions client ── nix-cache · reapi · gha-cache exposures
                          │ bulk bytes: presigned GET straight to GCS
```

- **[CI-1]** The warehouse MUST be the `serve` role running
  `guard(bucket(gcs://…))` on GCE instances behind a load balancer. It
  MUST be stateless apart from caches: every instance serves the same
  bucket, and an instance MAY be replaced at any time (spec STORE-16,
  TOPO-27).
- **[CI-2]** The bucket backend for GCS MUST implement refs by
  `x-goog-if-generation-match` preconditions and create-once keys by
  generation `0` (spec BKT-5, BKT-6, `13-bucket-layout.md` §Conditional
  writes), MUST mint presigned reads as V4 signed URLs (spec PROTO-55), and
  MUST pass the startup probe (spec BKT-10) before accepting writers. The
  live probe against a real bucket is run by hand and recorded in
  [`06-decision-register.md`](06-decision-register.md); the Nix check uses a
  recorded fixture.
- **[CI-3]** The CI tree MUST be one root, `refs/heads/ci/master`, with the
  following grafted roots and properties. Each protocol surface is exposed
  over its own subtree (spec SURF-7).

```text
/                     domain=public   retain=gc       trust=signed-baseline
/nix/store            nix-cache schema (spec NIX-4)
/bazel/cas            reapi schema, cas/ (spec REAPI-1)   index=[hash.sha256]
/bazel/ac             reapi schema, ac/  (spec REAPI-1)
/gha/<version>/<key>  gha-cache schema   (spec GHA-1)     retain=ttl(30d)
```

Deduplication is global within the public domain (spec DOM-6), so a NAR
uploaded by `nix` and the same bytes uploaded as a Bazel blob share chunks.

## Identity and authority

- **[CI-4]** A runner MUST obtain its Terrane token from the GCP
  instance-identity issuer in the `serve` role: it presents the GCE
  instance identity token for its own instance, and the issuer mints a
  workload token (spec AUTH-3) bound to the instance id and to the job the
  instance declares in its metadata, with an expiry no later than the
  job's maximum duration plus a bounded margin.
- **[CI-5]** The token minted for a change's job MUST carry exactly:
  `fork` on `refs/heads/ci/master`, and `commit` (which implies `read`,
  spec AUTH-22) on `refs/heads/ci/pr/<n>` for that change only. It MUST
  NOT carry `commit` on master (spec AUTH-23). The runner attenuates this
  token further per exposure (spec AUTH-36).
- **[CI-6]** Folding a change into the baseline MUST be done by a separate
  post-merge job whose token carries `commit` on `refs/heads/ci/master`.
  That job runs only for changes the source forge reports as merged, and
  its token is minted by the same issuer from a distinct instance role.
  No surface exposes a fold to protocol clients (spec GHA-4).
- **[CI-7]** A fold MUST be a three-way merge with base
  `master@N` (the sequence the change forked at), ours `master@now`, theirs
  the change's branch, under the `prefer-ours` policy for conflicting keys
  (spec ALG-33, ALG-18); the fold commit re-signs with the post-merge
  principal and lists the change's commit as a parent (spec PROV-17). After
  the fold the change's branch MUST be retired by tagging its last commit
  under `refs/tags/ci/pr/<n>` and deleting the branch (spec ALG-35).
- **[CI-8]** `refs/heads/ci/pr/*` roots MUST carry `retain=ttl` with a
  bound of thirty days, so an abandoned change's caches are collected
  without a fold (spec GC-28). Tags under `refs/tags/ci/pr/*` carry the
  same retention.

## Credential mapping

Each protocol brings its own credential; none of them is a Terrane token.

- **[CI-9]** Each exposure MUST map the client's credential through the
  exposure's configured issuer (spec SURF-21 (b)): the GitHub Actions job
  token, the Bazel `--remote_header` bearer, and the Nix bearer or netrc
  credential are each exchanged for an attenuation of the runner's
  workload token scoped to the job's branch. The surface then forgets the
  foreign credential (spec PROV-25).
- **[CI-10]** The mapping MUST NOT widen authority: the resulting token is a
  child of the runner's token (spec SURF-22, AUTH-14), so a forged client
  credential can at most reach what the runner already could. This is
  tested for every surface by the credential-mapping check.

## Runner configuration

- **[CI-11]** A spot runner MUST run `terrane` in the `realize` role with
  the store expression `routed[disk(<ephemeral>), remote(<warehouse>)]`,
  where `remote` names the load balancer. Reads of bulk bytes MUST go by
  presigned GET straight to GCS (spec PROTO-55, PERF-9); the warehouse
  carries control traffic only.
- **[CI-12]** The `disk` tier MUST live on the instance's ephemeral disk,
  sized from the instance's capacity by the module, with `redundancy=none`
  and no expectation of surviving the instance. Nothing on the runner is
  authoritative; every byte the runner holds is either in the bucket or is
  uncommitted work.
- **[CI-13]** Exposures on a runner MUST use the `periodic` writer mode with
  an interval of at most sixty seconds (spec CONS-7, CONS-9). A commit is
  the durability point: when a spot instance is preempted, the uncommitted
  upper is lost and every committed result survives. Jobs that must not
  lose the last interval call `terrane commit` through the `.terrane`
  control directory before exiting (spec CONS-35).
- **[CI-14]** At boot the runner MUST warm the bundle for its view (spec
  PACK-24, PROTO bundles) before announcing the exposures ready, so the
  first lookup does not wait on the bucket. Warming of content beyond the
  bundle is deferred (see below).

## Client configuration

- **[CI-15]** `nix` on a runner MUST be configured with the `nix-cache`
  exposure as a substituter and with the exposure's public signing key in
  `trusted-public-keys`; uploads use `nix copy --to` the exposure or a
  post-build hook. The surface accepts the bearer credential per spec
  NIX-13 and validates uploads per spec NIX-10 to NIX-12.
- **[CI-16]** `bazel` MUST be configured with `--remote_cache` pointing at
  the `reapi` exposure and `--remote_header` carrying the job's bearer
  credential (spec REAPI-8). Action results are served only when complete
  (spec REAPI-3), so a runner never fetches a result whose outputs were
  evicted.
- **[CI-17]** The GitHub Actions cache client MUST be pointed at the
  `gha-cache` exposure through the cache-URL environment the runner
  exposes, with the job token as the bearer (spec GHA-8). Restore-key
  semantics follow spec GHA-5; a save lands only on the job's branch (spec
  GHA-3).

## What the MVP defers

These are deliberately absent from the trunk and land on the branches
named in [`05-implementation-plan.md`](05-implementation-plan.md):

- zone-local peers and residency-based routing between runners
  (B-topology); every miss goes to the warehouse or the bucket;
- warming of content beyond the view bundle, and access-profile prefetch
  (B-bandwidth);
- `sync` writer mode for `reapi` and `gha-cache` (B-consistency); the
  `periodic` interval bounds the exposure to preemption instead;
- blocking performance thresholds (B-ops); the harness reports;
- multi-region buckets and replication (B-topology); one region, one
  bucket.

## Interactions

- [`05-implementation-plan.md`](05-implementation-plan.md) milestones T3
  and T4.
- [`06-decision-register.md`](06-decision-register.md) AD-3 (the
  three-consumer MVP) and the recorded results of the manual GCS probe.
- Spec files 07 (fork and fold), 20 (writer modes), 22 (workload issuers),
  26 and 30 (surfaces and credential mapping), 13 (GCS conditional writes).

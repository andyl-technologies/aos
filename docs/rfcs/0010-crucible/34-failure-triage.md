# 34 — Failure triage: clustering, signatures, and per-cluster reports

This file specifies Crucible's **failure-triage capability**: the offline,
deterministic projection that turns a *ledger of discovered findings* — the
property violations and divergences emitted by interactive runs, state-space
search, and coverage-guided fuzzing ([`22-advanced-features.md`](22-advanced-features.md)
§22.8) — into a small set of **root-cause clusters**, each with one
**signature-preserving minimal representative** and a **per-cluster report**.

The thing this file is most concerned with is *not adding anything to the run*.
Triage introduces **no new execution path**, **no new run state**, and **no
second record of what happened**. It is a pure, content-addressed *projection*
over the substrate Crucible already has: the one event log
([`19-observability-event-log.md`](19-observability-event-log.md)), the
content-addressed temporal graph ([`07-temporal-graph.md`](07-temporal-graph.md)),
the assertion/violation vocabulary ([`18-assertions-properties.md`](18-assertions-properties.md)),
and the self-contained reproduction artifact ([`22-advanced-features.md`](22-advanced-features.md)
§22.8, [`06-spatial-graph.md`](06-spatial-graph.md) §7.1,
[`23-cli.md`](23-cli.md), [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)
§12). A finding triaged a year after it was discovered MUST cluster, minimize,
and report **byte-for-byte identically** to one triaged the instant it was
found, because triage reads only stored artifacts and recomputes everything from
the recorded run.

Requirement IDs in this file use the prefix `TRI` (see
[`00-conventions.md`](00-conventions.md)). The canonical gates referenced here —
`gate:content-address`, `gate:e2e-determinism`, `gate:replay-oracle`, and
`gate:harness-lint` — are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.1; a
gate name used here that does not appear verbatim in that catalog is a defect
([HARN-1]). Triage is a **pure consumer** of the layers below it, exactly as the
advanced features are ([ADV-2]): it expresses everything as operations on the one
temporal graph (07) via the one execution model
([`05-execution-model.md`](05-execution-model.md)), reads the violation record of
18, the causal subsequence and coverage projection of 19, the symmetry-canonical
relabeling and `coverage_fingerprint` of 07 §2/§9, and the minimization pass of
22 §22.8.2 / [ADV-30]. It is driven offline by a thin `crucible triage`
subcommand that, like the rest of the CLI ([CLI-1], [CLI-2]), holds no run state.

The code blocks in this file are **illustrative sketches** per
[`00-conventions.md`](00-conventions.md) §"Code sketches in this RFC": they show
intended types and call order so the spec is concrete, but the authoritative
statement is always the prose requirement. A sketch that disagrees with a
requirement is a defect in the sketch.

## 34.1 What triage is, and what it is not

A Crucible exploration campaign — a state-space search ([`22-advanced-features.md`](22-advanced-features.md)
§22.5) or a coverage-guided fuzz ([`22-advanced-features.md`](22-advanced-features.md)
§22.7) — does not find *a* bug; it finds *findings*, often thousands of them,
and the same underlying defect surfaces over and over from different seeds,
schedules, and topologies. Without triage, an operator reading a campaign's
output cannot tell whether they are looking at one bug found a thousand ways or a
thousand distinct bugs. **Triage answers that question deterministically:** it
groups findings that share a *root-cause signature*, picks one minimal
representative per group, and reports each group once.

Triage is therefore a *post-processing projection*, not a runtime feature. The
distinction is load-bearing and is the entire reason triage is safe to add:

- It runs **offline**, over a stored **findings ledger** (§34.7) of reproduction
  artifacts (22 §22.8.1), never during a run and never by re-driving the
  scheduler. The only execution it ever performs is the *already-defined*
  per-candidate replay used by minimization (22 §22.8.2), which is itself a
  re-reduction of a recorded schedule (05), not a new code path.
- It introduces **no new state representation**: a finding is a reproduction
  artifact (22 §22.8), a signature is a content hash over the recorded run, a
  cluster is an equivalence class keyed by a signature, and a triage result is a
  content-addressed artifact in the `DagStore` (07 §7). There is no
  triage-specific run state, no parallel "triage log," and no record of "what
  happened" that the one event log (19) does not already own.
- It changes **nothing about determinism**: triage is a pure function of the
  stored findings and a `SignaturePolicy` (§34.2). Re-running triage on the same
  inputs MUST yield a byte-identical result ([INV-1] in spirit; the gate is
  `gate:e2e-determinism`).

- **[TRI-1]** Failure triage MUST be a deterministic, **offline**, content-addressed
  **projection** over the existing substrate — the one event log (19), the
  temporal graph (07), the violation record (18), and the reproduction artifact
  (22 §22.8, 24 §12). Triage MUST introduce **no new execution path** (05
  [EXEC-14]), **no new run state** outside `(ScenarioDef, Schedule)` (05
  [EXEC-25]) and the `DagStore` (07 §7), and **no second record of what
  happened** (19 [OBS-1]). The only execution triage performs MUST be the
  already-defined per-candidate replay of minimization (22 §22.8.2, [ADV-30]),
  which is a re-reduction of a recorded schedule (05), not a new path. *Gate:*
  `gate:e2e-determinism`, `gate:content-address`. *Spec:* §34.1; cross-ref 22
  §22.8, 05 [EXEC-14], 19 [OBS-1].

- **[TRI-2]** Triage MUST be computable purely from stored artifacts with no
  re-execution of guests for clustering or signature computation: clustering a
  finding (§34.3) MUST read only the finding's recorded run — its `ScenarioDef`,
  `Schedule`, and the causal subsequence of its event log (19 §19.5) — exactly as
  offline assertion checking does (18 [ASRT-14]). Re-running triage on the same
  findings ledger and `SignaturePolicy` MUST produce a **byte-identical** triage
  result. *Gate:* `gate:e2e-determinism`. *Spec:* §34.1; cross-ref 18 §18.6, 19
  §19.5.

## 34.2 The failure signature

The heart of triage is the **failure signature**: a deterministic,
content-addressed tuple that captures *why this run failed* in a form stable
enough that two findings of the same underlying defect produce the same
signature, and two findings of different defects produce different signatures.

The signature is computed from the **recorded run alone** — the immutable
`ScenarioDef` (06), the recorded `Schedule` (05 §3), and the **causal
subsequence** of the event log (19 §19.5, the `EventClass::Causal` projection
renumbered past observational interleaving). It is **never** a function of
wall-clock time, host map-iteration order, the discovering campaign, or any
observational entry (19 §19.3), so it is offline-recomputable and host-independent.

### 34.2.1 Signature fields

The signature is a small, closed tuple. Each field is either a **key** field
(part of the clustering key) or a **detail** field (reported but not clustered
on), as selected by the active `SignaturePolicy` (§34.2.3).

- **`failure_kind`** — the discriminant of *what kind of failure* this is. The
  closed set is `{ PropertyViolation, Divergence }`: a `PropertyViolation` is a
  failed assertion/property (18 §18.8, 18 §18.10), and a `Divergence` is a
  replay-oracle / determinism failure (07 §6, 24 §5, [INV-10]) — a run whose
  realized state disagrees with its replay-from-ancestor derivation, localized to
  a first differing decision/instruction by bisection (24 §5, 19 §19.6.2).

- **`property_id` + `quantifier`** — for a `PropertyViolation`, the violated
  property's stable **id** ([ASRT-5], [GHC-20]) and its **quantifier**
  (Always / Sometimes / Eventually / AfterQuiescence / Reachable, 18 §18.2),
  read directly from the violation record (18 §18.10.1, [ASRT-27]). Two findings
  that violate the *same* declared property under the *same* quantifier share
  this part of the signature; two findings that violate *different* properties do
  not.

- **`first_failing_point`** — `{ event_kind, faulting_node }`: the first run
  point at which the failure is *attributable*. For a `PropertyViolation` this is
  the violation site of [ASRT-27] (the failing evaluation point — the first false
  Always evaluation, the Eventually deadline instant, the AfterQuiescence
  quiescence point), reduced to its **event kind** (19 §19.7) and the **node**
  the site belongs to. For a `Divergence` this is the **first differing causal
  entry** localized by bisection (19 §19.6.2, [OBS-28]) — its `kind` and `node`.
  **Critically**, the *absolute icount* of this point is **not** a key field by
  default (it is report-only; §34.2.2), and `faulting_node` is recorded under the
  **symmetry-canonical relabeling** (§34.2.2).

- **`coverage_class`** — a *bucketed* class derived from the deterministic
  per-checkpoint `coverage_fingerprint` (07 §2), itself a deterministic digest of
  the observational coverage projection of the log (19 §19.6.3, [OBS-29], [ADV-22]).
  The raw fingerprint is too fine to cluster on (every distinct execution path
  has a distinct fingerprint), so the signature carries a **bucketing** of it — a
  coarse class such as "which fault-path / which set of basic-block regions the
  failing run exercised" — so that runs reaching the failure *through the same
  code region* cluster together while runs reaching genuinely different code do
  not. The bucketing function is a fixed, versioned part of the policy (§34.2.3).

- **`causal_slice_hash`** (optional) — a content hash over the **canonicalized
  causal cone** of the failure: the subsequence of causal entries (19 §19.5) that
  the first-failing point causally depends on (the causal cone of 19 §19.6.2 /
  the divergence-bisection neighborhood), canonicalized under the symmetry
  relabeling (§34.2.2). It is the finest-grained discriminator and is included
  only under `fine`/`exact` policies (§34.2.3); under coarser policies it is a
  detail field, so out-of-cone schedule shrinks (which minimization performs,
  §34.4) do not move the signature.

```rust,illustrative
/// A deterministic, content-addressed root-cause signature of one finding
/// (§34.2). Computed from the recorded run ALONE — `ScenarioDef`, `Schedule`,
/// and the causal subsequence of the event log (19 §19.5) — never from
/// wall-clock, host map order, or any observational entry (19 §19.3).
///
/// Which fields are KEY (clustered on) vs DETAIL (reported only) is chosen by
/// the active `SignaturePolicy` (§34.2.3) and recorded in the triage result's
/// identity, so re-clustering is idempotent (§34.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureSignature {
    /// What kind of failure: a property violation or a determinism divergence.
    pub failure_kind: FailureKind,
    /// The violated property's id + quantifier (18 §18.10.1), for
    /// `PropertyViolation`. `None` for a `Divergence`.
    pub property: Option<PropertyKey>, // { id: MarkerId, quantifier: QuantifierKind }
    /// The first attributable run point, symmetry-canonicalized (§34.2.2).
    pub first_failing_point: FailingPoint, // { event_kind, faulting_node (canonical) }
    /// A bucketed class of the deterministic coverage_fingerprint (07 §2).
    pub coverage_class: CoverageClass,
    /// Optional hash over the canonicalized causal cone (19 §19.6.2); a key
    /// field only under `fine`/`exact` policies (§34.2.3).
    pub causal_slice_hash: Option<ContentHash>,
    // REPORT-ONLY (never a default key field, §34.2.2):
    /// The absolute icount of the first-failing point. Report-only so that
    /// minimization (which changes icounts) does not change the signature.
    pub at_icount_report_only: u64,
}

/// The closed failure discriminant (§34.2.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// A failed assertion/property (18 §18.8, §18.10).
    PropertyViolation,
    /// A replay-oracle / determinism failure (07 §6, 24 §5, INV-10).
    Divergence,
}
```

- **[TRI-3]** The failure signature MUST be a deterministic, content-addressed
  tuple computed from the **recorded run alone** — the immutable `ScenarioDef`
  (06), the recorded `Schedule` (05 §3), and the **causal subsequence** of the
  event log (19 §19.5, [OBS-21]). It MUST NOT depend on host wall-clock, host
  map-iteration order, any observational event-log entry (19 §19.3, [OBS-22]), or
  the discovering campaign/family (06 [SPAT-27]). The same `(ScenarioDef,
  Schedule, causal subsequence)` MUST always yield the same signature, online or
  offline and across hosts ([INV-1], [INV-9]). *Gate:* `gate:e2e-determinism`,
  `gate:content-address`. *Spec:* §34.2; cross-ref 19 §19.5, 06 [SPAT-27].

- **[TRI-4]** The signature MUST carry at least the fields of §34.2.1:
  `failure_kind` (`{ PropertyViolation, Divergence }`); for a `PropertyViolation`
  the violated property's `id` and `quantifier` read from the violation record
  (18 §18.10.1, [ASRT-27]); a `first_failing_point` of `{ event_kind,
  faulting_node }` (the violation site of [ASRT-27] for a violation, or the first
  differing causal entry of bisection (19 [OBS-28]) for a divergence) reduced to
  its event kind (19 §19.7) and node; a `coverage_class` bucketed from the
  deterministic `coverage_fingerprint` (07 §2, [OBS-29]); and an OPTIONAL
  `causal_slice_hash` over the canonicalized causal cone (19 §19.6.2). Each field
  MUST be read from the deterministic record, never recomputed by re-execution
  for clustering (§34.2.4). *Gate:* `gate:e2e-determinism`,
  `gate:content-address`. *Spec:* §34.2.1; cross-ref 18 §18.10.1, 07 §2, 19
  §19.6.2.

### 34.2.2 The three critical normalizations

A signature that is *too literal* under-reports (the same bug looks like many
bugs) and a signature that is *too coarse* over-reports (different bugs collapse
into one). Three normalizations are non-negotiable for a stable, well-separated
signature, and each addresses a specific failure mode:

1. **Absolute icount is REPORT-ONLY by default.** The absolute instruction count
   at which the failure occurs MUST NOT be a key field under the default policy,
   because **minimization changes it**: shrinking a schedule (§34.4) removes
   decisions, which shifts every following icount. If absolute icount were a key
   field, `signature(minimal) != signature(original)` would hold by construction,
   breaking the central invariant of §34.4 ([TRI-9]). The absolute icount is
   reported (for the operator and the repro command) but is excluded from the
   clustering key.

2. **`faulting_node` under the symmetry-canonical relabeling.** The node at the
   first-failing point MUST be recorded under the **symmetry-canonical
   relabeling** of 07 §9 ([TEMP-27]) — the canonical relabeling of interchangeable
   entities (e.g. three identical replica VMs) derived from the
   `coverage_fingerprint` (07 §2). Without this, "replica A crashes" and "replica
   B crashes" — structurally the *same* bug — would produce *different* signatures
   and **under-cluster** (the same defect splits into one cluster per replica).
   Recording `faulting_node` canonically collapses these into one cluster, exactly
   as symmetry reduction collapses symmetric search nodes (22 §22.5.3, [ADV-19]).

3. **`causal_slice_hash` is over the causal CONE, not the whole schedule.** When
   present, the slice hash MUST be taken over the *causal cone* of the failure
   (the causal entries the first-failing point depends on, 19 §19.6.2), **not**
   over the entire schedule or the entire causal subsequence. This is what makes
   the slice hash **stable under minimization**: minimization removes decisions
   that are *out of the cone* (irrelevant to the failure, §34.4), and an
   out-of-cone shrink by construction does not change the cone, so it does not
   change the slice hash. A slice hash over the whole schedule would change on
   every shrink and would again break [TRI-9].

```text
  the three normalizations, and the failure mode each prevents:
  ──────────────────────────────────────────────────────────────────────────
  absolute icount → REPORT-ONLY (not a key field)
        prevents: minimization shifts icounts ⇒ signature(minimal)≠signature(orig)
        (the central §34.4 invariant [TRI-9] would be unsatisfiable)

  faulting_node → SYMMETRY-CANONICAL relabel (07 §9 [TEMP-27])
        prevents: UNDER-clustering — "replica A crashes" vs "replica B crashes"
        (the same defect) splitting into one cluster per interchangeable entity

  causal_slice_hash → over the causal CONE (19 §19.6.2), not the whole schedule
        prevents: out-of-cone shrinks changing the signature ⇒ unstable under
        minimization; cone-scoped means an irrelevant-decision removal is invisible
```

- **[TRI-5]** The signature's absolute icount of the first-failing point MUST be
  **report-only by default**: under the default `SignaturePolicy` (§34.2.3) it
  MUST NOT be a key field, because minimization (§34.4) shifts icounts when it
  removes decisions and a key icount would make `signature(minimal) !=
  signature(original)` unavoidable, violating [TRI-9]. The absolute icount MUST
  still be carried in the signature and reported (§34.5). *Gate:*
  `gate:e2e-determinism`. *Spec:* §34.2.2; cross-ref §34.4, [TRI-9].

- **[TRI-6]** The signature's `faulting_node` MUST be recorded under the
  **symmetry-canonical relabeling** of 07 §9 ([TEMP-27]) — the canonical
  relabeling of interchangeable entities derived from the `coverage_fingerprint`
  (07 §2) — so that findings differing only by which interchangeable entity
  faulted (e.g. "replica A" vs "replica B") produce the **same** signature and do
  not **under-cluster**. This is the triage-side use of the same canonicalization
  that symmetry reduction uses for search dedup (22 §22.5.3, [ADV-19]). *Gate:*
  `gate:content-address`. *Spec:* §34.2.2; cross-ref 07 §9, 22 §22.5.3.

- **[TRI-7]** When present, the `causal_slice_hash` MUST be computed over the
  **canonicalized causal cone** of the first-failing point (the causal entries it
  depends on, 19 §19.6.2), under the symmetry relabeling ([TRI-6]), **not** over
  the whole schedule or the whole causal subsequence. This MUST make the slice
  hash **stable under minimization**: an out-of-cone decision removal (§34.4) does
  not change the cone and therefore does not change the hash. A slice hash over
  the whole schedule is a defect because it would change on every shrink and break
  [TRI-9]. *Gate:* `gate:content-address`, `gate:e2e-determinism`. *Spec:*
  §34.2.2; cross-ref 19 §19.6.2, §34.4.

### 34.2.3 `SignaturePolicy` — which fields are key vs detail

Different triage questions want different granularity. A coarse pass ("how many
distinct *kinds* of failure are there?") wants few key fields; a fine pass
("which exact code paths fail?") wants many. The **`SignaturePolicy`** is the
closed, versioned selector of *which signature fields are key* (part of the
clustering key) versus *detail* (reported but not clustered on), plus the fixed
`coverage_class` bucketing function (§34.2.1).

```text
  SignaturePolicy   key fields (clustered on)                         use
  ───────────────   ────────────────────────────────────────────────  ─────────────────
  coarse            failure_kind, property.id                          "how many kinds?"
  default           + property.quantifier, first_failing_point.kind,   the everyday pass
                      first_failing_point.node(canonical), coverage_class
  fine              + causal_slice_hash                                "which code paths?"
  exact             + absolute icount, full causal cone                forensic / no merge
  ──────────────────────────────────────────────────────────────────────────────────────
  absolute icount is a key field ONLY under `exact` (which never minimizes-merges,
  §34.4); under coarse/default/fine it is report-only ([TRI-5]).
```

The policy is recorded **in the triage result's identity** (§34.3, §34.6), so a
triage result is content-addressed by `(findings ledger content, policy)` and
re-clustering the same ledger under the same policy is **idempotent** — it
resolves to the same content-addressed result and is a `DagStore` cache hit (07
§7), never a recompute that could drift.

- **[TRI-8]** Triage MUST provide a closed, versioned **`SignaturePolicy`** with at
  least the levels `coarse`, `default`, `fine`, and `exact`, selecting which
  signature fields (§34.2.1) are **key** (clustered on) versus **detail**
  (reported only) and fixing the `coverage_class` bucketing function. `exact` MUST
  be the only level under which absolute icount and the full causal cone are key
  fields ([TRI-5]), and `exact` MUST NOT minimize-merge (§34.4). The active policy
  MUST be recorded in the triage result's identity (§34.6) so that re-clustering
  the same findings ledger under the same policy is **idempotent** — it resolves
  to the same content-addressed triage result (07 §7) rather than recomputing. A
  policy change MUST be a versioned change to the triage result schema. *Gate:*
  `gate:content-address`. *Spec:* §34.2.3; cross-ref §34.3, §34.6, 07 §7.

### 34.2.4 The signature is read, not re-derived

The signature is read entirely from the deterministic record — the violation
record (18 §18.10.1), the causal subsequence (19 §19.5), the bisection result for
a divergence (24 §5), and the `coverage_fingerprint` (07 §2). It is **never**
recomputed by re-executing the guests for the purpose of clustering: clustering
reads stored artifacts only, exactly as offline assertion checking does (18
[ASRT-14]). The one place triage executes anything is minimization (§34.4), and
even there each candidate is a re-reduction of a recorded schedule (05),
validated like any run (24, [ADV-31]).

- **[TRI-9-pre]** (descriptive) Because every signature field is read from the
  deterministic record, two computations of the signature of the same finding
  agree byte-for-byte; this is what `--recompute-signatures` (§34.6) verifies
  against the discovery-time signature.

## 34.3 Clustering: a deterministic equivalence-class partition

Given a set of findings and a `SignaturePolicy`, **clustering** partitions the
findings into equivalence classes by their **signature key** (the key fields
under the active policy, §34.2.3). Two findings are in the same cluster iff their
signature keys are equal; the **cluster id** is the **content hash of the
signature key**, so cluster identity is content-addressed and stable.

Clustering is a pure deterministic fold: it reads each finding's stored run,
computes the signature ([TRI-3]), and groups by key. There is no host-side
nondeterminism on any ordering-significant path — the output cluster order, the
intra-cluster member order, and the cluster ids are all **content-address
ordered** (07 §1, [INV-9]), never host map-iteration order.

```text
  cluster(findings, policy):
  ──────────────────────────────────────────────────────────────────────────
  for each finding f in findings (a reproduction artifact, 22 §22.8):
    sig := signature(f, policy)            # read from f's recorded run ([TRI-3])
    key := project_key(sig, policy)        # the policy's KEY fields (§34.2.3)
    cluster_id := content_hash(key)        # content-addressed identity
    clusters[cluster_id].push(f)
  emit clusters, ORDERED by cluster_id (content-address order, INV-9),
       each cluster's members ORDERED by artifact content hash (never map order).
```

> `TRI-9` is reserved here; see §34.4 for the signature-preservation invariant.

- **[TRI-10]** Clustering MUST be a deterministic equivalence-class partition of
  the findings keyed by the **signature key** (the key fields under the active
  `SignaturePolicy`, §34.2.3): two findings MUST be in the same cluster iff their
  signature keys are equal. The **cluster id** MUST be the **content hash of the
  signature key**, so cluster identity is content-addressed and stable across
  hosts and runs ([INV-6]). *Gate:* `gate:content-address`. *Spec:* §34.3;
  cross-ref §34.2.3.

- **[TRI-11]** Clustering output MUST be ordered by **content address** (07 §1):
  clusters MUST be ordered by their cluster id, and the members within a cluster
  MUST be ordered by their reproduction-artifact content hash — never by host
  map-iteration order, thread scheduling, or wall-clock ([INV-9]). Two triage
  runs over the same findings ledger and policy MUST emit the identical ordering.
  The clustering pass MUST contain no host wall-clock read, no thread RNG, and no
  unordered-map iteration on an ordering-significant path
  ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §9,
  [HARN-24]). *Gate:* `gate:harness-lint`, `gate:e2e-determinism`. *Spec:* §34.3;
  cross-ref 07 §1, [INV-9].

## 34.4 Signature-preserving minimization

A cluster's findings are, by construction, all the *same* failure under the
policy — but each is a raw artifact, usually far larger than the bug needs.
Triage produces **one minimal representative per cluster** by *extending* the
existing minimization pass (22 §22.8.2, [ADV-30]) rather than by inventing a new
shrinker.

The one change triage makes to minimization is to **strengthen its accept
predicate**. The base pass (22 §22.8.2) accepts a shrunk candidate iff it still
triggers *the same violation*. Triage's pass accepts a candidate iff it still
produces *the same SIGNATURE under the active policy* — i.e.
`signature(candidate, policy) == signature(original, policy)`. Everything else is
reused unchanged: the **seeded candidate order** (22 [ADV-31], content-address
tie-broken, never host map order), the **per-candidate replay-oracle validation**
(each candidate is a full run validated like any run, 24, [ADV-11], [ADV-31]),
and the bit-reproducibility of every candidate (22 [ADV-28]).

This is *why* the three normalizations of §34.2.2 matter so much: minimization
removes decisions, which shifts icounts (so icount must be report-only, [TRI-5])
and removes out-of-cone decisions (so the slice hash must be cone-scoped,
[TRI-7]); and it can shrink across interchangeable entities (so the node must be
canonical, [TRI-6]). With those normalizations in place, signature preservation
is *achievable*: a shrink that does not change the policy's key fields is
accepted, and the result still clusters into the same cluster.

```text
  minimize_representative(cluster, policy):
  ──────────────────────────────────────────────────────────────────────────
  rep    := representative(cluster)        # the content-address-least member (deterministic)
  target := signature(rep, policy)         # the signature to PRESERVE
  cur    := rep
  repeat until no candidate shrinks further (22's SEEDED, content-address-tie-broken order):
    for each removable decision / heal-able fault / shrinkable param in cur:  # 22 §22.8.2
      cand := cur with that element removed/simplified              # still a valid Schedule
      run  := reduce(cand.def, cand.schedule)                      # a full run (05)
      validate(run) by replay oracle + fingerprint                 # 24, [ADV-11], [ADV-31]
      if signature(run, policy) == target:  cur := cand            # ACCEPT — STRENGTHENED predicate
  assert signature(cur, policy) == signature(rep, policy)          # the central invariant ([TRI-9])
  emit cur  — the minimal artifact whose signature equals the original's

  COST: ONE representative minimized per cluster ⇒ O(clusters), not O(findings).
```

Minimization is **per-cluster, one representative** — O(clusters), not
O(findings): triage does not minimize every finding (that would be wasteful and
would produce many minimal artifacts of the same bug), only the cluster's chosen
representative. The representative is chosen deterministically (the
content-address-least member of the cluster), so the choice is reproducible.

- **[TRI-9]** Triage's minimization MUST **extend** the existing minimization pass
  (22 §22.8.2, [ADV-30]) by strengthening its accept predicate from *"the
  candidate still triggers the same violation"* to *"`signature(candidate,
  policy) == signature(original, policy)` under the active `SignaturePolicy`"*. It
  MUST reuse 22's seeded, content-address-tie-broken candidate order ([ADV-31])
  and its per-candidate replay-oracle + fingerprint validation ([ADV-11],
  [ADV-31]); each candidate MUST be a bit-reproducible run ([ADV-28]). On
  completion it MUST assert `signature(minimal, policy) == signature(original,
  policy)` — the **central triage invariant**. A minimization that produces a
  representative whose signature differs from the original's is a defect, never an
  accepted result. *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:*
  §34.4; cross-ref 22 §22.8.2, [ADV-30], [ADV-31].

- **[TRI-12]** Triage MUST minimize **one representative per cluster**, not every
  finding: the per-cluster cost MUST be O(clusters), not O(findings). The
  representative MUST be chosen deterministically (the content-address-least
  member of the cluster, [TRI-11]) so the choice is reproducible, and the minimal
  representative MUST itself be a self-contained, bit-reproducible reproduction
  artifact (22 [ADV-28], §22.8.1). The minimal representative MUST cluster into
  the *same* cluster as the original under the active policy (a direct consequence
  of [TRI-9]). *Gate:* `gate:replay-oracle`, `gate:content-address`. *Spec:*
  §34.4; cross-ref 22 §22.8.1, [ADV-28].

## 34.5 Per-cluster reports

For each cluster, triage emits a **report** that bundles everything an operator
needs to understand and reproduce the failure once, instead of wading through
every member. A report is a pure projection of the cluster's stored artifacts and
the deterministic record; it adds no information not already in the substrate.

### 34.5.1 What a report contains

Each per-cluster report MUST bundle:

- the **cluster id** (the content hash of the signature key, [TRI-10]) and the
  full **signature** (key fields + detail fields, §34.2.1);
- the **member artifact hashes** — the content-addressed references (07 §7) of
  every finding in the cluster, and the count;
- the **minimal representative** — the minimized artifact of §34.4, by content
  reference;
- the **failing property** — for a `PropertyViolation`, the property id, message,
  quantifier, and the expected-vs-observed detail from the violation record (18
  §18.10.1, [ASRT-27]); for a `Divergence`, the **bisected first-diff** — the
  first differing causal entry's `(node, icount, kind)` and the both-sides state
  summary from divergence bisection (24 §5, 19 §19.6.2, [OBS-28]);
- the **minimal reproduction artifact** reference (`(seed, ScenarioDef,
  Schedule)`, 22 §22.8.1, 24 §12) for the representative;
- an **event-log excerpt** — the last-N **causal** entries (19 §19.5) leading up
  to the first-failing point of the representative (a tail of the causal
  subsequence, never observational noise);
- the **causal chain** — the failure's causal cone (19 §19.6.2) rendered as an
  ordered narrative of `(node, icount, kind)` steps, so the operator reads *how
  the failure was reached*, not just *that it failed*;
- the **exact replay command** — the copy-pasteable `crucible replay <minimal>`
  (23 §4, [CLI-10]) that re-runs the minimal representative bit-identically.

```text
  CRUCIBLE TRIAGE CLUSTER 3a7f… (default policy)
    signature   : kind=PropertyViolation  property=no_split_brain/AfterQuiescence
                  first_fail={kind=assertion_state_changed, node=replica#0(canonical)}
                  coverage_class=cc:partition-then-rejoin   icount(report-only)=842_117_903
    members      : 1_204 findings   (artifacts: cas:9d4e…, cas:1a02…, … +1_201 more)
    representative (minimal): cas:2c26b4…   (schedule: 7 decisions, 1 fault — from 318/12)
    failing prop : no_split_brain (AfterQuiescence)
                   expected = one leader at quiescence
                   observed = two leaders (replica#0, replica#2)
    causal chain : node=replica#0 icount=120_400 kind=fault_activated (partition l0)
                   node=replica#2 icount=131_990 kind=state_transition (→ Leader)
                   node=replica#0 icount=140_011 kind=fault_healed (partition l0)
                   node=replica#0 icount=842_117_903 kind=assertion_state_changed (→ Violated)
    log excerpt  : … last 8 causal entries to the violation site …
    reproduce    : crucible replay cas:2c26b4…   (bit-identical, [CLI-10])
```

### 34.5.2 Two renderings, both deterministic, idempotent

A report has **two renderings**: a **machine-readable** content-addressed
form (`json` / `jsonl`) under the canonical serialization (19 §19.4, [OBS-20]),
and a **human-readable** form (`table` / `markdown`). Both render the *same*
report content; the rendering is a pure function of the report, so regenerating a
report is **idempotent** (byte-identical every time) and the machine-readable
form is content-addressable like any artifact. The two renderings mirror the
CLI's `--format` discipline (23 §4, [CLI-11]): the format changes *how* the report
is printed, never *which* content it contains.

The supported deterministic `json`, `jsonl`, `table`, and `markdown` renderings
therefore differ only in encoding and presentation, never in report content.

- **[TRI-13]** Each per-cluster report MUST bundle: the cluster id ([TRI-10]) and
  the full signature (§34.2.1); the member artifact hashes (07 §7) and count; the
  minimal representative by content reference (§34.4); the failing property — for
  a `PropertyViolation`, the id/message/quantifier/detail from the violation
  record (18 §18.10.1, [ASRT-27]); for a `Divergence`, the bisected first-diff
  `(node, icount, kind)` and both-sides summary (24 §5, 19 [OBS-28]); the minimal
  reproduction artifact reference (22 §22.8.1, 24 §12); an event-log **excerpt**
  of the last-N **causal** entries (19 §19.5) to the first-failing point; the
  **causal chain** as an ordered `(node, icount, kind)` narrative of the causal
  cone (19 §19.6.2); and the exact `crucible replay <minimal>` command (23 §4,
  [CLI-10]). Every field MUST be read from the deterministic record, never from a
  re-execution done for reporting. *Gate:* `gate:e2e-determinism`,
  `gate:content-address`. *Spec:* §34.5.1; cross-ref 18 §18.10.1, 24 §5, 19
  §19.6.2.

- **[TRI-14]** Triage MUST emit each report in **two renderings**: a
  **machine-readable** content-addressed `json`/`jsonl` form under the canonical
  serialization (19 §19.4, [OBS-20]), and a **human-readable** `table`/`markdown`
  form. Both MUST render the **same** report content (the rendering MUST NOT change
  which content appears, only how it is printed, mirroring [CLI-11]), MUST be
  deterministic, and report regeneration MUST be **idempotent** — byte-identical
  output for the same report and rendering, on any host. *Gate:*
  `gate:e2e-determinism`, `gate:content-address`. *Spec:* §34.5.2; cross-ref 19
  §19.4, 23 §4, [CLI-11].

## 34.6 The `crucible triage` CLI

Triage is driven by a new `crucible triage <findings>` subcommand. Like every
other CLI subcommand (23 §1, [CLI-1], [CLI-2]) it is a **thin driver**: it holds
no run state, implements no clustering/signature/minimization mechanism of its
own, and decomposes entirely into the triage projection of this file over stored
artifacts. It is fully **offline** — it runs against a stored findings ledger
(§34.7) with no daemon, no scheduler, and no guest boot (except the per-candidate
replays minimization performs, which are re-reductions of recorded schedules,
[TRI-1]).

```text
  crucible triage <FINDINGS> [FLAGS]

  ARGS
    <FINDINGS>   A findings ledger (§34.7): a directory of reproduction artifacts,
                 a content hash of a stored ledger, or one artifact/ledger file path.

  FLAGS (subcommand-local; relevant global flags from 23 §2 also apply)
    --policy <coarse|default|fine|exact>     Signature policy (§34.2.3). Default: default.
    --minimize <none|representative|all>     What to minimize (§34.4). Default: representative.
    --report <dir>                           Write per-cluster reports here.
    --format <jsonl|json|table|markdown>     Report rendering (§34.5.2). Default: jsonl.
    --recompute-signatures                   Recompute signatures and assert byte-equality
                                             with the discovery-time signatures (§34.6).
    --compare <other-triage-result>          Content-diff against another triage result.
```

The driver's pipeline is **cluster → minimize-representative → emit reports**:
it reads the findings ledger, clusters by signature under `--policy` (§34.3),
minimizes one representative per cluster under `--minimize representative`
(§34.4, the default; `none` skips minimization, `all` minimizes every member —
O(findings), opt-in only), and writes per-cluster reports in `--format` to
`--report` (§34.5). Exit codes are **uniform with the rest of the CLI** (23 §15,
[CLI-25]): `0` if triage completed, `1` if any cluster's minimization failed its
signature-preservation assertion ([TRI-9]) or `--recompute-signatures` found a
mismatch, `4` discovery/config, `5` malformed/unresolvable ledger or artifact,
`64` usage.

### 34.6.1 The triage result is a content-addressed artifact

A **triage result** — the set of clusters, signatures, minimal representatives,
and reports under a given `(findings ledger, policy)` — is itself a
content-addressed artifact stored in the `DagStore` (07 §7), keyed by its inputs.
This gives triage three properties for free: **dedup** (the same ledger triaged
twice under the same policy resolves to the same stored result, a cache hit, not
a recompute), **idempotence** ([TRI-8], a re-cluster is a content lookup), and a
**content diff** — `--compare` is a *content diff* of two triage results (e.g.
"this campaign's clusters vs last week's": which clusters are new, which are
gone, which grew), not a re-clustering.

### 34.6.2 Offline-computable and self-checking

Triage MUST be fully computable from stored artifacts (the findings ledger and
the `DagStore`), with no live session and no re-execution beyond minimization's
recorded-schedule replays ([TRI-1], [TRI-2]). The `--recompute-signatures` flag
makes triage **self-checking**: it recomputes each finding's signature from the
recorded run and asserts it is **byte-for-byte identical** to the signature
recorded at discovery time. A mismatch is a determinism defect — a signature that
depends on something it must not (wall-clock, host map order, an observational
entry) — and MUST fail loudly (exit 1), never be smoothed over ([INV-10]).

- **[TRI-15]** Triage MUST be driven by a `crucible triage <findings>` subcommand
  that is a **thin driver** holding no run state and implementing no
  clustering/signature/minimization mechanism of its own (23 [CLI-1], [CLI-2]):
  it MUST decompose entirely into the triage projection of this file over stored
  artifacts. It MUST support `--policy {coarse|default|fine|exact}` (§34.2.3),
  `--minimize {none|representative|all}` (default `representative`, §34.4),
  `--report <dir>`, `--format {jsonl|json|table|markdown}` (§34.5.2),
  `--recompute-signatures` (§34.6.2), and `--compare <other>` (§34.6.1); and MUST
  run the pipeline cluster → minimize-representative → emit-reports. Exit codes
  MUST be uniform with 23 §15 ([CLI-25]). A `crucible triage` subcommand MUST be
  added to the CLI surface of [`23-cli.md`](23-cli.md) (forward-ref §34.9).
  *Gate:* `gate:content-address`, `gate:e2e-determinism`. *Spec:* §34.6; cross-ref
  23 §1, §15, [CLI-1], [CLI-2], [CLI-25].

- **[TRI-16]** A triage result (clusters + signatures + minimal representatives +
  reports under a given `(findings ledger, policy)`) MUST be a **content-addressed
  artifact** stored in the `DagStore` (07 §7), keyed by its inputs, so that the
  same ledger triaged under the same policy **dedups** to the same stored result
  (a cache hit, idempotent re-cluster, [TRI-8]). `--compare <other>` MUST be a
  **content diff** of two triage results (which clusters are added, removed, or
  changed), not a re-clustering. *Gate:* `gate:content-address`. *Spec:* §34.6.1;
  cross-ref 07 §7, [INV-6].

- **[TRI-17]** Triage MUST be fully **offline-computable** from stored artifacts
  with no live session and no re-execution beyond minimization's
  recorded-schedule replays ([TRI-1], [TRI-2]). `--recompute-signatures` MUST
  recompute each finding's signature from the recorded run and assert it is
  **byte-for-byte identical** to the discovery-time signature; a mismatch MUST
  fail loudly (exit 1) as a determinism defect — a signature that depends on
  wall-clock, host map order, or an observational entry — never be smoothed over
  ([INV-10]). *Gate:* `gate:e2e-determinism`. *Spec:* §34.6.2; cross-ref [TRI-3],
  [INV-10].

## 34.7 The findings ledger

Triage's input is a **findings ledger**: the set of discovered findings, each a
self-contained reproduction artifact (22 §22.8.1, 24 §12). The ledger is itself
**content-addressed** and stored in the `DagStore` (07 §7) like any other
artifact — it is just the set of artifacts the campaign retained as
"interesting," exactly the corpus the fuzzer already manages (22 §22.7.2,
[ADV-26]). Triage does not define a new ledger format; it reads the artifacts a
campaign already emits ([ADV-28]) and the corpus a fuzzer already stores
([ADV-26]).

Because the ledger is content-addressed, a finding appearing in two campaigns is
**one entry** (dedup, [INV-6]), and a finding's identity is its reproduction
artifact's content hash — the same identity triage clusters by member hash
(§34.3). The ledger therefore composes cleanly with the temporal graph and the
corpus: triage is a projection *over* the same content-addressed substrate, not a
sidecar database.

- **[TRI-18]** Triage's input findings ledger MUST be a **content-addressed** set
  of self-contained reproduction artifacts (22 §22.8.1, 24 §12) stored in the
  `DagStore` (07 §7): triage MUST NOT define a new ledger or finding format but
  MUST read the artifacts a campaign emits ([ADV-28]) and the corpus a fuzzer
  stores ([ADV-26]). A finding's identity MUST be its reproduction-artifact
  content hash (the member identity of §34.3), so a finding appearing in two
  campaigns is one ledger entry (dedup, [INV-6]). *Gate:* `gate:content-address`.
  *Spec:* §34.7; cross-ref 22 §22.7.2, §22.8.1, [INV-6].

## 34.8 Risks and how triage addresses them

### 34.8.1 Signature stability across minimization (the central invariant)

The single most important risk is that **minimization changes the signature**. If
shrinking a finding moved its signature, then the minimal representative would
fall out of its own cluster, reports would point at artifacts that no longer
match their cluster, and re-triaging after minimization would re-partition
everything. The entire §34.4 design — extending minimization's accept predicate
to *signature equality* rather than *violation equality* ([TRI-9]), backed by the
three normalizations of §34.2.2 (icount report-only, node canonical, slice hash
cone-scoped) — exists to make `signature(minimal) == signature(original)` a
**provable, asserted invariant**. The minimization loop *accepts only* shrinks
that preserve the signature, and asserts the invariant on completion; a violation
is a defect caught by `gate:e2e-determinism`, not a tolerated outcome. This is the
risk the rest of the file is organized around.

### 34.8.2 Over- and under-clustering

Triage can fail in two opposite directions, and the signature design has a knob
for each:

- **Under-clustering** (the same bug splits into many clusters) is caused by
  signatures that are too literal — most often by *not* canonicalizing
  interchangeable entities. The **symmetry-canonical relabeling** of
  `faulting_node` ([TRI-6], 07 §9) is the primary defense: it collapses
  "replica A" and "replica B" failures of the same defect into one cluster. The
  `causal_slice_hash` being **cone-scoped** ([TRI-7]) is the secondary defense:
  it keeps irrelevant out-of-cone schedule differences from splitting a cluster.

- **Over-clustering** (different bugs collapse into one cluster) is caused by
  signatures that are too coarse — most often by a `coverage_class` bucketing that
  is too aggressive. The **coverage bucketing** ([TRI-4], 07 §2) is the tuning
  knob: a finer bucket separates failures that reach the failure point through
  genuinely different code, and the `fine`/`exact` policies (§34.2.3) add the
  `causal_slice_hash` as a key field to separate failures that share a coarse
  class but differ in their causal cone. Because the policy is recorded in the
  result identity ([TRI-8]), an operator who suspects over- or under-clustering
  simply re-triages under a finer or coarser policy and **content-diffs** the
  results (`--compare`, [TRI-16]) — a cheap, deterministic experiment, not a
  guess.

The general rule, mirroring symmetry/partial-order reduction's "explore when in
doubt" ([ADV-19]): the bucketing and canonicalization MUST be **sound** in the
sense that they never merge findings whose *key* fields differ, and the
granularity trade-off is exposed as a policy the operator controls, not baked in.

### 34.8.3 Cost

Triage's cost is dominated by minimization, and minimization is the expensive
part of the substrate (each candidate is a full re-reduction, 22 §22.8.2). The
design bounds this directly: triage minimizes **one representative per cluster**
([TRI-12]), so minimization cost is **O(clusters)**, not O(findings). Clustering
itself is O(findings) but cheap — each finding's signature is *read* from its
recorded run ([TRI-9-pre], §34.2.4), not recomputed by re-execution. The
`--minimize all` mode (O(findings) minimization) exists for forensic use but is
opt-in and never the default ([TRI-15]). The result is that triaging a
thousand-finding campaign with ten root causes minimizes ten representatives, not
a thousand artifacts.

### 34.8.4 Interaction with the content-addressed findings ledger

Triage rides the same content addressing as everything else, which is what keeps
it from becoming a sidecar database that can drift from the run record. Findings
are content-addressed reproduction artifacts ([TRI-18]); the ledger dedups by
content hash ([INV-6]); cluster ids are content hashes of signature keys
([TRI-10]); the triage result is a content-addressed artifact in the `DagStore`
([TRI-16]); and re-triage is a content lookup, not a recompute ([TRI-8]). The
risk this *avoids* is the one that historically made post-hoc failure analysis
unreliable: a separate analysis store that drifts out of sync with the runs it
describes. Triage cannot drift, because it stores nothing the substrate does not
already content-address, and recomputes everything it reports from the recorded
run — verifiably so, via `--recompute-signatures` ([TRI-17]).

## 34.9 Forward reference: the `crucible triage` subcommand in 23

The `crucible triage` subcommand specified here (§34.6) is a **new CLI
subcommand** and MUST be added to the CLI surface of
[`23-cli.md`](23-cli.md): its name added to the subcommand set ([CLI-3]), its
flags and `--help` copy authored as user-facing CLI surface ([CLI-6]), and its
exit codes wired into the uniform mapping (23 §15, [CLI-25]). It is, like the
rest of the CLI, a thin driver holding no run state ([CLI-1], [CLI-2]); this file
owns the triage *projection* and 23 owns the *CLI ergonomics* of exposing it,
exactly as 22 owns exploration policy and 23 owns the `search`/`fuzz` drivers
([CLI-23]).

- **[TRI-19]** The `crucible triage` subcommand ([TRI-15]) MUST be added to the
  `crucible` CLI surface ([`23-cli.md`](23-cli.md)): its name in the subcommand
  set ([CLI-3]), its flags and `--help` copy authored as user-facing CLI surface
  ([CLI-6]), and its exit codes wired into the uniform mapping (23 §15,
  [CLI-25]). The CLI MUST own only the triage *ergonomics*; this file owns the
  triage *projection* (mirroring how 23 owns the `search`/`fuzz` drivers while 22
  owns exploration policy, [CLI-23]). *Gate:* `gate:content-address`. *Spec:*
  §34.9; cross-ref 23 §2, §15, [CLI-3], [CLI-6], [CLI-25].

## 34.10 Summary

```text
WHAT (§34.1): failure triage = a deterministic, OFFLINE, content-addressed
  PROJECTION over the one event log (19) / temporal graph (07) / violation record
  (18) / reproduction artifact (22 §22.8). NO new execution path, NO new run
  state, NO second record. The only execution is minimization's recorded-schedule
  replays ([TRI-1], [TRI-2]).

SIGNATURE (§34.2): a content-addressed tuple from the RECORDED RUN ALONE —
  failure_kind {PropertyViolation, Divergence} · property id+quantifier (18) ·
  first_failing_point {event_kind, faulting_node} · coverage_class (bucketed from
  07 §2 coverage_fingerprint) · optional causal_slice_hash (cone, 19 §19.6.2).
  THREE NORMALIZATIONS: icount REPORT-ONLY ([TRI-5]) · node SYMMETRY-CANONICAL
  ([TRI-6]) · slice hash over the CONE ([TRI-7]).

POLICY (§34.2.3): SignaturePolicy {coarse|default|fine|exact} picks key vs detail
  fields; recorded in the result identity ⇒ idempotent re-cluster ([TRI-8]).

CLUSTER (§34.3): equivalence-class partition by signature key; cluster id =
  content hash of the key; output content-address ordered ([TRI-10], [TRI-11]).

MINIMIZE (§34.4): EXTEND 22's minimization ([ADV-30]) — strengthen accept from
  "same violation" to "same SIGNATURE under the policy" ([TRI-9]); reuse 22's
  seeded order + per-candidate replay-oracle validation; ONE representative per
  cluster ⇒ O(clusters) ([TRI-12]); assert signature(minimal)==signature(orig).

REPORT (§34.5): per cluster — id+signature+member hashes+minimal rep · failing
  property (18) or bisected first-diff (24 §5) · minimal repro artifact · last-N
  causal log excerpt · causal-cone narrative · exact `crucible replay <minimal>`.
  TWO renderings (machine json/jsonl + human table/markdown), both deterministic,
  idempotent ([TRI-13], [TRI-14]).

CLI (§34.6): `crucible triage <findings>` — thin driver, no run state; flags
  --policy/--minimize/--report/--format/--recompute-signatures/--compare; pipeline
  cluster→minimize-representative→emit; exit codes uniform with 23 ([TRI-15]).
  Result is a content-addressed DagStore artifact (dedup; --compare = content diff,
  [TRI-16]); fully offline + self-checking via --recompute-signatures ([TRI-17]).

LEDGER (§34.7): content-addressed set of reproduction artifacts in the DagStore;
  no new format; finding identity = artifact content hash ([TRI-18]).

RISKS (§34.8): signature stability across minimization (THE invariant, §34.8.1) ·
  over/under-clustering (coverage bucketing + symmetry canon + causal-slice knobs,
  §34.8.2) · cost (O(clusters), §34.8.3) · ledger interaction (no drift, §34.8.4).

FORWARD-REF (§34.9): `crucible triage` is added to 23's CLI surface ([TRI-19]).
```

The shape of this file is the shape of the guarantee: triage adds *nothing* to
the run. It reads the same content-addressed substrate every other Crucible
feature reads, projects a stable root-cause signature out of each recorded run,
groups by it, shrinks one representative per group while *preserving* that
signature, and reports each group once — all deterministically, all offline, all
recomputable byte-for-byte from what was already stored.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is failure triage, tracked by [PLAN-3]. They are
> sequenced strictly after the determinism, event-log, assertion, reproduction,
> and minimization foundations they depend on ([ADV-30], [ASRT-27], [OBS-21],
> [HARN-27], [PLAN-4]).

- [x] **T-TRI-1** Implement the `FailureSignature` tuple computed from the
  recorded run alone (ScenarioDef + Schedule + causal subsequence) with the
  `failure_kind`/property/`first_failing_point`/`coverage_class`/`causal_slice_hash`
  fields read from the violation record (18) and the causal projection / bisection
  (19, 24), never from re-execution. — satisfies [TRI-1], [TRI-2], [TRI-3], [TRI-4]; spec §34.2,
  §34.2.1, §34.2.4.
  Completed by `checks.crucible.phase6.failureSignature`: the model now exposes
  `FailureSignature`, `FailureRecordedEventLog`, `FailureKind`,
  `FailurePropertyKey`, `FailureFirstFailingPoint`, `FailureCoverageClass`, and
  `FailurePropertyViolationRecord`; property-violation signatures bind and read
  the property id, quantifier, event kind, and node from the deterministic
  `HostAssertionViolation` record, while divergence signatures bind and read the event
  kind and node from a bisection point that must exist in the checked recorded
  causal projection. The checked event-log wrapper binds the projection metadata
  and recorded coverage fingerprint to the same reproduction artifact, derives
  the coverage class from that metadata-bound fingerprint, and omits discovery
  path and finding fingerprint so discovery campaign state cannot perturb the
  signature.
- [x] **T-TRI-2** Implement the three critical normalizations — absolute icount
  report-only, `faulting_node` under the symmetry-canonical relabeling (07 §9),
  and `causal_slice_hash` over the cone (19 §19.6.2) — and prove each prevents its
  failure mode (signature instability under minimization, under-clustering across
  interchangeable entities, out-of-cone shrink sensitivity). — satisfies [TRI-5],
  [TRI-6], [TRI-7]; spec §34.2.2.
  Completed by `checks.crucible.phase6.failureNormalization`: `FailureSignature`
  now carries `at_icount_report_only` in report material while excluding it from
  the default content hash, canonicalizes `faulting_node` through
  `FailureSignatureNormalization` / `FailureSymmetryCanonicalizer` over
  `SymmetryReductionClasses`, and computes `causal_slice_hash` from the
  normalized causal cone ending at the validated first-failing causal entry. The
  gate proves absolute icount shifts do not perturb the key, symmetric replica
  nodes collapse to one canonical faulting node, and trailing out-of-cone causal
  entries do not change the slice hash.
- [x] **T-TRI-3** Implement the closed, versioned `SignaturePolicy`
  (coarse/default/fine/exact) selecting key vs detail fields and the
  `coverage_class` bucketing, recorded in the triage result identity for
  idempotent re-cluster. — satisfies [TRI-8]; spec §34.2.3.
  Completed by `checks.crucible.phase6.signaturePolicy`: the model now exposes a
  closed `SignaturePolicyLevel` enum and versioned `SignaturePolicy` projection
  for coarse/default/fine/exact keys, with the fixed coverage bucketing algorithm
  recorded in policy material. `FailureSignatureKey` projects only the active
  key fields, `exact` adds absolute icount and full causal-cone material while
  disallowing minimize-merge, and `FailureTriageResultIdentity` includes the
  findings ledger plus policy so re-clustering the same ledger under the same
  policy is idempotent.
- [x] **T-TRI-4** Implement deterministic clustering: equivalence-class partition
  by signature key, cluster id = content hash of the key, output and intra-cluster
  members content-address ordered with no host-nondeterminism on an
  ordering-significant path. — satisfies [TRI-10], [TRI-11]; spec §34.3.
  Completed by `checks.crucible.phase6.failureClustering`: the model now exposes
  `FailureClusterFinding`, `FailureClusterMember`, `FailureCluster`, and
  `FailureClusteringResult`. The clustering fold projects each recorded
  signature through the active `SignaturePolicy`, uses the signature-key content
  hash as the cluster id, builds clusters and member sets with content-address
  ordered `BTreeMap`s, rejects conflicting duplicate artifact evidence, and emits
  canonical clustering material with clusters ordered by id and members ordered
  by reproduction-artifact hash.
- [x] **T-TRI-5** Implement signature-preserving minimization by extending 22's
  pass ([ADV-30]) — strengthen the accept predicate to signature equality under
  the active policy, reuse the seeded order + per-candidate replay-oracle
  validation, minimize one representative per cluster (O(clusters)), and assert
  `signature(minimal)==signature(original)`. — satisfies [TRI-9], [TRI-12]; spec
  §34.4; cross-ref 22 §22.8.2.
  Completed by `checks.crucible.phase6.signaturePreservingMinimization`: the
  model now exposes `FailureSignaturePreservingMinimizationRun` and
  `FailureSignaturePreservingMinimizationResult`. `FailureClusteringResult`
  minimizes only each cluster's content-address-least representative via the
  existing `FindingReproductionArtifact::minimize` pass, supplies an oracle that
  accepts only candidates whose active-policy `FailureSignatureKey` equals the
  original representative's key, preserves the seeded candidate order and
  replay-validated candidate evidence from 22, and records both target and
  minimized signature keys in canonical result material.
- [x] **T-TRI-6** Implement per-cluster reports (cluster id + signature + member
  hashes + minimal representative + failing property/bisected first-diff + minimal
  repro artifact + last-N causal log excerpt + causal-cone narrative + exact
  `crucible replay <minimal>`) in two deterministic, idempotent renderings
  (machine json/jsonl + human table/markdown). — satisfies [TRI-13], [TRI-14];
  spec §34.5.
  Completed by `checks.crucible.phase6.perClusterReports`: the model now exposes
  `FailureClusterReport`, `FailureClusterReportSet`,
  `FailureClusterReportFailure`, `FailureClusterReportDivergence`, and
  `FailureClusterReportFormat`. A report constructor binds the cluster id,
  active-policy signature, signature-preserving minimization run, minimized
  artifact event-log evidence, property violation or bisected first-diff detail,
  minimal `(seed, ScenarioDef, Schedule)` reference, last-N causal excerpt,
  causal-cone narrative, and exact `crucible replay blake3:<minimal>` command
  into one content-addressed artifact. Report construction recomputes the full
  minimized representative signature from checked evidence, not caller-provided
  signature detail, and rejects minimization evidence that does not use the
  cluster's content-address-least representative. The same canonical report
  material drives deterministic `json`, `jsonl`, `table`, and `markdown`
  renderings, and report sets are emitted in cluster-id order.
- [x] **T-TRI-7** Implement the `crucible triage <findings>` thin-driver
  subcommand (flags --policy/--minimize/--report/--format/--recompute-signatures/
  --compare; pipeline cluster→minimize-representative→emit; exit codes uniform
  with 23), the content-addressed triage result in the DagStore (dedup; --compare
  content diff), and the offline self-check that
  recomputed signatures equal discovery-time signatures byte-for-byte. — satisfies
  [TRI-15], [TRI-16],
  [TRI-17], [TRI-18]; spec §34.6, §34.7.
  Completed by `checks.crucible.phase6.triageThinDriver`: the model now exposes
  `FailureFindingsLedger`, `FailureTriageSignatureSelfCheck`,
  `FailureTriageResult`, and `FailureTriageResultDiff`. Findings ledgers dedup
  reproduction artifacts by content hash, self-check records retain per-finding
  discovery/recomputed signature byte hashes, and triage results re-bind
  clusters, signature-preserving minimization runs, and per-cluster reports to
  the same policy, representative, member set, signature key, and minimal
  artifact before storing deterministic bytes in the `DagStore`. Repeated stores
  report cache hits, the stored result hash is the `DagStore` key, and result
  comparison is a content diff over stored report hashes. The CLI `triage`
  command parses the policy, minimization, report, format, recompute, and
  compare controls, rejects daemon-backed use, opens a local `DagStore`, loads
  path or stored ledgers, executes the cluster→minimize-representative→emit→store
  runner for ledgers whose discovery-time signature evidence is representable,
  writes the report rendering, and preserves the uniform exit-code path for
  recompute-signature mismatches; bare non-empty artifact-only ledgers are
  rejected rather than assigned fabricated signatures.
- [x] **T-TRI-8** Add the `crucible triage` subcommand to the CLI surface of
  [`23-cli.md`](23-cli.md): subcommand-set entry, user-facing `--help` copy, and
  the uniform exit-code mapping. — satisfies [TRI-19]; spec §34.9; cross-ref 23
  §2, §15.
  Completed by `checks.crucible.phase6.triageCliSurface`: RFC-23 now names
  `triage` in the closed subcommand set and owns the CLI ergonomics for
  `crucible triage <FINDINGS>`, including the `--policy`, `--minimize`,
  `--report`, global `--format`, `--recompute-signatures`, and `--compare`
  surface plus the uniform `0`/`1`/`4`/`5`/`64` exit-code mapping, including
  parse-time usage errors. The CLI Rust regression renders the Clap top-level and
  `triage` help output, checks the required subcommand name, user-facing flag
  value sets, Markdown report format, and triage-specific exit-code contract; the
  phase gate verifies that regression is present and the surface is wired.

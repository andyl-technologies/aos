# 15 — Segmented attempt event log and bounded evaluation

Campaign attempts are expected to run for minutes to hours of virtual time. The
attempt event log grows with every quantum, so no consumer may hold the whole
log in memory or encode it as one object. This chapter defines how an executor
retains, evaluates, publishes, and reads back an attempt log whose length is
bounded only by an operational storage limit.

RFC-0010 already requires the log to be a sequence of content-addressed
segments shared by reference ([OBS-17], [OBS-18], [OBS-19]) and assertion
checking to be a fold that yields identical verdicts live and offline
([OBS-26]). This chapter applies those requirements to the campaign attempt
pipeline, replaces the whole-log retention bound formerly stated in
[`04a-coordinator-executor-contract.md`](04a-coordinator-executor-contract.md),
and replaces the single-leaf measurement replay evidence formerly stated in
[`08-observability-measurement-debugging.md`](08-observability-measurement-debugging.md).

## 15.1 Scope and motivation

Before this chapter, a fresh packaged attempt kept at least three complete
in-memory copies of its log: the scheduler's condition prefix, the observer's
execution-evidence snapshot, and the driver's retained log. Sealing added
several transient copies, and the measurement replay evidence embedded every
entry in one canonical CBOR leaf. Each copy enforced 1,000,000 entries and
64 MiB of canonical identity material. A five-VM network product reached that
bound after about seven seconds of virtual time.

Raising the bound does not change the shape of the problem: log growth is
linear in virtual time, so every whole-log bound eventually ends the attempt.
The design below makes resident memory and per-quantum work independent of the
elapsed attempt length, and moves the remaining bound to storage.

## 15.2 Attempt segments

An attempt segment is one encoded binary event-log segment
([OBS-20]) covering a contiguous, dense range of scheduler entries. Segments
form an evidence chain:

```text
chain_0 = H("crucible.attempt.event-log.chain.v1", "empty")
chain_i = H("crucible.attempt.event-log.chain.v1",
            chain_(i-1), segment_i content ID,
            first sequence, entry count, encoded bytes)
```

The chain hash after the last segment, together with the total entry count,
identifies the complete attempt log. A reader that has authenticated segments
`1..i` has authenticated the dense prefix they cover without decoding any later
segment.

- **[CCOMP-25]** The executor MUST retain an attempt's event log as an ordered
  sequence of sealed attempt segments followed by one open tail. Sealed
  segments MUST be written to quota-accounted attempt storage when sealed and
  MUST NOT remain resident. The executor's resident memory for the log MUST be
  bounded by the open tail, the segment references, and the bounded evaluation
  state of [§15.4](#154-bounded-evaluation-state), independent of the number of
  sealed segments.
- **[CCOMP-26]** The executor MUST seal the open tail before an append would
  make its encoding exceed 8 MiB, at every checkpoint or fork offset, and at
  the attempt stop. A sealed segment MUST NOT exceed 16 MiB encoded, and a
  single entry whose encoding exceeds 8 MiB MUST fail the attempt closed.
  Seal points MUST be a pure function of the attempt's entry sequence and its
  checkpoint offsets, so the same execution path yields the same segments.
- **[CCOMP-27]** Determinism, replay, and measurement comparisons MUST compare
  entries, never segment boundaries or chain hashes. Two executions whose
  entries are identical but whose segment boundaries differ are equivalent.

## 15.3 Retention bound and storage

The whole-log bound of 1,000,000 entries and 64 MiB of canonical identity
material is removed. Attempt length is bounded by three independent limits:
the campaign policy's virtual-time deadline (the only modeled horizon, see
[`01-campaign-data-model.md`](01-campaign-data-model.md)), the executor's
quantum allowance, and the event-log storage limit below.

```toml,illustrative
# Executor deployment configuration.
[attempt_storage]
maximum_event_log_bytes = "4GiB"
```

- **[CCOMP-28]** The total encoded size of an attempt's sealed segments and
  open tail MUST be bounded by the executor deployment's
  `maximum_event_log_bytes`, defaulting to 4 GiB. The limit is operational: it
  MUST NOT enter production identity, attempt resource identity, or campaign
  policy. Exhausting it MUST end the attempt as an operational limit failure,
  never as a policy timeout, a property verdict, or a finding.
- **[CCOMP-29]** Sealed segments of an unpublished attempt MUST be removed with
  the attempt's storage. Publication MUST store each segment as its own
  content-addressed trace leaf before publishing any manifest that references
  it, and MUST fail closed when a referenced segment is absent.

The packaged executor's attempt storage is an executor-owned namespace under
its run-state root. Every attempt log, both the modeled driver's and the
observer's copy, seals into its own directory there, removed when the last
log, evidence bundle, or prepared result that reads it is dropped. The
namespace is retired at daemon startup, before any attempt runs. A prepared
result names its segments by identity, and its prepared-result journal keeps
synchronized copies of exactly those segments, so publication after a restart
never depends on the retired namespace:

```text
<run-state>/campaign-attempt-event-logs/
  attempt-<16 hex digits>/<64 hex digits>.segment
<run-state>/campaign-prepared-results/<journal>/segments/<64 hex digits>.segment
```

## 15.4 Bounded evaluation state

The condition prefix seen by triggers and assertions becomes accumulated
state plus a tail:

| Component | Retained form |
| --- | --- |
| Latest firing per event, timer fires, black-box observation kinds, last black-box observation | Existing folds |
| Entry count and density | Counter and next expected sequence |
| Current-point observable events | Tail since the evaluation point last advanced |
| Coverage points | One seen bit per declared `(node, point)` |
| Console patterns | One automaton state per declared `(node, pattern)` ([§15.6](#156-console-expression-matcher)) |
| Named host predicates | One accumulator state per declared leaf ([§15.5](#155-named-predicate-accumulators)) |
| Temporal operators, latches, `eventually` obligations | Existing evaluator checkpoint |
| Prefix offsets | Offsets within the current observation interval and the terminal offset |
| Production fault-runtime referenced events | Emitted count, cumulative byte charge, and history chain digest, plus the events a live device subscription can still use ([CMEAS-26]) |

The prefix is built with a declaration catalog derived from the scenario so it
can maintain per-declaration state. Entries leave the tail when every consumer
has evaluated past them; triggers and assertions observe at different points
within one quantum, so the tail is held until the slower consumer advances.

- **[CMEAS-15]** Trigger and assertion evaluation MUST be a fold whose state
  is bounded by the scenario's declarations and one observation interval,
  independent of the attempt length. Evaluating a deadline inside an
  observation interval MUST use the fold snapshot taken at the interval's
  start plus the interval's tail, not a rebuilt prefix.
- **[CMEAS-16]** Scheduler checkpoints MUST carry the bounded fold state and
  the attempt log's chain position instead of the retained entries. Restore
  MUST authenticate the fold state against the checkpoint identity and MUST NOT
  require the complete entry sequence.

The production fault runtime emits a referenced signal event whenever an
exported event named by a storage recovery contract fires. Block recovery
releases a retained completion with the earliest such event strictly after its
subscription, and 9p visibility latches an event-released update the same way,
so a later event of the same signal cannot change either outcome. Each emission
is charged once against the cumulative `event_records` and `event_log_bytes`
budgets of RFC-0014 §13.7 and folded into a chain digest. Every block and 9p
coordinator is a registered consumer that reports its live subscriptions after
each service step, and the runtime retires an event once no reported
subscription, active persistent recovery action, or action that could still be
installed at the newest emitted tick can use it. A consumer whose live
subscription may have lost its releasing event fails closed.

- **[CMEAS-26]** The production fault-runtime continuation MUST retain a
  referenced signal event only while a registered consumer's live subscription,
  an active persistent storage action, or the newest emitted tick can still
  select it, and MUST charge each emission once against cumulative counters
  rather than rescan the emitted history (CPERF-10). Its checkpoint MUST carry
  the emitted count, cumulative byte charge, and history chain digest in place
  of the complete history, and restore MUST NOT require the complete history.

## 15.5 Named predicate accumulators

A named host predicate is a pure accumulator. It declares its initial state,
folds each observed batch into that state, and answers its leaf from the state
alone. The evaluator owns, checkpoints, and replays the state.

```rust,illustrative
pub trait HostAssertionPredicate {
    /// Accumulator state; its canonical CBOR goes into the evaluator checkpoint.
    type State: Serialize + DeserializeOwned;

    fn initial(&self, leaf: NamedLeaf<'_>) -> Self::State;

    /// Folds the observations of one scheduler entry.
    fn step(&self, leaf: NamedLeaf<'_>, state: &Self::State, batch: &ObservedBatch<'_>)
        -> Result<Self::State, NamedPredicateError>;

    fn leaf_is_true(&self, leaf: NamedLeaf<'_>, state: &Self::State) -> bool;
}
```

`ObservedBatch` exposes one scheduler entry's evaluation point and the
observable events and ordering facts that entry recorded. Raw entries, RNG
draws, and host state stay outside it, as they stay outside `ObservedState`.

The evaluator folds exactly one batch per scheduler entry, whichever prefixes
it observes. A live run that observes once per quantum and an offline check
that observes every prefix therefore fold the same batches. An `eventually`
deadline has no entry: its leaves are answered from the folded state stepped
once more with an empty batch at the deadline point, and that step is
discarded. A memoryless predicate, whose leaf depends only on the latest
batch, is the special case whose state is its last answer.

- **[CMEAS-17]** A named host predicate MUST be a pure function of its
  declared leaf, its previous accumulator state, and the current observed
  batch. Its canonical state MUST NOT exceed 64 KiB per leaf; a larger state
  MUST fail evaluation closed. The evaluator MUST include every accumulator
  state in its checkpoint, and live and offline folds MUST produce identical
  states and verdicts. Predicates MUST NOT receive the complete history. The
  evaluator MUST fold every declared leaf once per scheduler entry, in log
  order, independent of where evaluation observes the log; a prefix that does
  not continue the folded entries MUST fail evaluation closed.

## 15.6 Console expression matcher

`console_match` is evaluated by a streaming automaton compiled once per
pattern. The automaton state after consuming a node's console bytes is the
complete summary of everything the pattern can still depend on, so evaluation
needs no stored console history and no lookback window.

**Semantics.** `console_match(node, pattern)` is true at an evaluation point
exactly when some match of `pattern` ends at a byte the node appended at that
point. Every match end counts, including overlapping matches, and a match may
begin arbitrarily far back in the stream. Whether a match ends at a byte
depends only on the stream up to that byte, so the result does not depend on
how bytes are divided among evaluation points. `^` and `\A` denote the start
of the node's console stream and `(?m:^)` the start of a line. A whole-line
match is written with its terminator, for example `(?m:^)READY\r?\n`, and
holds when the line's newline arrives.

Leftmost-first semantics are not used: whether a leftmost-first match has
ended can depend on bytes that have not arrived yet, so it cannot be decided
at an evaluation point.

**Bounds.** Validation compiles every declared pattern to a fully determinized,
unanchored byte automaton.

- **[CMEAS-18]** Scenario validation MUST compile each console pattern into a
  deterministic byte automaton and MUST reject a pattern whose automaton
  exceeds 1 MiB, whose determinization exceeds the fixed construction bound,
  that matches the empty string or nothing, or that uses a construct decided
  by bytes after the match ends: an end anchor (`$`, `(?m:$)`, `\z`), a
  CRLF-aware line anchor, or a word boundary. The scenario's console automata
  MUST NOT exceed 16 MiB in total. Evaluation MUST NOT recompile a pattern or
  rescan earlier console bytes.
- **[CMEAS-19]** The console matcher state MUST be one automaton state per
  declared `(node, pattern)`, checkpointed as the automaton's content hash and
  state index. Restore MUST rebuild the automaton from the pattern, MUST verify
  its content hash, and MUST fail closed on a mismatch.

**Declaration.** A matcher exists before the first byte it could match, so
no declaration ever needs console history. The assertion evaluator declares a
matcher for every `console_match` leaf in its properties when it is built,
folds those matchers once per scheduler entry alongside its named-leaf states
([§15.5](#155-named-predicate-accumulators)), and carries them in its checkpoint;
property matchers do not depend on what the observed prefix declares. A
scheduler declares the matchers its trigger graph evaluates at admission. A
`console_match` leaf evaluated without a declared matcher fails closed with a
typed error; it is never answered by rescanning console bytes.

## 15.7 Measurement replay evidence

`crucible.executor.measurement-replay-evidence` version 3 replaces the
single-leaf version 2 body. The leaf is a manifest:

```text
MeasurementReplayEvidence v3
  scenario definition ID
  configuration ID
  measurement-definition hash
  terminal ready / frontier / per-node icount / quiescence state
  stop evidence
  entry count
  final chain hash
  segments: ordered [(segment content ID, first sequence, entry count, encoded bytes)]
```

Each segment is a separate trace leaf referenced as an evidence child.
Measurement derivation is a single forward pass: guest normalization and model
projection emit each entry's samples, and window evaluation folds them into
per-metric aggregates as the entry is replayed ([CMEAS-23]). No sample, sample
index, or per-sample evidence survives its entry.

- **[CMEAS-20]** Measurement replay evidence MUST reference the attempt log as
  ordered segment leaves and MUST NOT embed entries. Verification MUST fetch
  and authenticate segments in order against the chain, MUST fail closed on a
  missing, reordered, substituted, or non-dense segment, and MUST rederive and
  exact-compare evaluations in one forward pass whose state is bounded by the
  declared measurements ([CMEAS-23]).
- **[CMEAS-21]** The seal-time assertion check MUST consume segments in order
  with lookahead of at most one atomic evaluation batch and MUST produce the
  same verdicts as the live fold ([OBS-26]). The reproduction trace hash MUST
  be computed by streaming the same canonical trace bytes from the segments.

## 15.8 Readers, findings, and resume

Finding production replay captures, triage findings evidence, CLI
explanation, campaign objective verification, observation-stop verification, remote observation resume, hot-fork
materialization, and the campaign trace protocol all consume the attempt log.
Each reads segments by reference.

Published evidence is read through the repository: a measurement set owns
its replay leaf and every segment the leaf references, so an
ownership-checked read of the set's evidence fetches each segment, and the
campaign trace protocol serves one segment per request. A few carriers have
no repository: the lifecycle API's resume request, a savepoint handle, and a
guarded run's result after its private repository is released. They carry an
evidence bundle, the leaf followed by its segments in manifest order, bounded
by the carrier's own message limit. A bundle is a transport form; it never
enters production identity, and decoding it requires exactly the referenced
segments. The resume request is read as it arrives rather than collected:
each field is checked against its own bound before its bytes are accepted
and is decoded straight into place, so the request's message limit bounds
its decoded fields and never a buffered copy of the request.

A campaign replay closure, the choice records that authenticate a schedule's
selections, grows with the run in the same way and follows the same rule. Its
version 2 encoding is a root followed by frames of at most 64 MiB. The root
names every frame by length and digest. Entry frames list one entry per
covered selection decision, in schedule order, naming the selection by
identity and its domain, declaration, and opportunity by record ordinal.
Record frames hold each distinct record once, so a domain shared by many
selections is stored once. An exact checkpoint keeps the root and each frame
as separate children, and a finding capture keeps them as separate leaves; a
loader reads only the root, and validation reads frames one at a time as it
walks the schedule. Selections a raw checkpoint did not discover resolve from
the campaign repository one at a time. A carrier without a repository sends
a closure bundle, the root followed by its frames, as a sequence of separate
elements.

A finding production replay capture is a version 6 exact manifest whose
children are trace leaves: the model reproduction, the campaign replay
closure root and each of its frames, each guest asset and lifecycle object,
and, for each execution side, the attempt-log segments and any
resolved-effect trace segments ([§15.10](#1510-resolved-effect-trace)) in
manifest order. The manifest body carries each side's log manifest and trace
manifest, so a capture references both streams exactly as it references the
log, and neither has a whole-stream bound in the capture. Decoding requires
every segment child of its declared length, rebuilds each side manifest from
its segment references, and refuses a manifest whose recorded totals or chain
differ from the ones those references derive.
A side's recorded segments are referenced as sealed; only the replay prefix
before a resumed recording and the closing tail are sealed as new segments.
Selecting the side that explains a divergence streams both side logs to the
first causal mismatch. The four roles of one finding share equal leaves, and
each distinct leaf is charged once to one of two per-finding allowances:
log segments, trace segments, and replay-closure frames to the run-length
allowance and every other leaf, with the manifests, to the static allowance.
A role that would exceed either allowance is recorded as incomplete, never
truncated.

- **[CMEAS-22]** A reader MUST NOT materialize a complete attempt log. Every
  service response that carries log content MUST carry at most one segment and
  remain within the ordinary 64 MiB component-message bound. Digests, density
  checks, replay comparisons, and projections MUST stream segments in order.
- **[CMEAS-25]** A replay closure bundle MUST carry its root and every frame
  as separate elements, each within the ordinary 64 MiB component-message
  bound, mirroring [CMEAS-22]'s one-segment-per-response rule. Only a carrier
  that is one unary message, such as the resume request, bounds the sum by its
  own message limit, and a file carrier such as a savepoint handle may hold the
  bundle in one buffer. A loader MUST NOT read closure frames before
  validation needs them, and decoding MUST reject a frame whose length or
  digest differs from the root or a closure that is not canonically encoded.
- **[CMEAS-36]** The resume request carrier MUST parse the request as the
  transport delivers it and MUST NOT collect the request body whole. Before
  it accepts a field's bytes, it MUST check them against that field's bound.
  Each closure frame and observation payload is checked against its declared
  size, and that size is checked against the closure or observation limit
  before any of its hex is decoded. The scenario, schedule, and checkpoint
  share one model allowance. Each payload MUST be decoded directly into its
  field, and the payload identities MUST be hashed without concatenating the
  payloads. Every other unary control request MUST be collected under a fixed
  per-route bound.
- **[CMEAS-24]** Finding evidence ledgers MUST reference every captured
  service exchange by content address and MUST be authenticated as a fold over
  findings and, within a finding, over occurrences. No writer, loader, or
  verifier may materialize the occurrence proofs of a complete finding or
  ledger; at most one triage replay is reassembled at a time.
- **[CMEAS-27]** Failure-triage replay evidence MUST reference each replayed
  attempt log by its manifest, and a campaign triage record MUST name every
  referenced segment, in payload order, as an owned trace leaf. Neither MAY
  embed log entries or recording frames. Decoding MUST authenticate every
  segment against its manifest and fail closed on a missing, substituted, or
  unnamed segment. Signature construction, coverage folding, and
  paired-divergence comparison MUST stream segments in order.
The CLI's live QEMU fuzz corpus folds each accepted attempt log, segment by
segment, into a coverage set that keeps every distinct basic block or named
marker once, with the same fingerprint as the attempt's coverage projection.
Corpus schema 2 stores that set, the reproduction artifact, and the replay
closure as immutable objects when a candidate is admitted. Opening a corpus
authenticates the entries one at a time and keeps a fixed handle per entry:
its descriptor, artifact and scenario-form identities, coverage fingerprint
and identity set, and selection inputs. Only the entry chosen as a parent has
its artifact and closure read back.

- **[CMEAS-31]** The live fuzz corpus MUST retain coverage as the distinct
  observations of each entry, never as one record per coverage hit, and MUST
  keep only a handle per entry resident: reproduction artifacts and replay
  closures MUST stay in the corpus store and be read only for the selected
  parent. Opening a corpus MUST authenticate entries one at a time, and
  coverage guidance MUST be computed from fingerprints with the same index
  rule as guidance computed from complete feedback.
- **[CCOMP-30]** Resume from a checkpoint MUST continue from the checkpoint's
  chain position and bounded fold state. Resume proofs MUST compare the
  checkpoint's chain position, not a retained entry vector.

## 15.9 Per-quantum work

Several per-quantum consumers formerly rescanned the retained log: replay
target matching, network-fault discovery, guest-marker assertion observation,
and console matching. With a bounded log those rescans become the dominant
cost. The same growth appears outside the log wherever per-quantum work reads
run history: rehashing a configuration's whole schedule for its identity,
decoding every recorded selection for a stop check, deep-copying scheduler
state whose ledgers grow with the run, and re-validating every emitted fault
event.

- **[CPERF-10]** All per-quantum host work MUST be proportional to the work
  appended in that quantum. This covers event-log consumers, scheduler
  staging and rollback copies, schedule and configuration identity, stop
  checks, imported I/O inventory, and fault accounting. State that grows with
  the run MAY be read per quantum only through structural sharing, a sealed
  or memoized form, or an index maintained on append. Resident executor
  memory and per-quantum host time MUST NOT grow with elapsed virtual time.
  The performance gate runs a long-horizon attempt that includes a long phase
  after a deep selected branch point, and fails when either trend exceeds its
  noise allowance.

The imported I/O delivery ledger meets CPERF-10 by pruning. A new physical
completion never precedes its node's authenticated stopped tick, so a
published delivery below that tick can never be named again, and the next
import drops it. The stopped tick is therefore a per-node retired-delivery
floor. It never regresses: the scheduler refuses an inventory observed below
it, so a pruned key cannot return as a fresh delivery. The retained window
holds unpublished deliveries, which are bounded by queue depth, and
deliveries published since the last import. Staging copies share the
published part through a reference count, so copying a scheduler does not
copy run history.

## 15.10 Resolved-effect trace

The resolved-effect trace of RFC-0014 section 5.1 holds one work item per
evaluated scheduler boundary or fault opportunity, so it grows with virtual
time exactly as the attempt log does. The fault runtime, the campaign network
effect log, the candidate observation, the executor's prepared result, and the
daemon's attempt evidence formerly each held the complete trace as one
canonical value under a 64 MiB bound, and the fault runtime checkpoint embedded
it whole. The trace now uses the segment scheme of
[§15.2](#152-attempt-segments) with its own object schemas:

```text
segment   ContentId(trace, schema 1), at most 16 MiB:
  canonical CBOR { schema: 1, first_item: u64,
                   work_items: [ResolvedReplayWorkItem, ...] }   // dense, nonempty

manifest  ContentId(trace, schema 4), at most 1 MiB:
  "crucible.resolved-effect-trace.v4\0" ++ canonical CBOR {
    mode, work_items: u64, records: u64, chain: ContentHash,
    segments: [{ id, first_item, item_count, records, encoded_bytes }, ...] }

chain_0 = H("crucible.fault.resolved-effect-trace.chain.v1", "empty")
chain_i = H(domain, chain_(i-1) | segment id | first item | item count
                    | record count | encoded bytes)

bundle    "crucible.resolved-effect-trace-bundle.v1\0"
          u32 manifest length, manifest, u32 segment count,
          per segment in manifest order: u32 length, segment
```

A segment carries no replay mode, so one sealed segment serves recomputed and
locked replay of the same execution. A bundle is the transport form of
[§15.8](#158-readers-findings-and-resume) for carriers without a segment
store: a saved run artifact and a lifecycle query assembled by a client. It
never enters production identity. A finding production replay capture is not
such a carrier: it names each side's trace by its manifest and publishes the
trace segments as its own children, so a capture holds no whole-trace buffer
and admits a trace of any length the attempt could record.

- **[CCOMP-31]** The fault runtime and the campaign network effect log MUST
  retain each resolved-effect trace as sealed trace segments followed by one
  open tail. A writer MUST seal before an append would make the tail's
  encoding exceed 8 MiB and MUST NOT seal for any other reason, so seal points
  are a pure function of the work-item sequence and a writer restored from a
  checkpoint seals where the uninterrupted writer would ([CCOMP-21]). A
  checkpoint MUST carry the trace position (sealed segment references, chain,
  running work-item and record counters, and the open tail) and never a sealed
  work item; an exact checkpoint closure retains every sealed segment its
  fault continuation references as a closure object. Observations retain the
  manifest and every segment as content children, prepared results and their
  journals name segments by identity, and every reader, comparison, and
  replay cursor decodes one segment at a time.

Running counters replace the former per-item and per-record collection
bounds: the authored `thin_replay_events` and `resolved_effect_records`
limits apply to the counters, and the fat checkpoint bound applies to the
encoded position including its open tail. An exported trace merges the
signal runtime's trace and the campaign network effect log by scheduler
coordinate and same-coordinate sequence, signal work first on ties, and a
replay partitions a supplied trace back into those two owners while
streaming.

An executor attempt seals its trace segments into their own directory in the
executor's attempt storage, beside the attempt log, and each distinct segment
is charged against the deployment's `maximum_event_log_bytes`, the
operational bound every retained run-length stream of the attempt observes.
Exceeding it is an operational refusal, never modeled evidence.

## 15.11 Segmented reproduction schedules

A reproduction schedule holds one decision per recorded delivery order,
application random draw, and preemption, so it grows with virtual time like
the attempt log. The self-contained reproduction transport embedded the whole
schedule as one blob, and the campaign reproduction record embedded that
transport under a 32 MiB payload bound, so a long run could not be retained as
a finding. The schedule now uses the segment scheme of
[§15.2](#152-attempt-segments) with its own schemas:

```text
segment   ContentId(trace, schema 2), at most 16 MiB:
  "crucible.schedule-segment.v2\0" u64 first_decision, u64 decision_count,
  decision_count compact decisions                    // dense, nonempty

manifest  at most 1 MiB:
  "crucible.schedule-manifest.v1\0" schedule ContentHash, u64 decisions,
  chain, u64 count, per segment: segment digest, u64 first_decision,
                                 u64 decision_count, u64 encoded_bytes

chain_0 = H("crucible.schedule.segment-chain.v1", "empty")
chain_i = H(domain, chain_(i-1) | segment digest | first decision
                    | decision count | encoded bytes)

schedule  "crucible.schedule.v6\0" blob manifest, per segment in manifest
          order: blob segment                          // transport form

stored    "crucible.reproduction-artifact-manifest.v1\0"
          blob scenario-def-form, blob manifest

artifact  "crucible.reproduction-artifact.v10\0"
          blob scenario-def-form, blob schedule v6     // transport form
```

Each recorded random draw carries its stream and its full draw address
(RFC-0010 [DET-26]). Schedule version 6 and segment schema 2 introduced that
address; a reader refuses version 5 schedules, schema 1 segments, and the
retired address-free draw encoding rather than infer an address.

The schedule's content hash is computed over its decisions, independent of
segment boundaries. The reproduction identity is the hash of the version 10
transport bytes; a writer streams that hash over the scenario, the manifest,
and each segment in turn rather than assembling the transport.

Campaign reproduction record version 3 keeps the stored form inline, under a
34 MiB static bound, and names each schedule segment in manifest order as a
trace-leaf child with its encoded length. Executor reproduction payload
schema 5 is that stored form. A writer publishes every segment before the
record that names it, the repository refuses a record whose segments it does
not hold, and a prepared result's journal stages the segments of its finding's
reproductions beside its log and trace segments. The finding-object and
occurrence-object services serve one segment per request, authenticated
against the record, and a failure-findings evidence record names each
reproduction's segment exchanges through a content-addressed segment list.

- **[CCOMP-32]** A reproduction artifact MUST retain its schedule as sealed
  schedule segments named by a manifest, and a campaign reproduction record
  MUST name exactly the manifest's segments, in order, as content children. A
  writer MUST seal before an append would make a segment exceed 8 MiB and
  MUST NOT seal for any other reason. Schedule identity MUST NOT depend on
  segment boundaries. Every reader MUST authenticate each segment against the
  record before decoding it, and no service response may carry more than one
  segment.

## 15.12 Scheduler continuation log

The single scheduler's own event log, which a scheduler continuation formerly
embedded entry by entry, now uses the attempt segment format of
[§15.2](#152-attempt-segments). The log keeps its per-append binary segments,
which chain into its offset ([OBS-17]), and also seals its entries into
attempt-format segments under the attempt writer's rule: before an entry
would make the open tail's encoding exceed 8 MiB, and for no other reason.
Sealed segments are stored in the scheduler's segment store under their
content hash, so seal points depend only on the entry sequence and a
restored log seals where the uninterrupted log would.

```text
continuation event log (single-scheduler continuation v10):
  prefix, appended_segment, bytes, events   // chain position (offset)
  base_events                               // first sequence covered
  segments: [{ object, first_sequence, entry_count, encoded_bytes }, ...]
  tail: [SchedulerEventLogEntry, ...]       // dense to events, <= 8 MiB
  last_append_entries                       // entries of the latest append
```

Restore streams the segments in order to rebuild the condition prefix, and
recomputes the latest append's per-append segment from the tail, which must
derive the offset's appended segment. An exact checkpoint closure retains each
referenced segment as a closure object, charged by its referenced length, and
a hot-fork continuation names the segments in its run's store. Readers that
need entries, such as replay proofs, guarded replay planning, and finding
checkpoint authentication, stream them one segment at a time. The condition
prefix still retains its complete history until the bounded fold of
[§15.4](#154-bounded-evaluation-state) replaces it ([CMEAS-15], [CMEAS-16]).

- **[CCOMP-33]** The single scheduler's event log MUST seal its entries into
  attempt-format segments under the seal rule of [CCOMP-26]. A
  single-scheduler continuation MUST carry the log's chain position,
  references to its sealed segments, the open tail, and the latest append's
  entry count, and never a sealed entry. Restore MUST authenticate each
  segment against its reference before folding it, and MUST authenticate the
  latest append against the chain position.
- **[CMEAS-28]** Exact-checkpoint capture, publication, load, restore, and
  hot-fork admission MUST NOT hold a continuation's sealed segments together.
  They MUST check presence, or copy, authenticate, and decode one segment at a
  time, and an exact closure MUST charge each segment against its byte bounds
  by its referenced length rather than by reading it.
- **[CMEAS-37]** Exact-checkpoint publication MUST write each node's QEMU
  snapshot envelope, and each failed node's host-I/O continuation, to a
  staged content-addressed object as it is encoded, hashing it in the same
  pass. No two such envelopes may be resident together, and at most one
  nested owner's encoding may be resident while one envelope is written.
  `fat_checkpoint_bytes` MUST bound each envelope as it is written, and MUST
  bound the closure by staged length. Decoding an envelope MUST check that
  it is canonical by streaming its re-encoding against the input, never by
  building a second copy.

The scheduler also records a runtime search frontier for every finite
signal-fault binding choice and every live network frame that offers branch
alternatives. A frontier can authenticate an unmodified campaign branch, or be
published as a discovery, only while the scheduler stands at the frontier's
own virtual time, and that time never moves backward. Recording a frontier
therefore first retires every leading frontier whose time precedes the
scheduler frontier, and the scheduler counts retired frontiers so a caller can
still name the frontiers first recorded by one quantum. Each retained
frontier's parent is a prefix of the scheduler configuration, so the
continuation names it by prefix length and configuration identity:

```text
search frontiers (single-scheduler continuation v10):
  search_frontiers: [{ parent_len, parent, at, choices }, ...]
  retired_search_frontiers                  // frontiers retired so far
```

- **[CCOMP-36]** The single scheduler MUST retain only the search frontiers
  whose virtual time is not before its frontier, plus the count of retired
  frontiers, so retained frontiers do not grow with the run. A
  single-scheduler continuation MUST name each retained frontier's parent by
  its prefix length of the continuation schedule and its canonical
  configuration identity, never by a copy of the schedule, and restore MUST
  check that identity. Branch authentication MUST compare a frontier's time
  and parent before normalizing its candidates.

A live session keeps two views of the same log: the subscriber hub that
streams entries to control-plane clients, and the debug history behind
breakpoints and time travel, which survives a reverse step until execution
diverges. Both seal under the same rule into the quantum loop's segment
store, so a session that starts at the run's genesis adds no segment objects
of its own. Each keeps its open tail resident and one index row per sealed
segment: the reference and the cumulative entry counts by class.

```text
session log view:
  index: [{ segment ref, causal/observational counts before and after }, ...]
  tail:  [SchedulerEventLogEntry, ...]          // since the last seal, <= 8 MiB
```

Subscriber replay reads one sealed segment at a time and walks it batch by
batch, an attach summary decodes at most the one segment its cursor falls in,
and a truncation decodes only the segment it cuts. While a breakpoint is
armed, the debug history extends one condition prefix by each appended batch
instead of rebuilding it from the history at every quantum, and it records an
event's configuration coordinate only where the coordinate changes. A
debugger command whose engine request takes the complete log collects it from
the segments for that command alone. The condition prefix itself still
retains its history until [CMEAS-15] lands.

- **[CCOMP-42]** A live session's subscriber hub and debug history MUST seal
  their entries under the rule of [CCOMP-26] and keep only the open tail and
  one index row per sealed segment resident. Subscriber replay MUST hold at
  most one sealed segment at a time, breakpoint evaluation MUST extend its
  condition prefix by each appended batch rather than rebuild it from the
  history, and the debug history MUST keep configuration coordinates only
  where they change. Only a debugger command whose engine request requires
  the complete log MAY collect it, and only for that command.

## 15.13 Guarded campaign run results

The guarded campaign owner behind local `run`, replay, save, resume, search,
and fuzz accepts one observation per attempt, and a scenario-default path
takes one attempt per choice. Each accepted observation carries its decoded
configuration, choice closure, coverage, measurement evidence, and execution
evidence snapshot. The configuration and closure grow with the path's depth,
so a result that kept every observation grew quadratically with the number of
choices.

The owner therefore delivers each accepted observation, each exploration
branch acceptance, and each requested watch frame to a caller-supplied sink,
synchronously and in acceptance order. It calls the sink while the
observation's evidence snapshot still names the attempt's live log segments,
then drops the observation. The result keeps the observation and
branch-request counts, the terminal observation, its evidence and choice
closure, the final snapshot, the savepoint and resume proofs, and at most three
lifecycle states. A resume proof also keeps its accepted source observation,
the one earlier observation a resume caller authenticates against its handle.
CLI consumers fold what they print or admit as each observation arrives:
canonical-log lines, watch frames, explored configuration identities and
findings, or fuzz corpus candidates.

A run without exploration is funded for an explicit choice budget. The budget
defaults to 65,536 and a request can replace it. The campaign's funded budget
is the run's only choice bound, and the supervisor's livelock guard scales
with the funded attempt count rather than imposing a second fixed limit.

- **[CMEAS-29]** The guarded campaign owner MUST deliver each accepted
  observation, branch acceptance, and requested watch frame to the caller's
  sink, in acceptance order, while the attempt's log segments are live. It
  MUST NOT retain them beyond the terminal observation and a resume proof's
  source observation. A run's choice bound MUST be its funded campaign budget.

## 15.14 Block overlay storage

A block device's copy-on-write overlay grows with every distinct page the
guest writes, so an attempt that runs for hours can dirty far more disk than
an executor can hold in memory. The overlay keeps the page semantics of
RFC-0010 [IO-5], [IO-7], and [IO-11], but its pages live in a page store
created as an unnamed file in the run directory, where the run's disk quota
accounts for them. A hot fork shares its parent's page store, and a page is
copied before either side patches a page the other still references.

The overlay is partitioned into 4 MiB chunks of 1,024 pages. A chunk's
identity is the BLAKE3 hash of its logical bytes: present pages in place,
zeroes elsewhere, truncated to the device length. A chunk with no nonzero
byte has no identity and no object. A block snapshot names every overlay
chunk by that identity together with its present and dirty page bitmaps, and
never carries page bytes:

```text
block snapshot overlay (block snapshot v7):
  device_length
  chunks: [{ index, identity?, present[16 x u64], dirty[16 x u64] }, ...]
```

Unchanged chunks keep their identity across checkpoints, so a checkpoint adds
objects only for chunks that hold pages dirtied since its parent. An exact
checkpoint closure lists the distinct chunk objects of every block
continuation it retains, sorted, and stores each as a closure object.

- **[CMEAS-33]** The block overlay MUST keep its pages in a run-local,
  quota-accounted page store rather than in executor memory. Snapshot
  capture, exact-closure publication, load, restore, and hot-fork admission
  MUST NOT hold more than one overlay chunk's bytes resident at a time, and a
  closure MUST bound each chunk object by the chunk size when it is loaded.
- **[CCOMP-39]** A block snapshot MUST name each overlay chunk by its
  content identity and page bitmaps, never by its bytes, and its canonical
  encoding MUST NOT depend on the page store that held the pages. Restore and
  restore validation MUST authenticate every named chunk's length, identity,
  and zero bytes outside its present pages before exposing it, and an exact
  closure MUST list exactly the chunk objects its block continuations name.

## 15.15 Compatibility

Version 2 measurement replay evidence remains readable for retained findings
whose logs fit its bound; new attempts publish only version 3. The attempt
evidence chain and the console automaton checkpoint encoding are new schemas.
Named host predicates change from history-reading functions to accumulators;
this is a source-level breaking change for host predicate implementations.
Single-scheduler continuation version 9 replaces version 8: it keeps the
imported I/O ledger in its pruned form, names the event log's sealed segments,
and carries only the open tail; version 8 continuations are refused.
Version 10 replaces version 9: it keeps only the current boundary's search
frontiers and names their parents by prefix length and identity
([CCOMP-36]); version 9 continuations are refused. The
production exact closure stayed at version 10 for those changes, because
sealed segments occupy the closure's existing event-log object role.
Block snapshot version 7 replaces version 6: it names overlay chunks by
identity instead of carrying full and delta page lists ([CCOMP-39]). Host-I/O
checkpoint version 7, device-scheduling sub-node checkpoint version 3, and
production exact closure version 11 carry it, and the closure lists the
block overlay chunk objects; their predecessors are refused.
The resolved-effect trace manifest replaces the version 3 whole-trace object
without a compatibility reader; version 3 traces, fault runtime checkpoints
before version 7, and observations before version 16 are refused. Schedule
version 5, reproduction transport version 10, campaign reproduction record
version 3, and executor payload schema 5 replace their predecessors without
compatibility readers, and prepared-result journals name reproduction
segments under segment-set hash version 3.
The guarded campaign result no longer lists its observations, branch
acceptances, or watch frames; this is a source-level breaking change for
callers, which now consume them through a sink.

[CCOMP-21]: 04a-coordinator-executor-contract.md#04a7-capability-and-locality-reporting
[IO-5]: ../0010-crucible/15-io-subnodes.md#1521-base-image-overlay-and-cow-reads
[IO-7]: ../0010-crucible/15-io-subnodes.md#1521-base-image-overlay-and-cow-reads
[IO-11]: ../0010-crucible/15-io-subnodes.md#1524-snapshot-restore-and-materialize
[OBS-17]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
[OBS-18]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
[OBS-19]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
[OBS-20]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
[OBS-26]: ../0010-crucible/19-observability-event-log.md#1961-assertion-checking-18-including-offline

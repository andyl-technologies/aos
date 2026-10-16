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

Finding production replay captures, CLI explanation, campaign objective
verification, observation-stop verification, remote observation resume, hot-fork
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
segments.

- **[CMEAS-22]** A reader MUST NOT materialize a complete attempt log. Every
  service response that carries log content MUST carry at most one segment and
  remain within the ordinary 64 MiB component-message bound. Digests, density
  checks, replay comparisons, and projections MUST stream segments in order.
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

## 15.10 Compatibility

Version 2 measurement replay evidence remains readable for retained findings
whose logs fit its bound; new attempts publish only version 3. The attempt
evidence chain and the console automaton checkpoint encoding are new schemas.
Named host predicates change from history-reading functions to accumulators;
this is a source-level breaking change for host predicate implementations.

[OBS-17]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
[OBS-18]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
[OBS-19]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
[OBS-20]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
[OBS-26]: ../0010-crucible/19-observability-event-log.md#1961-assertion-checking-18-including-offline

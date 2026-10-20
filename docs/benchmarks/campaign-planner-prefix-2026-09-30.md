# Campaign planner publication measurements

The candidate reduces durable publication work by combining the existing
three choice-graph edits and four request-exploration edits into bounded
Merkle batches. All nested-index checks, immutable byte authentication,
snapshot ancestry, resource admission, and ref publication remain in place.
Only nodes reachable from the final batch root are published. The batch
overlay retains at most the paths for these three or four edits; it does not
retain campaign history or object data across operations.

This is prefix evidence, not a million-admission qualification. The production
gate still requires 1,000,000 admissions in 62,500 requests of 16, its complete
hot/cold queue checks, and all original object, index, physical-byte, and
physical-RSS ceilings. Its timeout and required counts were not changed.

## Measurement basis

The coordinator baseline is commit
`4b6c0cdc4c58f6abf2ee80f33ce792655f01e1bb`, with diagnostic stage reporting.
Both variants use the same protected packaged planner wrapper and actual
planner process. That worker comes from the earlier running gate: its exact
source revision was not independently established here, so these measurements
are representative comparisons rather than a matching-package release proof.
The wrapper is 1,352 bytes and invokes the 104,265,000-byte controller. Their
hashes and the two test-executable hashes are in the adjacent JSON evidence.

Each run creates a new SQLite/WAL store, performs real discovery, submission
and planner acceptance, drains the hot paged queue, drops the repository and
store, then reopens and authenticates the complete cold campaign and queue.
The authorized service still supervises the real planner process and obtains
its physical peak RSS. Diagnostic timing does not enter simulation inputs.
Concurrent machine activity was not controlled or paused.

| Requests / admissions | Variant | Setup s | Planner s | Cold reopen/queue s | Physical bytes | Combined peak RSS KiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 64 / 1,024 | Baseline | 6.402 | 19.978 | 8.116 | 49,602,560 | 24,284 |
| 64 / 1,024 | Candidate | 9.099 | 25.083 | 8.444 | 48,160,768 | 23,864 |
| 256 / 4,096 | Baseline | 38.858 | 118.066 | 51.744 | 265,428,992 | 39,500 |
| 256 / 4,096 | Candidate | 43.607 | 130.497 | 48.302 | 260,186,112 | 36,480 |
| 64 / 1,024, repeat | Baseline | 7.547 | 24.642 | 8.227 | 49,602,560 | 24,272 |
| 64 / 1,024, repeat | Candidate | 8.855 | 21.319 | 7.973 | 48,160,768 | 23,952 |

Every run passed. Every ordered planner step identity matches between baseline
and candidate for the same corpus, including the repeat. Hot and cold queues
contained exactly the required prefix admissions with identical page counts.
The wall times do not establish a reliable hot-path speedup: both initial
candidate runs were slower, while the repeated overall corpus finished sooner.
The deterministic reduction in publication and stored bytes is established.

## Growing work and changed work

In the baseline 256-request corpus, the real component calls totalled 1.997 s
of the 118.066 s reported planner stage. Coordinator work dominates this
prefix. In the baseline 64-request corpus, acceptance's fresh immutable reads
grew from 2,654 calls / 2.688 MB at request 1 to 4,471 calls / 8.158 MB at
request 64. Its batch publication grew from 111,032 to 520,787 bytes. Trie
path and value authentication work grows with the store; this is not evidence
that the hot path replays the entire ancestry on every request. The existing
validated-head checkpoint promotion remains unchanged.

For the matched 256-request corpus, discovery batch calls fall from 1,280 to
768 (40%) and discovery batch bytes from 7,130,435 to 5,427,126. Submission
batch calls fall from 2,048 to 1,536 (25%) and bytes from 12,348,470 to
10,613,625. The candidate stores 1,130 fewer objects and 3,426,854 fewer index
bytes. The removed intermediate roots were never campaign snapshot roots.
The larger acceptance authentication cost remains; no object cache or skipped
byte/identity check was introduced to conceal it.

## Reproduction and validation

Build through the AOS source-built development shell:

```text
nix develop -c cargo test --manifest-path crates/Cargo.toml --release \
  -p crucible-daemon --test gate_campaign_metadata_million --no-run
```

Run the reported test executable with an absolute protected planner path,
an absolute empty owned storage path, `CRUCIBLE_CAMPAIGN_STORE_PROFILE=1`, and
`CRUCIBLE_CAMPAIGN_MILLION_DIAGNOSTIC_REQUESTS=64` or `256`. Select
`small_real_admission_corpus_exercises_the_same_path --exact --ignored
--nocapture --test-threads=1`. The production million test has no diagnostic
count override. Summarize its log with the AOS-built Python:

```text
python3 tests/crucible/campaign-million-profile.py diagnostic.log
```

Store reports split request publication, discovery, submission (`setup`),
planner preflight, real component execution, and acceptance (`planner`).
Identity samples retain at most 4,096 IDs per stage; operation counts and bytes
remain exact when that cap fills. The summary reader bounds each input line,
retains only fixed stages and request samples, requires successful completion,
checks consecutive step evidence, and hashes the complete ordered step IDs.
Raw logs remain in the isolated worktree's `.performance-87/`; their hashes
and finite summaries are recorded in the adjacent JSON file.

Validation passed eight existing discovery regressions, a new independent
sequential-root comparison across eight real choice/request transitions and
cold reopen, all three Issue-basis regressions (including corrupt/missing
inputs and failed partial publication), and missing/corrupt Merkle closure
validation. The summary reader rejected truncated, oversized, nonconsecutive,
and duplicate-terminal evidence. Rust formatting and diff checks passed.

The original million-admission job was neither changed nor restarted. A final
bounded log read observed its progress at 131,072 admissions / 8,192 requests.
Only a separately reviewed matching-package full run can qualify this candidate.

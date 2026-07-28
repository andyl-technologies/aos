# Pinned nixpkgs system-toplevel profile (2026-07-27)

## Scope

This note records the first byte-clean and performance-attributed native
evaluation of a nontrivial nixpkgs NixOS system. It supersedes extrapolation
from the smaller AOS-toplevel workload for target planning.

The fixture uses nixpkgs 25.11 commit
`c6f52ebd45e5925c188d1a20119978aa4ffd5ef6`, source path
`/nix/store/h804a5w2y4cqmzkrcgp37m8804ialqi4-source`, and enables nginx,
OpenSSH, curl, git, and jq. Both evaluators produced:

```text
/nix/store/g3lcf1mzgvi8k1gpynbalc6gn130qaxp-nixos-system-aos-evaluator-bench-25.11.19700101.dirty.drv
```

The C++ oracle was the hermetic repository-selected
`/nix/store/s06fk05p64jrww40ncam4kncidjbnblv-nix-2.24.12`. The builder's
system Nix is 2.31.2+1 and is not an admissible oracle. Every acceptance command
must therefore use the absolute 2.24.12 path and print `nix --version` before a
campaign.

The same pinned source and configuration also produced the identical root
`.drv` under local Nix 2.34.8 on aarch64-darwin. This establishes a useful
cross-version oracle fixture, but not yet full transitive `.drv` byte parity
for the 2.34 compatibility profile.

## Cold-run definition

A cold run starts with no cache records from outside that run. It does not
disable caching: all in-process memo tiers remain enabled and may hit records
produced earlier in the same run. Persistent cache population is measured as a
separate axis because its purpose and dominant costs are cross-run reuse.
Additive disk locations and network tiers are excluded because they import
external records.

The first profile below predated this correction and ran with the in-process
content memo and persistent cache disabled. It remains useful as a cache-off
diagnostic, but it is not the final cold acceptance result.

An isolated in-process-memo rerun remained byte-correct but regressed from
273,110,398,403 to 275,776,820,655 instructions and from 4,270,764 to
4,526,540 KiB RSS. It confirmed only 49 demand-key hashes, so the current
admission population did not repay the tier on that build.

After the linear mapped-attribute ordering changes, the corrected L0/L1-only
cold configuration produces the identical root derivation in 197,103,073,775
instructions, 76,675,241,073 cycles, 25.57 seconds, and 4,288,420 KiB peak RSS.
It still confirms only 49 demand-key hashes. This is the current acceptance
configuration: it retains every in-process cache opportunity without importing
data or paying cross-run persistence costs. Later parser, module-identity, and
memo-index improvements below supersede its performance numbers.

The serial evaluator constructs only the per-evaluator L0 table; L1 is a
shared table created with a parallel-demand context. An opt-in memo-economics
run made the serial result more precise:

```text
claimed force attempts                 7,961,369
successfully derived memo keys                49
unique keys                                   33
keys observed more than once                   7
potential repeated occurrences                16
L0 admissions                                 29
L0 hits                                       14
total L0 record time                    3.390 ms
```

The instrumented run remained byte-identical and peaked at 4,316,908 KiB RSS.
The admitted L0 population is therefore too small, and record construction too
cheap, to explain the multi-gigabyte peak. The immediate in-process cache
problem is effectiveness: its durable-value-hash key model declines almost
every captured-thunk environment. A same-run key must be able to use
evaluator-local stable identities, with explicit invalidation at relocation,
instead of requiring every capture to have a cross-run hash. Independently,
the terminal liveness evidence below still makes reclamation of historical
arena state the factor-level memory path.

An admission-floor sweep showed that the durable-key path can find substantial
same-run reuse when it considers cheaper def-sites. Every row remained
byte-identical and retained the 65,536-entry L0 cap:

```text
minimum cost   key confirmations   instructions       cycles          wall       max RSS
64 (default)                  49   154,871,249,470   69,807,244,581   22.66 s   4,258,984 KiB
16                         35,576   156,125,008,884   62,190,463,492   20.80 s   4,267,108 KiB
4                         470,405   161,617,370,159   65,181,187,318   21.53 s   4,304,576 KiB
0                         768,251   165,374,701,893   66,926,057,797   21.10 s   4,293,032 KiB
```

The cycle and wall figures are noisy, but retired instructions make the
tradeoff clear: breadth alone is not a win. At floor 0 the cache recorded
576,389 L0 hits, filled all 65,536 entries, and still executed 6.8 percent more
instructions than the default. Most avoided computations were too cheap to
repay key derivation, payload serialization, and replay. Floor 16 was much more
selective: 2,338 admissions produced 26,681 hits, while the economics census
assigned about 21 static cost units to each potential repeated occurrence.

This changes the immediate cache priorities:

1. remove the admission-decision hash from every claimed force;
2. keep static cost selection rather than admitting every hashable def-site;
3. give same-worker L0 a direct, GC-rooted value representation so it does not
   serialize and rehydrate values solely to remain shareable with L1; and
4. treat evaluator-local identity keys as an opt-in experiment until their
   measured high-cost repeat population exceeds the existing raw-identity
   census.

The first implementation of item 1 replaced the global
`HashMap<EvalNodeRef, ...>` with a module/node index. It reduced the default
sample from 154.87 to 153.24 billion instructions, confirming that the lookup
was material, but a dense node vector increased RSS for sparse high node ids.
The retained design indexes modules directly and uses a sparse module-local
`u32` table with a cheap integer mixer. It produced the identical derivation in
153,408,986,114 instructions, 61,180,145,695 cycles, 22.48 seconds of native
wall time, and 4,294,228 KiB RSS. This retains a 0.94-percent instruction
reduction versus the preceding sparse global table without the dense index's
roughly 149 MiB RSS spike. Repeating floor 16 on this build produced
154,662,318,493 instructions and 61,859,913,110 cycles, so the default floor 64
remains the acceptance setting until a direct-value L0 lowers hit replay cost.

Two subsequent lookup changes preserve the same cache policy. A seven-byte
order-preserving symbol prefix is retained only by the shape and HAMT ordering
paths, where its eight-byte token replaces a sixteen-byte borrowed slice;
materializing one token for every flat attr entry was faster but raised peak
RSS, while recomputing it in every comparator was slower. Separately,
`unsafeGetAttrPos` now builds one lazy line-start index per queried module
instead of rescanning the source prefix for every position. The combined build
produced the exact derivation in two samples spanning
142,170,804,681--142,213,216,721 instructions and
58,123,737,914--58,152,581,521 cycles. The corresponding RSS samples were
4,255,704 and 4,436,600 KiB, inside the campaign's substantial allocator noise
but without a repeatable factor-level regression. The instruction reduction
from the 153.41-billion sparse-index baseline is 7.3 percent. In the following
profile, `attr_position_fields`, previously 3.71 percent self cycles, no longer
appeared above the 0.5-percent reporting threshold.

That profile also showed 5.09 percent self cycles in `memmove`, mostly below
`defer_flat_capture_if_assembling`. The pending-capture queue called
`try_reserve_exact(1)` before every push, which repeatedly copied the entire
queue during large recursive binding assemblies. Normal fallible geometric
growth reduced two exact samples to 140,480,775,215--140,513,611,122
instructions and 55,656,013,936--56,000,465,376 cycles. The separate RSS run
peaked at 4,270,216 KiB. This is a further 1.2-percent instruction reduction
without changing capture publication, early-force, or recursive-binding
semantics.

Caching the same seven-byte ordering prefix once per interned symbol, rather
than once per flat attr entry, restored the comparator shortcut without the
rejected flat scratch allocation. Three exact samples retired
136,154,922,262--136,216,044,543 instructions and peaked at
4,191,048--4,205,456 KiB RSS. The least-contended sample retired
57,878,684,648 cycles. This is a further 3.1-percent instruction reduction and
about 1.7-percent peak-RSS reduction from the geometric-capture baseline; the
first two cycle samples were distorted upward by builder contention.

An opt-in Ready-lifecycle census then tested whether a second in-process
structural table could expose missed reuse without changing the ordinary hot
path. Across 7,961,369 force-path key samples, the cost floor admitted only 49
exact recipes: 33 unique recipes, 16 repeats after an earlier recipe was Ready,
and no repeats overlapping a Pending recipe. The existing L0 already served 14
of those 16 repeats. The two missed repeats account for only 1,024 bytes of
conservatively estimated thunk work, while candidate derivation declined 181
dynamic-scope and 629 unknown-capture cases. A second map over the same key
cannot materially help this workload. The useful next in-process experiment
must make identity/admission cheaper or move reuse to the thunk/def-site
representation; lowering the cost floor with the current key machinery was
already instruction-negative. At floor zero the census found 657,633 Ready
repeats and the L0 served 576,389 hits, but two clean samples retired
146,021,310,029--146,032,015,540 instructions,
58,467,713,681--58,614,161,779 cycles, and peaked at
4,312,408--4,324,324 KiB RSS. That is 7.25 percent more instructions and about
3 percent more peak RSS than floor 64 despite roughly 607,000 fewer actual
forces. The cache's limiting cost is structural key derivation and record
materialization, not the table lookup or a lack of intra-run reuse.

A bounded direct-value L0 path then stored representation-self-contained
scalars without constructing or rehydrating a closed payload. Candidate-C
boxed integers and floats remain payload-backed because their words name arena
cells; heap and position-bearing values also retain the old path. At floor zero
two clean samples retired 145,941,654,201--145,951,546,965 instructions, only
about 0.055 percent below the payload-only result. At the accepted floor 64 the
same build retired 136,199,366,638--136,259,249,242 instructions, within run
noise of the preceding result. Direct scalar replay is sound and worth keeping,
but the material opportunity is avoiding durable key and payload work for
equivalent Ready thunk cells, not specializing more payload scalar cases.

An opt-in worker-local raw-identity census measured that alternative without
serving hits. Recipes contain the module-qualified def-site plus the
relocation-sensitive words of only its statically referenced direct capture
slots; effectful bodies, dynamic scopes, and projected dependencies are
declined. At floor 64 it found only 12 Ready repeats. At floor zero it found
675,707 exact Ready repeats, no Pending overlap, and 2,529,691 avoided static
cost units. A one-entry-per-def-site shadow directory retained 473,552 hits
(70.1 percent of the exact upper bound) and 2,008,397 cost units; a two-entry
directory retained 512,367 hits (75.8 percent) and 2,075,959 cost units. The
second way buys only 38,815 additional hits and still misses the proposed
90-percent capture threshold. The first active experiment should therefore be
a one-entry-per-def-site weak Ready-cell directory: it avoids a global recipe
map and all durable key/payload work while retaining most of the measured
bounded-cache benefit.

The first active one-way implementation initially remained 2.92 percent
instruction-negative at floor zero even after caching each def-site's static
capture plan: two clean samples retired 150,578,553,711--150,585,398,418
instructions, versus 146,299,839,083--146,316,446,373 with the directory
disabled. The cause was duplicated cache policy. Every raw-eligible miss still
derived, probed, and admitted the durable content key after missing the local
directory. Making the raw directory exclusive for eligible sites reduced
durable confirmations from 768,251 to 86,465 and recovered almost the entire
loss. The clean paired samples were:

```text
mode                 instructions       cycles          max RSS
Ready disabled      146,322,523,787   59,505,177,706   4,252,000 KiB
Ready exclusive     146,393,611,199   58,173,102,474   4,229,768 KiB
```

Both produced the exact expected derivation. The exclusive path is effectively
instruction-neutral at floor zero (+0.049 percent), while this clean pair
showed 2.24 percent fewer cycles and 0.52 percent lower peak RSS. A second,
load-contaminated pair likewise differed by only +0.023 percent instructions,
so exclusivity is a retained improvement over the stacked design. It is not
yet a default win: floor zero as a whole remains materially worse than the
accepted floor-64 configuration, while the floor-64 raw census found almost no
reuse. The next experiment must separate the policies: retain floor 64 for
durable content memoization while allowing the lower-overhead local Ready
directory to use its own floor.

That mixed policy was also negative. With the durable floor fixed at 64 and
the local Ready floor at zero, two clean pairs produced:

```text
mode                         instructions       cycles          max RSS       native wall
durable 64, Ready off       136,593,721,752   53,228,248,278   4,242,884 KiB   18.468 s
durable 64, Ready floor 0   141,938,328,204   55,727,209,850   4,221,522 KiB   19.799 s
delta                                 +3.91%            +4.70%          -0.50%       +7.21%
```

Every sample was byte-identical. Demand-key confirmations fell from 49 to 4,
but that did not compensate for candidate construction, two general-purpose
def-site table probes, captured-slot resolution, source-thunk lookup, and the
Ready-cell load on every eligible force. The small RSS movement is not a cache
retention win: lookup happens after the duplicate thunk and captured
environment were allocated, so this design cannot avoid their dominant memory
cost. The separate floor remains useful opt-in experimental infrastructure,
but the directory stays disabled by default. The next local-cache experiment
must first classify retained hits by empty/flat/linked capture representation,
then test a dense module-local direct-result slot for only the shapes that can
avoid both hash tables and source-cell resolution. Allocation-time
canonicalization is the stronger follow-on because it can avoid the duplicate
thunk rather than merely skip its body.

A stats-only representation census then partitioned the exact and one-way
Ready hits by the actual captured environment:

```text
capture representation   exact Ready hits   one-way hits
empty                               297,471        297,471
flat, one slot                      101,829         43,020
flat, two slots                      36,726          3,422
flat, more than two slots                 0              0
linked or hybrid                    267,506        145,632
total                               703,532        489,545
```

The run remained byte-identical and the bucket sums exactly matched their
parent counters. Empty captures supply 60.8 percent of retained one-way hits,
and their exact and one-way counts are identical because the recipe is only the
module-qualified def-site. This is the narrowest credible active specialization:
fuse cached plan state and a direct Ready result for empty-capture sites so one
module-local lookup replaces capture resolution, recipe construction, the
second directory lookup, source-thunk resolution, and its Ready-cell load.
Flat-one adds only 8.8 percent of retained hits and should wait until the empty
path proves that one cheap lookup can repay these low-cost bodies.

The direct empty-capture specialization retained the completed `Value` in the
cached def-site plan. A hit therefore preserved a distinct outer thunk but
needed only the per-thunk scope/frame validation, one plan-table lookup, and
normal force completion. Adversarial Candidate-C tests compared cache-off and
replay behavior for lambda, primop, NaN, list-with-lambda, and
attrs-with-lambda results, both directly and after `builtins.seq`. The only
statically eligible adversarial shape, NaN, genuinely served Ready hits without
changing equality; the other non-reflexive bodies were declined by the existing
speculability predicate.

Two clean acceptance pairs nevertheless rejected the specialization as a
default:

```text
mode                       instructions       cycles          max RSS       native wall
durable 64, Ready off     136,945,805,153   55,355,356,224   4,251,470 KiB   19.294 s
empty Ready floor 0       138,727,428,706   55,027,319,523   4,226,720 KiB   20.128 s
delta                               +1.30%            -0.59%          -0.58%       +4.32%
```

All four samples produced the exact pinned derivation. Cycle and RSS movement
was mixed across the individual pairs, while instructions were a stable
1.28--1.32 percent regression. This still recovers roughly two thirds of the
general captured directory's 3.91-percent instruction loss, proving that
recipe/source-cell elimination is material, but the per-force plan-table
probe/classification remains more expensive than the small bodies avoided.
The specialization remains opt-in. A subsequent active version needs a
module-local preclassification or compact indexed site state so ineligible
forces do not pay a general hash-table lookup.

Replacing the global `HashMap<EvalNodeRef, ...>` plan table with sparse
module-indexed `HashMap<u32, ...>` tables and the existing specialized integer
mixer recovered most of that loss. Two exact pairs measured +0.167 and +0.207
percent instructions, for a +0.187-percent mean, while demand confirmations
remained 49 versus 9. Cycle, RSS, and wall directions disagreed between pairs.
A low-overhead profile of the preceding build had attributed 0.81 percent self
cycles directly to `ReadyCellPlanCache::probe_empty`, with generic
`BuildHasher::hash_one` sites contributing additional aggregate cost; normal
force completion was only 0.07 percent. Module indexing is therefore retained,
but empty replay remains opt-in. A small module-local hot-plan PIC is the next
bounded experiment: it can bypass even the specialized sparse-map hash for
temporally repeated def-sites without allocating a dense max-IR-id table.

That one-entry-per-module PIC did not improve the sparse-map result. Two exact
pairs measured +0.208 and +0.245 percent instructions, for a +0.226-percent
mean; cycles were flat (+0.003 percent), and native wall regressed 5.32 percent.
The added tag/frame comparison and coherence maintenance cost more than the
hashes avoided by temporal hits. Commit `94d0c0304` therefore reverts only the
PIC while retaining the better sparse module/u32 plan index.

Enabling a fresh persistent cache independently exposed a correctness defect:
cached-import hydration did not remap the symbol carried by an
`IrData::SearchPath` node, so `<nix/fetchurl.nix>` resolved through an unrelated
live symbol as `getFlake`. Commit `2ed97b959` fixes the remap. The corrected run
is byte-identical, but persistent observation increases the result from
273,110,398,403 to 883,156,805,561 instructions (106.4 seconds wall time) and
records 2,297,608 persistent-expression key hashes. Write-behind produces an
indistinguishable 883,209,114,173 instructions, proving the dominant cost is
per-force identity/observation and payload work before writeback, not synchronous
pack writes. Persistent caching therefore remains a separate optimization
track; it is not part of the in-process cold acceptance result.

## Cache-off diagnostic measurements

The native leg was the fat-LTO release build with `candidate_c_value`,
`AOS_NIX_BENCH_COLD_ONLY=1`, `--nix-compat=2.24.12`, and an explicit pinned
search path:

```text
--nix-path nixpkgs=/nix/store/h804a5w2y4cqmzkrcgp37m8804ialqi4-source:nix=/tmp/aos-pr104-corepkgs-224
```

The exactly matched stock leg was:

```text
nix-instantiate flake-adapter.nix -A system
```

Both instantiate and materialize the selected derivation. A separate
`--eval --strict -A system.drvPath` stock leg produced identical evaluator
counters but retired 1.8 percent fewer instructions, so it is useful for
semantic attribution but is not the acceptance baseline.

```text
                         instructions       cycles          max RSS
Nix 2.24.12                       24,254,636,565     12,420,737,095  828,652 KiB
AOS Candidate C, cache off       273,110,398,403    111,755,985,336  4,270,764 KiB
AOS Candidate C, L0/L1           197,103,073,775     76,675,241,073  4,288,420 KiB
AOS Candidate C, current L0      136,154,922,262     57,878,684,648  4,196,852 KiB
target                            <12,127,318,283     <6,210,368,548  <414,326 KiB
```

The current L0 result is approximately 5.61 times stock instructions, 4.66
times stock cycles, and 5.06 times stock peak RSS. Reaching the acceptance gates
still requires about an 11.23-fold instruction reduction, 9.32-fold cycle
reduction, and 10.13-fold peak-RSS reduction from this native result. More
averaging cannot turn this architecture into a pass; attribution and
architectural changes come first.

## Allocation and liveness attribution

The diagnostic run reported:

```text
modules                                  8,432
imports evaluated                       3,073
thunks allocated                   12,297,448
thunks forced                       7,961,696
function calls                      8,756,827
values allocated                   19,091,619
flat closure objects               16,823,672
worker arena used               1,565,659,016 bytes
permanent arena used              558,244,664 bytes
module IR                           326,130,731 bytes
module source                        46,594,467 bytes
```

Pinned C++ Nix reported 7,480,248 allocated thunks and 6,229,845 avoided thunk
sites. Native's 12,297,448 allocations are below stock's 13,710,093 potential
sites, but its 4,335,752 allocated-and-unforced records expose substantially
weaker thunk elision. This is an allocation-planning and lifetime target, not
evidence of duplicate demand. Likewise, the apparent 64-percent function-call
difference is not directly comparable: the native counter increments before
callable dispatch and includes primop and functor applications, while C++ Nix
records those separately. Subtracting native primop-resolution traffic leaves
the counters within 0.4 percent, although a true apply-tag census is required
for an exact comparison.

The terminal weak-liveness census is more decisive:

```text
roots                                      3,074
reachable objects                         98,555
allocated objects                     18,091,619
arena pages used                         518,532
arena pages containing reachable data      8,714
reclaimable arena pages                  509,818
reclaimable resident bytes         2,088,214,528
```

Reachable closure counts were only 30,699 suspended thunks, 10,856 forced
thunks, 3,686 lambdas, and 786 primops. Reachable permanent objects were only
5,783 attrsets and 4,889 lists. Mid-import census points likewise showed small
live graphs, but the current evaluator performs no useful pre-peak sweep. Peak
RSS therefore tracks historical allocation rather than the live result.

Enabling the existing non-moving `AOS_NIX_GC=sweep` mode on the current exact
build did not change that conclusion. It remained byte-identical but increased
native wall time to 27.73 seconds and peaked at 4,425,636 KiB RSS, versus
roughly 18--21 seconds and 4,270,216 KiB for the retained configuration. Capture
shedding and the current quiescent sweep cadence therefore do not reclaim the
historical arena pages before this workload's peak.

The narrower callback-free final-config sweep has already isolated the physical
fragmentation limit. At ordinal 160 it retired 221,940 unreachable worker
objects, but live/dead interleaving exposed only 267 complete 4-KiB pages
(1,093,632 bytes) to `MADV_DONTNEED`. Matched peak RSS fell only 3,196 KiB while
instructions rose 3.0 percent and cycles 4.2 percent. A broader ordinal-192
projection found only 31,162,368 bytes on wholly dead pages and still faced
weak-index, writeback, and incoming-edge blockers. Import-boundary sweeping
cannot turn the terminal 2.09-GiB logical-dead estimate into physical recovery
without first changing allocation placement. The next factor-level memory
implementation must segregate chronological/lifetime cohorts or rotate the
whole domain; another non-moving decommit hook would repeat an already rejected
experiment.

This rejects the assumption that a compact `Value` alone is sufficient. The
next memory experiment should segregate import/demand-scoped immutable cohorts,
weakly retain interning candidates, and decommit complete dead regions before
the peak. It must avoid a global stable-handle load on every access.

## Capture-free Ready sidecar

A direct module-local bitmap/rank index removed the sparse hash-table lookup
from the capture-free Ready experiment. Its lazy classification cost was fully
charged to the cold run, and the result remained the exact
`g3lcf1mzgvi8k1gpynbalc6gn130qaxp` derivation. The sidecar nevertheless
regressed from 136,825,285,708 to 139,084,517,515 instructions (+1.65 percent),
from 53,702,870,931 to 54,310,264,785 cycles (+1.13 percent), and from
4,272,436 to 4,296,256 KiB peak RSS (+23,820 KiB). Demand-key confirmations
fell from 49 to 9, but the saved capture-free bodies were too cheap to repay
whole-module subtree classification and sidecar storage. The prototype was
reverted; the earlier sparse per-module plan index remains retained.

A substantially different follow-up is an allocation-time weak Ready factory:
preclassify eligible allocation sites once, publish a weak successfully forced
source, and allocate a fresh small forced thunk head on a later safe hit. This
moves the probe off the general force path and preserves distinct outer thunk
identity. The measured empty-capture ceiling is 297,471 hits and roughly
22--28 MiB net RSS, so it is additive rather than factor-level. Before an active
implementation, a report-only census must find at least 200,000
identity-insensitive Ready-before-allocation hits and 16 MiB of net pre-peak
bytes; active retention additionally requires at least a 0.25-percent
instruction reduction without a cycle or wall regression above one percent.

The report-only allocation-time census then rejected that follow-up before an
active implementation. It observed 502,439 eligible allocations across 16,841
sites and 380,065 allocations with a Ready source already available. Only
17,149 of those Ready results were identity-insensitive scalar, string, or path
values; 362,916 were functions or composite values whose reuse could change
Nix equality through pointer-identity shortcuts. The safe subset projects only
1,646,304 replaceable bytes, while a direct four-byte IR-node site map plus
eight-byte weak slots projects 11,444,408 bytes. The net projection is therefore
approximately 9.8 MiB worse before charging implementation code or peak timing.
Only 16,106 of 311,060 eventually forced eligible allocations produced a safe
result, confirming that a different publication policy cannot recover the
gate. The exact output remained `g3lcf1mzgvi8k1gpynbalc6gn130qaxp`; the
measurement-only implementation was reverted so normal allocation and force
paths retain no census checks.

## Exact formal-set application Ready census

The generic formal-set boundary probe covers modern nixpkgs broadly, but the
source-Merkle boundary recognizer does not: the pinned system evaluation
recognized only 3,851 applications at five def-sites in four modules. That
recognizer therefore cannot establish the economics of an in-process
application cache for the current nixpkgs `callPackage` graph.

A default-off `AOS_NIX_FORMAL_SET_READY_CENSUS` probe now measures the broader
alternative without serving results. It is admitted by the exact same
serial, GC-off, non-relocating, non-reusing local-Ready safety predicate as the
existing raw-identity directory. Each integer-only key contains the
module-qualified lambda body plus the function and argument value tags and
their transient representation identities. The probe never retains a `Value`,
walks or forces an argument attrset, or changes evaluation. Its drop-based
Absent/Pending/Ready lifecycle removes a failed first application, distinguishes
recursive Pending overlap from a strict Ready repeat, and reports both measured
repeat-body wall and a projection based on the first successful body.

- [x] The exact pinned Nix-2.24-compatible system run observed 151,264 Absent
      keys, zero recursive-Pending overlaps, 254 strict-Ready repeats, 151,264
      distinct Ready keys, and no failed or residual Pending entries. Strict
      repeats were only 0.168% of 151,518 formal-set applications and consumed
      32,663,140 ns of measured repeat-body wall; projecting each repeat from
      its first successful body gives an upper estimate of 430,021,955 ns.
      The measurement run retired 138,766,959,312 instructions and
      54,616,929,162 cycles, peaked at 4,317,368 KiB RSS, and returned the exact
      expected
      `g3lcf1mzgvi8k1gpynbalc6gn130qaxp-nixos-system-aos-evaluator-bench-25.11.19700101.dirty.drv`.
- [x] Do not build the serving raw-identity application cache from this route:
      its measured reusable work is about 0.17% of clean wall, below the 1%
      go/no-go floor and unlikely to repay an integer-key lookup on every
      formal-set application. Retain the probe and lifecycle tests for future
      workloads. A durable source-Merkle record remains a separate avenue, but
      must include or prove away runtime overrides/captures and preserve the
      canonical impure-input slice.
- [x] The corrected strict-cold baseline uses capture-free local-Ready
      specialization. The full local-Ready census found only 12 Ready hits,
      all capture-free, with zero captured-recipe hits; strict-cold therefore
      keeps the cache enabled but uses its direct empty-capture admission path.
      Two clean runs retired 137,979,947,847 / 137,966,989,822 instructions,
      consumed 54,603,117,964 / 54,196,076,390 cycles, peaked at
      4,290,544 / 4,241,600 KiB RSS, and took 18.138 / 19.128 seconds of
      evaluator wall. Both returned the exact expected derivation. Relative to
      the full captured-recipe Ready run (138,347,167,443 instructions), the
      specialization removes about 374 million instructions (0.27%) while
      preserving every observed hit; RSS remains effectively at the prior
      ~4.27 GiB level.

## Exact absent-formal allocation census

Generic `TreeWalkThunkAllocationPlan::Omit` cannot by itself remove storage:
`eval_thunk_alloc` is an expression-valued boundary and must return a valid
`Value`. Storage omission belongs to the owning container or frame, which can
preserve layout with a semantically unreachable dummy slot. The existing
dead-`let` consumer already follows that rule.

Formal-set summaries now persist a separate conservative cardinality field.
The producer reuses the frame-aware escape traversal, but records every lexical
slot reference regardless of value-flow position. A formal is
`Cardinality::Absent` only when neither the lambda body, any nested closure, nor
any formal default references its slot; all referenced or malformed cases stay
`Many`. This is intentionally distinct from `LambdaDemand::Unknown`, which
does not prove absence. The facts artifact version is bumped so a warm parse
cache cannot silently load the older summary shape.

Under `AOS_NIX_EVAL_STATS=1`, the binder remains observational and splits exact
runtime outcomes into:

- missing values with defaults, the narrow first-slice thunk-omission class;
- supplied values, the broader caller-side omission ceiling;
- missing required values, whose error must remain;
- otherwise absent slots declined because an `@` alias can expose the argument
  aggregate.

The census preserves argument forcing, unexpected/missing-key validation,
default thunk allocation, slot population, cache observation, and output. The
first active slice is gated on at least 217,000 eligible missing-default
allocations (5% of the measured 4.335 million allocated-but-unforced
population), a projected 32 MiB of pre-peak storage, or at least 1% retired
instructions. Below those floors, retain the proof/counters and measure the
supplied-value class before adding a semantic rewrite.

The exact pinned Nix-2.24-compatible system run rejects both active follow-ups:
each of three benchmark evaluations reported 12 eligible missing-default
allocations, 1,026 supplied-value opportunities, zero missing-required cases,
and 376 alias declines. The cold and warm native evaluations both passed byte
parity. Twelve allocations are 0.00028% of the 4.335 million
allocated-but-unforced population and 0.0055% of the 217,000-candidate gate;
even the broader supplied-value ceiling is only 0.024% of that population.
Neither class can plausibly reach 32 MiB or 1% retired instructions. Retain the
persisted absence proof and cheap stats counters as reusable infrastructure,
but do not add dummy-slot substitution or caller-side argument rewriting for
this workload.

## Cycle profile

A low-overhead cycles profile of the current build attributed the largest self
costs as:

```text
6.06%  libc memcmp
3.59%  TreeWalk::capture_env
2.66%  EvalHeap::alloc_attrs_with_projected_shape_metadata
2.62%  TreeWalk::pop_env_scope
2.34%  slice unstable quicksort
2.26%  TreeWalk::force_serial_thunk_value
2.25%  HAMT build_node
2.15%  libc memmove
2.04%  TreeWalk::eval_thunk_alloc
1.80%  SHA-256 block compression
```

The former `lexicographic_rank`, mapped-name allocation, binding-target lookup,
and source-position scan hotspots are gone. Symbol-byte comparison and sorting
remain the largest aggregate local family, while environment capture, scope
management, and thunk allocation now expose the broader closure-representation
cost. Even eliminating the listed local functions entirely would not reach the
2x gate, so the longer speed avenue remains a generated whole-demand state
machine over high-coverage callback-free regions, with precise statepoints that
can later support a nursery.

## Research anchors

The implementation experiments should borrow mechanisms rather than copy an
entire runtime design:

- Peyton Jones, *Implementing Lazy Functional Languages on Stock Hardware: The
  Spineless Tagless G-machine* (1992), for explicit update/value/argument stacks
  and non-strict execution.
- Tofte and Talpin, *Region-Based Memory Management* (1997), for assigning
  allocations to statically scoped lifetimes.
- Blackburn and McKinley, *Immix: A Mark-Region Garbage Collector with Space
  Efficiency, Fast Collection, and Mutator Performance* (2008), for block/line
  segregation and opportunistic evacuation.
- Appel and Goncalves, *Hash-consing Garbage Collection* (1993), for the warning
  that deduplication must not pay lookup and lifetime-extension costs for
  short-lived objects.

The measured shape favors a hybrid: prove and reclaim ephemeral regions first,
then introduce generated statepoints and a small copying/mark-region nursery
only where region escape analysis cannot classify the allocation.

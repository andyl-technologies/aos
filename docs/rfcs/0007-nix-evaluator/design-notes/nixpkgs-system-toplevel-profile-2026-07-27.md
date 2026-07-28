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

This rejects the assumption that a compact `Value` alone is sufficient. The
next memory experiment should segregate import/demand-scoped immutable cohorts,
weakly retain interning candidates, and decommit complete dead regions before
the peak. It must avoid a global stable-handle load on every access.

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

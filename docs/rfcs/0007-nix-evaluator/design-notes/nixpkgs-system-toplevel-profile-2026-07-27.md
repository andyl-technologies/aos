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
baseline: it retains every in-process cache opportunity without importing data
or paying cross-run persistence costs.

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
`AOS_NIX_BENCH_COLD_ONLY=1`, and `--nix-compat=2.24.12`. The exactly matched
stock leg was:

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
target                            <12,127,318,283     <6,210,368,548  <414,326 KiB
```

The current L0/L1 result is approximately 8.13 times stock instructions, 6.17
times stock cycles, and 5.18 times stock peak RSS. Reaching the acceptance gates
still requires about a 12.35-fold cycle reduction and a 10.35-fold peak-RSS
reduction from this native result. More averaging cannot turn this architecture
into a pass; attribution and architectural changes come first.

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

This rejects the assumption that a compact `Value` alone is sufficient. The
next memory experiment should segregate import/demand-scoped immutable cohorts,
weakly retain interning candidates, and decommit complete dead regions before
the peak. It must avoid a global stable-handle load on every access.

## Cycle profile

A low-overhead cycles profile attributed the largest self costs as:

```text
17.01%  SymbolTable::lexicographic_rank
15.22%  TreeWalk::alloc_mapped_attr_name
 9.46%  libc memmove
 4.16%  Parser::binding_target_symbol
 3.15%  allocator free
 2.18%  TreeWalk::attr_position_fields
```

The first two attr-name paths plus their copying account for more than a third
of cycles. They are immediate bounded optimization candidates. Even eliminating
them entirely would not reach the 2x gate, so the longer speed avenue remains a
generated whole-demand state machine over high-coverage callback-free regions,
with precise statepoints that can later support a nursery.

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

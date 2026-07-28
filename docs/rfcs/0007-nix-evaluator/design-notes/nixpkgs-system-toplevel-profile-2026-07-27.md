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

## Clean cold measurements

The native leg was the fat-LTO release build with `candidate_c_value`,
`AOS_NIX_BENCH_COLD_ONLY=1`, and `--nix-compat=2.24.12`. The stock leg was:

```text
nix-instantiate --eval --strict flake-adapter.nix -A system.drvPath
```

Both demand the same selected `drvPath`; the native path additionally installs
the already-computed in-memory derivation closure, matching normal Nix
derivation materialization.

```text
                         instructions       cycles          max RSS
Nix 2.24.12              23,812,328,735     11,495,560,746  829,200 KiB
AOS Candidate C         273,110,398,403    111,755,985,336  4,270,764 KiB
target                   <11,906,164,368     <5,747,780,373  <414,600 KiB
```

The first native result is approximately 11.47 times the stock instruction
count and 5.15 times its peak RSS. More averaging cannot turn this architecture
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

Pinned C++ Nix reported 7,480,248 thunks, so native thunk-allocation traffic is
about 64 percent greater before object-size and lifetime overhead is
considered. The apparent 64-percent function-call difference is not directly
comparable: the native counter increments before callable dispatch and includes
primop and functor applications, while C++ Nix records those separately.
Additional apply-tag attribution is required before claiming duplicate semantic
execution.

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

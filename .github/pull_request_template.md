## Summary

## Determinism Review

Apply this section to any PR that touches engine, scheduler, transport, or other ordering-significant host code:

- L0: `crucible-sim`, `crucible-assert`
- L1: `crucible-shmem`, `crucible-protocol`, `crucible-device`
- L3: `crucible`

Reviewers must block merge on any unchecked applicable item.

- [ ] Not applicable: this PR does not touch engine, scheduler, transport, or ordering-significant host code.
- [ ] Applicable: every relevant item in the determinism review checklist below is checked or explicitly justified in this PR.

### DETERMINISM REVIEW CHECKLIST

Ordering

- [ ] Every collection on an ordering-significant path is ordered (BTree*/IndexMap/ sorted Vec) or carries a justified [STD-13] allow. No HashMap/HashSet iteration leaks order into State / Schedule / canonical log / a hash.
- [ ] Any sort uses a TOTAL, stable key - the cross-node order key is (virtual_time, consumer node_id, producer node_id, sequence) [INV-3]; ties cannot resolve by address, pointer, allocation order, or insertion-into-a-hash order.
- [ ] Any select/poll over simultaneous readiness is biased/priority-ordered; the branch taken on a tie is a pure function of declared priority.

Time, randomness, numerics

- [ ] No host wall-clock (Instant::now/SystemTime::now/elapsed) feeds State; virtual time is icount-derived [INV-4]. Wall-clock appears only in observational tracing that never feeds back.
- [ ] No thread_rng/getrandom/host entropy; all randomness is the seeded decision RNG, forked per-entity by name-hash so adding/renaming a node doesn't perturb others [HARN-31].
- [ ] No f32/f64 on a decision path; fractional decision quantities are integer basis points (or fixed-point) so comparisons are exact and FPU-independent.

State purity & content addressing

- [ ] State is still a pure function of (ScenarioDef, Schedule) [INV-1]; no new uncontrolled input (env var, file mtime, host core count, address) reaches it.
- [ ] Anything newly added to the canonical log/hash is canonical, not observational; anything that may vary between equivalent runs is observational by schema, not by a side flag [OBS schema].
- [ ] Content addressing holds: equal content => equal id; the (de)serializer is canonical (stable field order, no map-order dependence) [INV-6].

ABI, unsafe, errors

- [ ] If a boundary ABI changed: version bumped AND golden vectors regenerated in THIS PR; round-trip property still holds [STD-23], gate:abi-conformance.
- [ ] If unsafe was added/touched: the crate is an enumerated unsafe-permitted crate [STD-16]; every block has a // SAFETY: comment [STD-17]; the safe wrapper upholds the invariant; SPSC changes are covered by the exhaustive ordering model and its negative controls [STD-22].
- [ ] No .unwrap()/.expect() in production; library errors are typed (thiserror), anyhow only at the binary boundary; a loud-failure panic names the invariant it defends [STD-7, STD-8, INV-10].

Tests & gates

- [ ] The relevant layer gate covers the change (not a higher layer) [HARN-3]; a new determinism property has a test that FAILS when it is violated.
- [ ] If the change could introduce nondeterminism the lint can't express, it is exercised under gate:adversarial-determinism and localizable by bisection [INV-10].
- [ ] gate:harness-lint config was not weakened to make this PR green; any new [STD-13] allow has a written rationale.

### Root-Cause Fix Rule

When this checklist surfaces a determinism leak, the fix must be at the source of the nondeterminism. Do not paper over the leak with retry logic, quarantine, jitter tolerance, compare-with-a-fudge-factor behavior, or post-hoc smoothing that leaves the source intact.

- [ ] Any discovered determinism leak was fixed at source, or no leak was discovered.

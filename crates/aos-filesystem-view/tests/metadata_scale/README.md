# Userspace metadata-scale fixture

`metadata_scale` is a harness-free, single-thread test target requiring
`test-fixtures`. It measures the existing canonical structural-index builder,
validator and logical inode table. It activates no production connection,
FUSE installer, source membership, service, key or readiness gate.

Build and test only through the AOS dev shell, after obtaining the shared Cargo
lane and establishing the local-package freshness boundary documented in
`docs/maintainers/build-concurrency.md`. The small profile is selected without
arguments:

```sh
nix develop -c cargo test --manifest-path crates/Cargo.toml \
  -p aos-filesystem-view --features test-fixtures --test metadata_scale --jobs 2
```

Run the resulting test executable directly for the optional million profile;
do not use `cargo run`. Its ordinary test invocation creates 256 children. The
explicit `--million` invocation creates 1,000,000 children plus root, exactly
1,000,001 records. Set `AOS_METADATA_SCALE_HARDWARE_CLASS` and
`AOS_METADATA_SCALE_SOURCE_COMMIT` to label the execution; these are operator
labels, not verified hardware or source attestations.
Operator labels are limited to 256 bytes and the complete final report to
64 KiB. Child report reads have the same bound; read/decode failures reap only
the fixture's own child before temporary-file cleanup.

## Process and cleanup boundaries

The coordinator creates a private temporary directory, execs the builder and
waits for its exit before execing a fresh measurement worker. The builder uses
`StructuralIndexBuilder` and `IndexStaging<File>` with fixed-width sorted names,
shared borrowed metadata and empty-file content. Its synthetic source
descriptors are test-only. No million-element portable tree, `MemorySource`,
index byte Vec or construction heap is inherited by the measured worker.
`IndexStaging::new` uses its index-byte ceiling as its internal builder working
ceiling. The report names that cap explicitly: small CI narrows it to the
normal 256 MiB compiler working ceiling, while the opt-in million fixture uses
the existing 2 GiB index ceiling as its separately declared builder envelope.
This does not qualify the portable-tree compiler's 256 MiB working budget.

The worker streams the file through fixed scratch into a fully sealed memfd,
then uses the existing scoped `SealedMemfdMapping`. The mapping is **shmem**;
this is not filesystem page-cache, ZFS ARC or FUSE data/mmap evidence. It returns
only scalar observations. After tables and validation wrappers are dropped and
the mapping closes, requested-live bytes must return to the pre-mapping
baseline. The coordinator waits for worker exit and removes only the exact
generated file names and directory; there is no recursive cleanup.

## Validation envelope and refusal

The normal validator is never bypassed. Its checked reservation is
`encoded_index_bytes * 64 + 4096`, even though actual allocation may be smaller.
The small profile retains the normal `TreeCompileLimits::working_bytes`
ceiling. The million profile defaults to that same ceiling and can report a
validation refusal with no workload results. That is an observation, not a
successful million-node working-set qualification.

An explicitly supplied `--validation-envelope-bytes N` permits a separately
declared test-only envelope in the million profile. The selected cap is the
smaller of that envelope and the computed reservation. Choose a host/guest
resource envelope before running; this does not reserve physical memory and
must not silently change VM/image budgets or production limits. The report
records the reservation, cap, normal-ceiling refusal, validation peak and
validation resource snapshots independently of steady-state work. Allocation
failure, malformed data or unexpected refusal is an error, not a performance
pass. This initial slice adds no VM or fleet gate.

## Report interpretation

JSON uses `aos.filesystem.metadata-scale/v1`. Sixteen fixed raw batch samples
produce nearest-rank p50/p95/p99, mean and population variance. They are **batch
total latencies**, not individual kernel request quantiles. The report includes
operations per batch, architecture/kernel, profile, concurrency and warm-cache
scope. There is no numeric timing pass threshold. Negative storms execute
4,096 operations in the small profile and 1,000,000 in the million profile.

The shared allocator preserves the allocation-call assertions used by
`semantic_no_alloc`, and additionally counts globally live and phase-peak Rust
requested layout bytes with checked arithmetic. Those numbers exclude
allocator overhead and realloc's internal storage overlap. They are not RSS.
Separate bounded procfs observations report virtual/RSS/high-water bytes and
minor/major faults; RSS can retain freed allocator arenas. Reporting and
serialization run outside tracked operations; timing arrays and handle IDs use
fixed stack storage independent of tree size.

Retained working sets touch 0, 16 and 128 children. Failure-atomic checks cover
negative-state preservation, touched-node/reference/active-open/pending-open
ceiling-plus-one refusal, balanced FORGET, abort and release, and post-drop
requested-byte baselines. Inode handles are logical pins, not kernel FDs.

This fixture does not qualify production portable-tree compilation, real-kernel
FUSE, filesystem cache sharing/isolation, passthrough fallback, OOM containment,
memcg attribution, ARC/double caching or end-to-end native attachment.

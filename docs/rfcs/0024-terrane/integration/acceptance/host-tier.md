# T-HOST-1 requirement audit

This audit covers the 34 trunk requirements assigned to T-HOST-1 in the
[implementation plan](../05-implementation-plan.md). It records implementation
boundaries and the evidence still needed for acceptance. **T-HOST-1 remains
unaccepted.** Optional smart reassembly, discard and volatile storage are outside
this task.

The source inspection uses `0677eb432c`, including the publisher directory-open
correction. The four owning gates passed at `a7e05fa6cd`: independent review
checked all 8,258 immutable source files, ten retained Cargo executables,
twenty-one original ordered selectors and seventeen actual guests. That result
predates the directory-open correction. Qualification of the correction is
running; the earlier result does not establish its native behavior.

## Clause coverage

| Requirements | Inspected implementation | Required physical evidence and remaining limits |
| --- | --- | --- |
| HOST-1 | [NativeHostLayout][layout] retains the original root, provisioning exclusion and seven directory descriptors; requires one device and an allowed local filesystem; rejects symlink ancestry and replaced roots. | Filesystem identification alone is insufficient. The publisher must successfully enable and measure an actual seal. |
| HOST-2, HOST-14 | [Encoded sources][source], [admission custody][admission] and [verification][verification] bind encoded bytes, chunk identity, length, boundary and dictionaries before exposure or admission. | The native admission guest must establish actual temporary writes, synchronization and canonical insertion. |
| HOST-3 to HOST-5, OBJ-5 | [Native publication][publisher] closes writers, verifies the independent content claim, enables and measures verity, publishes without replacement and durably records its binding. [Adoption][adoption] independently verifies the existing original inode and binding. | Renewed native evidence is required for the directory-open correction. Full publisher deployment is also owned by T-HOST-2. |
| HOST-11 to HOST-13 | [Reassembly][reassembly] verifies the same ordered stream that reaches the output, including manifest identity, chunk boundaries and whole-file hashes. [Residence recovery][residences] verifies ranges and metadata independently. | Reassembly and eviction guests must prove source retention and dependent extraction. A plan object grants neither funding nor publication authority. |
| HOST-15 | [Read failure custody][corruption] latches denial across original aliases. The [physical worker][quarantine] retains the failed inode for publisher quarantine; [read-through][read-through] can fetch independently verified lower bytes. | Failed or uncertain quarantine retains custody and requires recovery. This evidence does not establish a scrub scheduler or complete structured security logging. |
| HOST-16 to HOST-21 | [Cache policy][policy] reserves before admission, implements bounded probation/main FIFOs, second chance, pins and grace. [Retirement][retirement] retains charges until physical completion. [Lower reads][driver] remain usable when admission fails. | Policy holds are distinct from measured allocation. Whole-pack retirement and exact accounting require the physical guests. |
| HOST-22, HOST-24 | [State][state] records pin owner, digest and expiry. [Snapshots][snapshot] require actual synchronization and bounded readback. The [worker][worker] sweeps before commands and on its one-second idle bound; [expiry][expiry] uses durable deadlines without applying grace twice. | Expired policy rows alone are insufficient: evidence must reach original-inode retirement and measured reclamation while the expired handle remains retained. |
| HOST-23, PROTO-60 | [Preparation][preparation] authenticates the configured owner, roots, project and epoch. [Native completion][completion] distinguishes allocation, charged/reserved usage and future holds. The [quota transport][quota] queries actual kernel state; [confinement][confinement] denies project setters across threads and descendants. | Trusted host identity isolation, provisioning and production boot ordering need separate deployment proof. Component confinement does not establish those host obligations. |
| HOST-25, HOST-27, DOM-18 | [Host configuration][configuration] rejects sealed zero-wipe before startup under D-128. Domain-bound [layouts][domain-layout] prevent cross-domain sealed reuse. The [signed read policy][read-policy] checks effective erasure requirements before content I/O. `none` means unlink; it never means overwrite. | The private-domain default remains `zero`, so unsupported sealed configuration must refuse rather than silently select `none`. Discard and volatile implementations remain optional worklines. |
| HOST-28 | [Pending recovery][pending], [physical retirement][retirement] and the [publisher channel][lifecycle] retain original custody, durable deadlines, no-replace names and restoration before final removal. Pack/index reconciliation preserves the original pair. | Unknown deadlines require a conservative recovery interval. Queue transitions do not prove deletion or release retained inode charges. |
| HOST-29, HOST-30 | [Embedded state][state] contains bounded policy and physical obligations, excluding reconstruction manifests, trees and indexes. [Sealed backing][backing] and its atomic [failure latch][corruption] do not enter embedded state or its command queue. | Exposure records describe retained pins and custody; they are not resumed execution or a content lookup index. |
| HOST-31 to HOST-34, BKT-15 | [NativeReady][ready] validates the complete portable bucket before and after actual recovery, compares its checkpoint and requires physical Resume. [Namespace recovery][namespace], [manifest recovery][manifests], [residence recovery][residences] and [pending recovery][pending] verify actual inventory before service. | Bare cache recovery is insufficient for BKT-15. Old exposures are not resumed. Writable upper recovery remains conditional on its owning surface implementation; production role deployment is still unqualified. |
| HOST-35, HOST-36 | The [native driver][driver] checks residents before lower routing, shares circuit state across clones and bounds the complete lower attempt. [Ordered fetch][fetch] skips open circuits and performs bounded probes. | This host-local composition does not establish a production remote Distribution backend or full T3 expression deployment. |

## Acceptance evidence

The owning gates remain `host-layout`, `host-verify-before-admit`,
`host-eviction-s3fifo` and `host-crash-recovery`. Their original selectors and
physical prerequisites remain mandatory. Shared compilation images and aggregate
results do not replace individual guest transcripts, retained Cargo artifact
identity or complete immutable source comparison.

The renewed six-gate dispatch, including the two T-HOST-2 gates, has been
compared with the previously reviewed dependency closures. All 86 missing
derivations retain the same execution contracts after normalizing only Nix store
hash prefixes; twenty are KVM checks. This is a dispatch audit, not a passing
runtime result. The separate base/all-feature cache qualification also remains
pending at the inspected source.

Acceptance requires reviewing those actual results and reconciling the deployment
and conditional-surface limits above. No requirement or task is accepted solely
because its source is listed in this audit.

[layout]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/mod.rs
[source]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/source.rs
[admission]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/admission/read_custody.rs
[verification]: ../../../../../crates/terrane/sdk/terrane-sdk/src/host/cache/verification.rs
[publisher]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_io/native.rs
[adoption]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/client/recovery.rs
[reassembly]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/reassembly.rs
[residences]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/recovery_residences.rs
[corruption]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/corruption.rs
[quarantine]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/retention/executor/corruption.rs
[read-through]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/read_through.rs
[policy]: ../../../../../crates/terrane/sdk/terrane-sdk/src/host/cache/policy.rs
[retirement]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/publication/eviction/lifecycle.rs
[driver]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/content/driver.rs
[state]: ../../../../../crates/terrane/sdk/terrane-sdk/src/host/cache/state.rs
[snapshot]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/snapshot.rs
[worker]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/retention.rs
[expiry]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/consumer/sweep.rs
[preparation]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/preparation.rs
[completion]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/consumer/state.rs
[quota]: ../../../../../crates/terrane/linux/terrane-linux/src/host_quota/socket.rs
[confinement]: ../../../../../crates/terrane/linux/terrane-linux/src/quota_confinement/policy.rs
[configuration]: ../../../../../crates/terrane/sdk/terrane-sdk/src/config/host.rs
[domain-layout]: ../../../../../crates/terrane/sdk/terrane-sdk/src/host/cache/layout.rs
[pending]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/recovery_pending.rs
[lifecycle]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/client/cache_lifecycle.rs
[backing]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/content/backing.rs
[ready]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/ready.rs
[namespace]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/recovery_namespace.rs
[manifests]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/recovery_manifests.rs
[fetch]: ../../../../../crates/terrane/sdk/terrane-sdk/src/host/cache/fetch.rs
[read-policy]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/content/presentation.rs

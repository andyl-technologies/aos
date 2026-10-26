# T-HOST-1 requirement audit

This audit covers the 34 trunk requirements assigned to T-HOST-1 in the
[implementation plan](../05-implementation-plan.md). It records implementation
boundaries and the evidence still needed for acceptance. **T-HOST-1 remains
unaccepted.** Optional smart reassembly, discard and volatile storage are outside
this task.

Current source inspection uses
`330e82243d9441a63e9fbbb7672b9e4fd6883041`. All four host owning gates pass
in 80.730 seconds after independently reviewed prerequisite construction in
401.661 seconds. Runtime review matches all 9,596 tracked source files, the
original three new selector guests and their three aggregates, and the already
qualified crash-recovery gate. All 21 original selectors retain their actual
SDK executable identity, UID/GID 840, empty supplementary groups, empty
capability sets, no-new-privileges, private ext4 storage and original deadlines.

The four gates consume seventeen distinct original KVM outputs and the same
ten physical prerequisites. Review binds the reused thirteen physical guests
and original crash-recovery selector guest to their source-qualified serial
hashes; they are not presented as new executions in this renewal. Twenty-three
outputs are preserved as 89 hashed regular files and three checked aggregate
aliases. Prerequisite review independently checks all thirteen guest dispatches,
including the fresh isolation probe, with host builds disabled. Seven raw
controller records are preserved and the exact owned scratch is removed.

Production and toolchain comparison with `42cb99b1a6` matches all 7,278 checked
Git entries, and the normative specification is unchanged. That comparison is
source equality only. The six newer Python verifier changes retain their own
guest-renewal obligation; no executable or runtime result is relabeled. These
complete gate results still require reconciliation with every assigned clause
below before accepting T-HOST-1.

The complete manager fixture at `874c01676f` passes in 218.935 seconds under
its original 300-second bound. Review matches all 8,266 immutable source files,
five retained Cargo executables, fifteen enrollment controls, and eighteen
actual mount observations for each of Serve and publisher. Actual PID 1 journal
records order both fresh confined GC processes after Serve readiness. Original
owner exclusion, foreign-peer refusal, listener retirement and durable snapshots
through acknowledged shutdown pass. Its renewed prerequisites pass in 1,471.441
seconds with all 96 remote derivations, both imported outputs, the fresh
capability-free ext4 sandbox proof and clean shutdown reviewed. This establishes
manager startup at that source; it does not establish later complete Serve
restart or draining physical exposure release. T-HOST-2 is now independently
accepted under the [publisher audit](publisher-role.md). This earlier manager
result does not renew current role execution or accept T-HOST-1.

## Clause coverage

| Requirements | Inspected implementation | Required physical evidence and remaining limits |
| --- | --- | --- |
| HOST-1 | [NativeHostLayout][layout] retains the original root, provisioning exclusion and seven directory descriptors; requires one device and an allowed local filesystem; rejects symlink ancestry and replaced roots. | Filesystem identification alone is insufficient. The publisher must successfully enable and measure an actual seal. |
| HOST-2, HOST-14 | [Encoded sources][source], [admission custody][admission] and [verification][verification] bind encoded bytes, chunk identity, length, boundary and dictionaries before exposure or admission. | The native admission guest must establish actual temporary writes, synchronization and canonical insertion. |
| HOST-3 to HOST-5, OBJ-5 | [Native publication][publisher] closes writers, verifies the independent content claim, enables and measures verity, publishes without replacement and durably records its binding. [Adoption][adoption] independently verifies the existing original inode and binding. | The renewed native guests qualify the directory-open correction at the recorded source. Later service mount behavior and full publisher deployment remain separately owned by T-HOST-2. |
| HOST-11 to HOST-13 | [Reassembly][reassembly] verifies the same ordered stream that reaches the output, including manifest identity, chunk boundaries and whole-file hashes. [Residence recovery][residences] verifies ranges and metadata independently. | Reassembly and eviction guests must prove source retention and dependent extraction. A plan object grants neither funding nor publication authority. |
| HOST-15 | [Read failure custody][corruption] latches denial across original aliases. The [physical worker][quarantine] reports the native failure and retains the failed inode for publisher quarantine; [read-through][read-through] can fetch independently verified lower bytes. | Failed or uncertain quarantine retains custody and requires recovery. Retention must end only after confirmation of another good copy or the quarantine deadline; HOST-15 does not prescribe a scrub scheduler or a structured log format. |
| HOST-16 to HOST-21 | [Cache policy][policy] reserves before admission, implements bounded probation/main FIFOs, second chance, pins and grace. [Retirement][retirement] retains charges until physical completion. [Lower reads][driver] remain usable when admission fails. | Policy holds are distinct from measured allocation. Whole-pack retirement and exact accounting require the physical guests. |
| HOST-22, HOST-24 | [State][state] records pin owner, digest and expiry. [Snapshots][snapshot] require actual synchronization and bounded readback. The [worker][worker] sweeps before commands and on its one-second idle bound; [expiry][expiry] uses durable deadlines without applying grace twice. | Expired policy rows alone are insufficient: evidence must reach original-inode retirement and measured reclamation while the expired handle remains retained. |
| HOST-23, PROTO-60 | [Preparation][preparation] authenticates the configured owner, roots, project and epoch. [Native completion][completion] distinguishes allocation, charged/reserved usage and future holds. The [quota transport][quota] queries actual kernel state; [confinement][confinement] denies project setters across threads and descendants. [Provisioning][quota-configuration] bounds the sum of finite project limits by the tier budget; the [configured opener][configured-cache] checks the authenticated ledger and complete domain partition before opening owners. | [Identity assertions][identity-checks] reject UID/GID aliases, foreign role-group members and other units using a role identity. [Service configuration][services] orders roles after the quota service and restricts writable paths, capabilities and process visibility. Actual current-source manager execution remains necessary to qualify deployment of these controls. |
| HOST-25, HOST-27, DOM-18 | [Host configuration][configuration] rejects sealed zero-wipe before startup under D-128. Domain-bound [layouts][domain-layout] prevent cross-domain sealed reuse. The [signed read policy][read-policy] checks effective erasure requirements before content I/O. `none` means unlink; it never means overwrite. | The private-domain default remains `zero`, so unsupported sealed configuration must refuse rather than silently select `none`. Discard and volatile implementations remain optional worklines. |
| HOST-28 | [Pending recovery][pending], [physical retirement][retirement] and the [publisher channel][lifecycle] retain original custody, durable deadlines, no-replace names and restoration before final removal. Pack/index reconciliation preserves the original pair. | Unknown deadlines require a conservative recovery interval. Queue transitions do not prove deletion or release retained inode charges. |
| HOST-29, HOST-30 | [Embedded state][state] contains bounded policy and physical obligations, excluding reconstruction manifests, trees and indexes. [Sealed backing][backing] and its atomic [failure latch][corruption] do not enter embedded state or its command queue. | Exposure records describe retained pins and custody; they are not resumed execution or a content lookup index. |
| HOST-31 to HOST-34, BKT-15 | [NativeReady][ready] validates the complete portable bucket before and after actual recovery, compares its checkpoint and requires physical Resume. The [configured opener][configured-cache] constructs this value for every configured domain before returning its content store. [Namespace recovery][namespace], [manifest recovery][manifests], [residence recovery][residences] and [pending recovery][pending] verify actual inventory before service. | Bare cache recovery is insufficient for BKT-15. Portable validation and native custody are separate obligations, reconciled below. Old exposures are not resumed. Writable upper recovery remains conditional on its owning surface implementation; production role deployment is still unqualified. |
| HOST-35, HOST-36 | The [native driver][driver] checks residents before lower routing, shares circuit state across clones and bounds the complete lower attempt. [Ordered fetch][fetch] skips open circuits and performs bounded probes. | This host-local composition does not establish a production remote Distribution backend or full T3 expression deployment. |

## Acceptance evidence

The owning gates remain `host-layout`, `host-verify-before-admit`,
`host-eviction-s3fifo` and `host-crash-recovery`. Their original selectors and
physical prerequisites remain mandatory. Shared compilation images and aggregate
results do not replace individual guest transcripts, retained Cargo artifact
identity or complete immutable source comparison.

The current four-gate preflight leaves exactly eighteen original derivations:
twelve packaging prerequisites, three KVM selector guests and three aggregates.
After guest-only prerequisite construction, the repeated preflight leaves
exactly those six deferred runtime derivations. Runtime review checks all six
original derivations, four gate outputs, each selector transcript, the source
image and its retained Cargo artifact. The crash-recovery gate's separately
reviewed dependencies retain their original source and execution attribution.

### Portable validity and native readiness

BKT-15 requires the disk tier's durable state to remain a valid `file://`
bucket extended only by the registered host prefixes. It does not require an
allocation role to reopen the bucket's administrative publication authority.
The initial-enrollment transcript records `capabilities-update` as an
unqualified actual Original native-fence refusal. That result remains a refusal;
the enclosing guest's success supplies no positive administrative reopening proof.

The independent [portable validator][portable-validation] reuses the complete
portable-copy validators through a bounded native filesystem binding that denies
every mutation. It captures the selected portable pointer, capabilities,
history, generation manifest and payload through the same retained descriptors,
then checks capture continuity before returning. Its private `Access::Writable`
tag selects the existing layout-two validators; the binding supplies no write,
initialization, repair, lock or publication-control operation. The returned
snapshot retains neither pack bodies nor serving authority.

The configured native opener combines portable validation with authenticated
quota and publisher custody, recovery of the original inventory and completed
physical Resume. Validation runs before cache initialization and again after
recovery. The opener
compares the before/after checkpoint before returning `NativeReady`. This is the
composition exercised by the separately qualified configured SDK guests consumed
by the current host gates. Seven of their original physical guests record 24
explicit portable-validation, recovery and Resume witnesses across the public
and private fixture domains. The fixture also repeats portable validation after
its populated native content operations. These are the original reviewed
transcripts, not additional executions. A decoded portable observation or a bare
recovery result cannot construct the private readiness value. This evidence applies to
portable validity and the configured native opener; it does not establish full
Serve restart or conditional surface recovery.

Separate base/all-feature native cache renewal at `31aa0ae05f` passes in
3,235.284 seconds. Each profile matches 8,263 immutable source files, four
retained Cargo executables and three original guests. Base/all-features execute
130/258 ordinary cases and five creator cases per profile. All five allocation
mount controls and the original recovery, finite-consumer expiry, physical
eviction and measured charge-release witnesses pass. The expired handle remains
retained through physical release. This component evidence qualifies the setgid
correction; it does not establish later service mount deployment or complete
role behavior.

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
[portable-validation]: ../../../../../crates/terrane/sdk/terrane-sdk/src/bucket/portable_reader/native.rs
[configured-cache]: ../../../../../crates/terrane/linux/terrane-linux/src/configured/cache.rs
[quota-configuration]: ../../../../../modules/terrane/_host-quota.nix
[identity-checks]: ../../../../../modules/terrane/_identity-checks.nix
[services]: ../../../../../modules/terrane/host.nix

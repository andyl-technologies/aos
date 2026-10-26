# T-STORE-3 shared-directory audit

This audit inspects the implementation at
`330e82243d9441a63e9fbbb7672b9e4fd6883041`. It does not accept T-STORE-3.
The complete `shared-dir-read-only` and `dom-host-isolation` owning gates
require current-source execution and independent review. Their results must
then be reconciled with all six assigned requirements below.

## Requirement coverage

| Requirement | Inspected implementation | Required evidence and limits |
| --- | --- | --- |
| STORE-14 | [Shared views][shared] open existing non-private host content through the concrete verified reader. `put` returns `ReadOnly` before consulting the directory. Reads allocate temporary response data without admitting content or creating viewing-instance reservations. | The original seven read-only selectors must preserve directory bytes and names, reject corrupt content without repair, verify complete chunks before ranged responses, retain canonical manifest metadata, and exercise residence fallback. The separate actual setgid-mode guest must pass. A portable residence callback alone establishes no native seal or physical custody. |
| DOM-12 | [Host layouts][layout] bind one physical root to a configured domain. [Routes][routes] reject overlapping paths and roots observed as the same device/inode. Native publication supplies domain-bound immutable backing. | The original isolation selectors must retain one existing inode for authorized consumers of the same domain and refuse aliases and symlink crossings. Genuine native publication/reassembly evidence remains necessary for sealed backing and page-cache sharing; a routing table alone does not establish those properties. |
| DOM-13 | [Routes][routes] select one configured shared directory using the guard-issued effective root domain. Unknown domains have no fallback, including to `public`; unreachable identities are filtered before membership lookup. | The original isolation selectors must prove that another directory and unreachable hashes are never probed. The enclosing repository must obtain and close current authorization around each disclosure. Retaining a routing table or an old domain decision grants no later read authority. |
| DOM-14 | Shared routes preserve one selected domain per operation; [publication][publication] binds each sealed object to its configured domain. | These backend checks alone do not prove mixed-domain shared-realization admission. Production FUSE/worker integration must establish that every consumer can access every domain represented by any shared backing directory. EROFS and VM surfaces remain separate worklines. No global DOM-14 conformance follows from the two backend gates. |
| DOM-15 | [Shared views][shared] reject private domains before opening their roots. [Consumer maintenance][consumers] schedules private retirement independently of FIFO pressure. [Physical retirement][retirement] retains original jobs, descriptors and funding through publisher acknowledgment and actual accounting. | The three original private-release guests must prove independent-consumer protection, refusal after lease release, actual private unlink, retained backing and quota, and a measured charge decrease after backing closes. Cold inline and manifest recovery must preserve the original public inode. These finite scenarios do not by themselves prove crash recovery or final release of arbitrary retained kernel mappings. |
| HOST-27 | Each shared view and published body remains bound to one configured domain. Sealed tiers reject unsupported zero-wipe configuration under D-128. | Isolation must preserve distinct physical domain custody. Configuration refusal must precede resource mutation; a wipe-policy mismatch cannot silently select another domain or deduplicate across domains. The supported sealed-tier policy is `none`; this grants no conformance for future wipe strategies. |

## Qualification checkpoint

At the inspected source, both SDK images and all twelve remaining non-KVM
prerequisites pass independent source, executable and guest-dispatch review.
Both native-builder probes retain the original unprivileged ext4 controls;
fourteen raw records are preserved and owned controller scratch is removed.

Complete owning-gate renewal stops in 164.316 seconds after the three original
private-release guests pass. The 512 MiB portable shared-mode guest OOM-kills
its UID-840 Python verifier before native execution: the helper reads its
466,280,768-byte executable to check the four-byte ELF header. Independent
failure review and raw VM records preserve that result. Header reads are now
bounded to four bytes; the common SDK verifier streams the full SHA-256.
Metadata-only verification of both actual retained executables preserves their
prior hashes with measured Python peak allocations below 12 MiB. No guest
memory, filesystem, privilege, selector or deadline control changes. Renewed
original native execution remains required.

Compilation, retained executable hashes, finite selector results and complete
gate results are distinct evidence. Neither successful image construction nor
earlier component qualifications accept this task. Original guest identities,
filesystem and quota controls, selectors and deadlines must remain intact.

Acceptance also requires resolving the DOM-14 realization boundary and the
DOM-15 physical-lifetime limits above. The assigned requirement IDs are
obligations, not a conformance claim established by a green gate name.

## Realization and lifetime enforcement

Source review at `9efbf29becbda14f9ac58c1a820cde63a3f8d050` identifies the
following enforcement paths. They are separate from the backend gate renewal
and do not constitute new native execution evidence.

For DOM-14, [full-root preparation][root-read] expands graft paths and requires
ordinary Read for every path under one unchanged complete live policy record.
The [path evaluator][read-guard] resolves each path's signed effective domain
and checks the token against that domain and its containing policy root.
The selected physical domain returned by `storage_domain()` is the enclosing
snapshot's domain; that accessor alone does not establish permission for all
graft domains. The per-path checks establish those permissions for the
particular invocation.

[Native index preparation][scoped-index] validates every expanded path's
storage policy before admission, binds the index to the selected physical
domain, and closes the original full-root Read before returning a mapping.
For a later worker, [index disclosure][worker-channel] requires a fresh
`PreparedRootRead`; the native bridge compares its commit, root and physical
domain with the original served index, checks the original exposure, and
closes that fresh Read before returning backing for the serialized send.
Possession of the index or an exposure receipt therefore does not replace
this consumer's repository authorization.

End-to-end acceptance still needs the production registration and worker path
to bind each requesting consumer to its own verified repository credentials.
Native qualification must exercise a mixed-domain graft, an authorized
consumer and a consumer missing one domain, including policy change between
preparation and disclosure. Existing root-only attenuation and policy-advance
cases establish narrower boundaries; they do not substitute for that scenario
or prove that every production consumer traverses this path.

For DOM-15, [exposure reconciliation][closure] accepts only the original
draining generation and its bounded inode bindings in the configured
filesystem and project. It removes exposure pins and leases only after
`exposure_inodes_closed` succeeds. The underlying [project census][census]
holds every counted, non-excluded inode through a fresh kernel quota query;
equality with the project's charged inode count establishes that none of the
excluded original inodes remains charged. An incomplete census or an uncounted
charged inode delays release. Expiry, a disconnected worker and disappearance
of a pathname do not establish closure.

The remaining lifetime evidence must follow the actual production worker
through drain and recovery while another process retains a descriptor or
mapping, then close the final reference and measure physical retirement and
charge release. The three private-release backend guests do not exercise
that complete exposure lifecycle. D-133's retained-passthrough semantics must
remain intact throughout this qualification.

[shared]: ../../../../../crates/terrane/sdk/terrane-sdk/src/store/shared_dir/mod.rs
[routes]: ../../../../../crates/terrane/sdk/terrane-sdk/src/store/shared_dir/domains.rs
[layout]: ../../../../../crates/terrane/sdk/terrane-sdk/src/host/cache/layout.rs
[publication]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_io/native.rs
[consumers]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/consumer/sweep.rs
[retirement]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/publication/retirement.rs
[root-read]: ../../../../../crates/terrane/sdk/terrane-sdk/src/repository/root_nodes.rs
[read-guard]: ../../../../../crates/terrane/sdk/terrane-sdk/src/guard/read.rs
[scoped-index]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/surface_index/scoped.rs
[worker-channel]: ../../../../../crates/terrane/linux/terrane-linux/src/worker_channel/mod.rs
[closure]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/surface_index/closure.rs
[census]: ../../../../../crates/terrane/linux/terrane-linux/src/host_quota/census.rs

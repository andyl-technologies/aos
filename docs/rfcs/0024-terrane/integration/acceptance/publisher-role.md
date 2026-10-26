# T-HOST-2 publisher role audit

T-HOST-2 is accepted at frozen
`330e82243d9441a63e9fbbb7672b9e4fd6883041` after the complete
`publisher-sole-writer`, `host-publish-sequence` and separately required
`host-crash-recovery` gates pass and the ten clauses below are reconciled.
This accepts the publisher component; complete host readiness, other process
roles and intertier services remain separate obligations.

## Requirement coverage

| Requirement | Inspected implementation | Qualified evidence and limits |
| --- | --- | --- |
| HOST-6 | [Configured startup][configured] installs publisher confinement before opening native resources. [Native roots][native] retain directory custody; other roles receive read-only backing through the [local socket][socket]. | Qualified by seven distinct kernel role identities, six non-publisher namespace-refusal controls, actual read-only backing handoff and irreversible publisher confinement before resource startup. Startup audits inherited descriptors; trusted host standard-I/O policy remains required. |
| HOST-7 | [Publication sequencing][sequence] stages, verifies the independent content claim, closes writers, seals, synchronizes, inserts without replacement, synchronizes the parent and records the binding before returning backing. Failed completion attempts inode-checked rollback. Adoption independently verifies the seal and plaintext and refuses conflicting recorded bindings. | All twelve portable ordering/fault cases and ten native publication selectors pass, including actual binding failure, rollback and retained physical-owner completion. Configured native inline and manifest reassembly also pass; manifest identity remains distinct from assembled plaintext. |
| HOST-8 | [Native staging][native] copies the source into a newly created publisher-private inode. It does not reflink the source. The private copy is verified before writers close and sealing starts. | The inspected implementation uses a verified private copy and no reflink. The conditional reflink permission is unused; introducing that path would require its additional source immutability and domain checks. |
| HOST-9 | [Publication sequencing][sequence] handles an existing canonical name by independently adopting it. [Native insertion and rollback][native] use retained directory/inode custody and no-replace operations. | Native collision, adoption, recovery and domain-isolation controls pass. Adoption independently checks the existing seal and claim; cleanup and partial-retirement controls preserve preexisting or replacement inodes. |
| ARCH-5 | The [server][server] and [closed codec][validation] implement the registered `publisher-local-v1` operations. The configured publisher opens no Store, repository or backend credentials. | Qualified for the registered publisher boundary by the closed codec, twelve pure transport cases and native transport guests. Publisher operations expose no alternate Store/ref/repository API. Other registered local transports and intertier services retain their own conformance obligations. |
| ARCH-8 | [Configured startup][configured], [native publication][native] and [publisher confinement][confinement] keep sealed namespace effects in the publisher role. | The complete ownership gate passes with source-bound actual executables and original privilege controls. All six non-publisher fixture identities are denied sealed namespace mutation; native handoff cannot be reopened writable. |
| PROTO-56 | [Sockets][socket] use connected Unix sequenced packets and passed descriptors. The [codec][validation] accepts only the registered version, direction and operation fields. | The exact twelve portable transport cases and native multi-identity/lifecycle guests pass for registered Unix sequenced packets and descriptor exchange. HTTP authentication and intertier forwarding are outside this transport. |
| PROTO-57 | [Sockets][socket] authenticate actual kernel peer credentials against distinct configured role identities, validate received descriptor access/type and retain close-on-exec files. [Server claim conversion][server] independently constructs domain-bound publication claims. | All seventeen socket cases pass, including kernel credentials, spoofing, domain selection, descriptor rejection and protected listener retirement. Role authentication grants no repository authority; guarded repository reads still authorize each disclosure. |
| PROTO-58 | [Connection owners][shutdown] retain and join accepted work. A [server wait deadline][server] awaits actual native completion even when its reply fails. The [native worker][worker] owns its runtime and retained roots independently of the caller. | Current cancellation, joined physical completion, listener-retirement and new-cache recovery controls pass. The separately named crash-recovery gate consumes fourteen source-bound KVM guests and all ten original physical prerequisites. Managed publisher-restart execution retains its earlier source attribution; full Serve restart and general physical-release conformance are separate. |
| PROTO-59 | [Validation][validation] closes the operation/descriptor matrix. [Server dispatch][server] converts registered content keys and configured domains into native operations; callers supply no filesystem path or callback. [Publication/adoption][sequence] precedes returned backing. | Registered operation/descriptor checks and native no-replace, domain, incarnation and partial-retirement controls pass. Returned backing follows verified publication/adoption. Quarantine inspection descriptors remain unverified and cannot become serving authority. |

## Qualification checkpoint

At frozen `10699f7b5d`, the original focused KVM checks pass in 42.470 seconds:
all seventeen socket cases and ten publication selectors execute with their
original privilege and filesystem controls. The independently reviewed,
unmodified manager guest passes in 191.360 seconds with fifteen enrollment
controls, complete initial publisher readiness, fresh publisher process and
listener identities, and two clean stops. Required application-target
compilation separately passes in 703.613 seconds for 190 targets across 59
packages; compilation establishes no execution.

At frozen `330e82243d`, both complete owning gates pass in 1,216.385
seconds. Independent review matches all 9,596 tracked source files, 8,297
immutable image-source files, 5,535 cache-image inputs, the actual retained
Cargo executables and all eleven originally missing derivations. All eight
original KVM guests pass: publication, cache units, recovery, eviction,
multi-identity transport, native transport, enrollment and reassembly. The
cache unit guest executes exactly 135 ordinary and five administrator cases
with its original ext4, identity, empty-capability and no-new-privileges controls.

The current transport executes all seventeen socket cases and twelve pure
protocol cases. The publication guest executes all ten original selectors,
including cancellation through actual binding durability and failed-binding
rollback. Seven distinct kernel role identities retain the original six
non-publisher namespace-refusal controls; native handoff remains read-only
and cannot be reopened writable. Enrollment and reassembly retain all fifteen
common controls, fresh quota queries and distinct sealed inodes. Their original
capabilities-update refusal remains explicitly unqualified. These results do
not supply a global NativeReady or physical-release claim.

Earlier renewal attempts exposed two stale expected inventories: five listener
retirement cases and the recorded `host_cache_mount_views_vm.py` helper. The
corrections preserve every original case and exact input equality. Independent
review preserves each refusal and its attribution. The successful run's eleven
original outputs are retained as 39 hashed regular files and three checked
cache-aggregate symlink records. The reviewer's initial assumption that every
aggregate result begins with `PASS` is also preserved; the original publication
aggregate's exact descriptive success message is checked against its source.
No original runtime assertion or guest resource limit changes.

The separately required `host-crash-recovery` gate passes at the same frozen
source in 599.483 seconds. Independent review verifies all six remaining KVM
guests and both aggregates, the four original recovery selectors, and the
complete ten-entry physical prerequisite list. That list expands to thirteen
actual cache/enrollment/SDK/release/pressure guests; the selector guest makes
fourteen. Together with the publisher owning gates, seventeen distinct
original KVM outputs pass. All original SDK positive/refusal, read-only namespace,
wipe-refusal, private-release and cold-pressure controls remain intact.
Seventeen consumed outputs are preserved as 65 hashed regular files and three
validated aggregate symlink records.

All 7,278 production/build/module Git entries and the normative specification
remain identical through `806f6b98a5`. That commit changes only SDK image
verification memory use and checkpoint documentation. This source comparison
does not relabel the earlier manager execution or claim equal executable bytes
across different builds. The managed publisher-restart result remains at
`10699f7b5d`; complete Serve restart is still unqualified.

The separate 194.410-second warm Serve-restart observation at `10699f7b5d`
preserves the original units, credentials, endpoints, configuration and limits.
A third fresh publisher reaches readiness, while Serve exits at SDK
presentation with status 1. Existing snapshots retain their bytes and inode
metadata. This is a qualified failure observation, not Serve restart acceptance.
SDK checkout still requires a new private directory; deleting or reusing the
completed snapshots would not qualify that original contract.

These three complete gate results, retained source/executable reviews and the
ten-clause reconciliation accept T-HOST-2. They do not accept T-HOST-1, other
process roles, intertier services or global architecture conformance. The
capabilities-update refusal and full NativeReady limits recorded above remain.

[configured]: ../../../../../crates/terrane/linux/terrane-linux/src/configured.rs
[native]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_io/native.rs
[socket]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/socket.rs
[sequence]: ../../../../../crates/terrane/sdk/terrane-sdk/src/host/publication/sequence.rs
[server]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/server.rs
[validation]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/validation.rs
[confinement]: ../../../../../crates/terrane/linux/terrane-linux/src/quota_confinement/publisher.rs
[shutdown]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/server_shutdown.rs
[worker]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_io/worker.rs

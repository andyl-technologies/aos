# T-HOST-2 publisher role audit

This audit inspects the publisher implementation at
`d70df3c1a2d4558c84322ec7acca21f66ee8a146`. It does not accept T-HOST-2.
The complete `publisher-sole-writer` and `host-publish-sequence` owning gates
still require renewal at this source. Passing a focused component check does
not replace either gate or the clause review below.

## Requirement coverage

| Requirement | Inspected implementation | Required evidence and limits |
| --- | --- | --- |
| HOST-6 | [Configured startup][configured] installs publisher confinement before opening native resources. [Native roots][native] retain directory custody; other roles receive read-only backing through the [local socket][socket]. | The ownership gate combines actual role permissions, native descriptor handoff and publisher confinement. Managed-role evidence must retain the original Serve read-only mounts and publisher namespace controls. A read-only pathname does not prove that an inherited writable descriptor is absent. |
| HOST-7 | [Publication sequencing][sequence] stages, verifies the independent content claim, closes writers, seals, synchronizes, inserts without replacement, synchronizes the parent and records the binding before returning backing. Failed completion attempts inode-checked rollback. Adoption independently verifies the seal and plaintext and refuses conflicting recorded bindings. | The sequence gate requires all twelve portable fault cases and all ten original native publication selectors, including binding failure and retained physical-owner completion. Inline and manifest identities must remain distinct; a one-chunk manifest cannot become an inline claim. |
| HOST-8 | [Native staging][native] copies the source into a newly created publisher-private inode. It does not reflink the source. The private copy is verified before writers close and sealing starts. | The conditional reflink permission is unused. Source mutation cannot substitute unverified bytes after the private-copy verification. This establishes no permission to introduce a future reflink path without its additional immutability and domain checks. |
| HOST-9 | [Publication sequencing][sequence] handles an existing canonical name by independently adopting it. [Native insertion and rollback][native] use retained directory/inode custody and no-replace operations. | Native collision, recovery and domain-isolation controls must pass. Successful adoption requires the existing seal and content claim; cleanup must preserve a preexisting or replacement inode. |
| ARCH-5 | The [server][server] and [closed codec][validation] implement the registered `publisher-local-v1` operations. The configured publisher opens no Store, repository or backend credentials. | This audit covers the assigned publisher boundary. It does not establish conformance of other registered local transports or the separate intertier services. No publisher command may become an alternate store/ref/repository API. |
| ARCH-8 | [Configured startup][configured], [native publication][native] and [publisher confinement][confinement] keep sealed namespace effects in the publisher role. | The complete ownership gate must verify the retained actual executables and original privilege controls, rather than infer exclusivity from the Rust interface or module rendering alone. |
| PROTO-56 | [Sockets][socket] use connected Unix sequenced packets and passed descriptors. The [codec][validation] accepts only the registered version, direction and operation fields. | The ownership gate retains the exact portable transport inventory and native multi-identity/lifecycle guests. HTTP authentication and intertier forwarding are outside this transport. |
| PROTO-57 | [Sockets][socket] authenticate actual kernel peer credentials against distinct configured role identities, validate received descriptor access/type and retain close-on-exec files. [Server claim conversion][server] independently constructs domain-bound publication claims. | All seventeen socket cases are required, including credential spoofing, domain selection, descriptor rejection and listener retirement. Role authentication grants no repository authority; the separate repository read path remains responsible for authorization before disclosure. |
| PROTO-58 | [Connection owners][shutdown] retain and join accepted work. A [server wait deadline][server] awaits actual native completion even when its reply fails. The [native worker][worker] owns its runtime and retained roots independently of the caller. | The original cancellation, binding-durability, recovery and native lifecycle controls must pass. Clean publisher restart requires a fresh process/listener identity after the original listener retires. Publisher restart alone establishes neither Serve restart recovery nor final physical charge release. |
| PROTO-59 | [Validation][validation] closes the operation/descriptor matrix. [Server dispatch][server] converts registered content keys and configured domains into native operations; callers supply no filesystem path or callback. [Publication/adoption][sequence] precedes returned backing. | Native no-replace, domain, incarnation and partial-retirement controls must preserve replacement inodes. A returned quarantine inspection descriptor remains unverified and cannot become serving authority. |

## Qualification checkpoint

At frozen `10699f7b5d`, the original focused KVM checks pass in 42.470 seconds:
all seventeen socket cases and ten publication selectors execute with their
original privilege and filesystem controls. The independently reviewed,
unmodified manager guest passes in 191.360 seconds with fifteen enrollment
controls, complete initial publisher readiness, fresh publisher process and
listener identities, and two clean stops. Required application-target
compilation separately passes in 703.613 seconds for 190 targets across 59
packages; compilation establishes no execution.

The owning-verifier correction at `5c4a228973` adds the five retirement cases
to its expected socket inventory. It does not change the Rust implementation
or qualify the complete owning gates. Renewal at `d70df3c1a2` must include this
corrected verifier and the original full dependency graph.

That renewal stops during AOS prerequisite construction in 525.215 seconds:
the host-cache image's separate native source inventory omits the same five
publisher retirement cases. All original cases remain declared. The inventory
correction preserves them and requires 135 ordinary base cases or 263 ordinary
FUSE-profile cases, with the original five administrator creator cases in each
profile. Both source contracts pass; native image construction and complete
owning-gate renewal still require a fresh run. The failed run's raw records and
independent attribution review remain preserved.

The separate 194.410-second warm Serve-restart observation at `10699f7b5d`
preserves the original units, credentials, endpoints, configuration and limits.
A third fresh publisher reaches readiness, while Serve exits at SDK
presentation with status 1. Existing snapshots retain their bytes and inode
metadata. This is a qualified failure observation, not Serve restart acceptance.
SDK checkout still requires a new private directory; deleting or reusing the
completed snapshots would not qualify that original contract.

Acceptance requires complete current-source gate results, their source and
actual-executable review, and reconciliation of every clause above. These
results do not accept T-HOST-1, other process roles, protocol services or global
architecture conformance.

[configured]: ../../../../../crates/terrane/linux/terrane-linux/src/configured.rs
[native]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_io/native.rs
[socket]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/socket.rs
[sequence]: ../../../../../crates/terrane/sdk/terrane-sdk/src/host/publication/sequence.rs
[server]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/server.rs
[validation]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/validation.rs
[confinement]: ../../../../../crates/terrane/linux/terrane-linux/src/quota_confinement/publisher.rs
[shutdown]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_local/server_shutdown.rs
[worker]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_io/worker.rs

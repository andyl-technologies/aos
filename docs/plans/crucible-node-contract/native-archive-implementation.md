# Installed native archive implementation

The generic archive in `crates/crucible/src/node_state/native/` preserves native
owners through the existing complete-world capture admission and inactive restore
transaction. Its edition, authentication domain and files are independent of the
existing host archive. A native process image is preservation data; it does not
grant fresh execution or establish that a restored peer has the required native
closure.

## Capture boundary and ownership

`SimulationNode::capture_native_continuation` defaults to refusal.
`InstalledNativeCapture` can only be constructed by installed adapters inside
Crucible. The host adapter explicitly bridges its existing sealed native capture;
other implementations must retain their own authentic native proofs.

`NodeRuntime::capture_installed_native` checks the original runtime before and
after capture. It derives the exact participant roster for each capture owner from
the admitted graph, checks every participant's declared roster, and invokes that
owner once. A public node view does not constitute independent state ownership.
The result must match all participants' implementation and state schema bindings.
The collector reserves its complete result roster and validates every participant's
actual descriptor, binding and thread affinity before the first native hook.
Subsequent hooks receive only remaining world credits for records, streamed files
and objects; individual record/file ceilings cannot exceed those remaining totals.
Installed hooks must preflight their required reservation before mechanical native
effects. Exhausted mandatory state-object credit prevents another hook entirely.

The capture cut is the original complete coordinator `Position` and ordinal.
A backend may have latent native progress from an original pending operation.
Its codec must preserve the actual native position, original operation authority
scope, all immutable prefixes, outputs and ACK knowledge. It must not execute,
drain queues or move the native cursor to make that cursor appear equal to the
coordinator cut. Mechanical checkpoint work may change process implementation
details while the complete modeled state remains unchanged.

`NativeArchive::capture_world` retains all required immutable references, the
complete runtime and scheduler, and every scheduler-owned payload. It verifies
the runtime and scheduler again after native capture. Installed source and
coordinator authentication through `NativeWorldFactory` must succeed before the
archive signs an index. Unowned extra core objects are refused.

## Persistent format and streamed files

The private index is a closed, duplicate-strict JSON record:

```text
body.schema_version = 1
body.artifact = complete capture-manifest ContentRef
body.objects = pages of small core object references and dependencies
body.owners = complete authoritative capture-owner roster
authentication = 32-byte HMAC-SHA256 of the canonical body and archive domain
```

Each owner binds an implementation ID, operating profile ID and state schema;
its exact participants and common cut; the small native ledger and evidence; and
every native artifact's role, checked relative reconstruction name and complete
`ContentRef`. The ordinary capture-owner receipt hashes that entire inventory.
File inventories use pages of at most 256 entries without relaxing the public
canonical parser's per-array limit. An arbitrary backend-native ledger can retain
opaque operational rebinding hints; the generic archive does not interpret those
hints as host paths or portable artifact identities.

Native images and resource files are streamed through descriptor-owned
`NativeCaptureArtifact` values. Their canonical BLAKE3 framing matches
`canonical::content_ref` without allocating a whole image. Independent readers
use positional reads and do not share a seek cursor. The archive verifies full
bytes before publishing a CAS object, then synchronizes both file and directory.
Existing objects must match exactly. Load verifies the signed roster and all
native image/resource streams again. Native file references cannot be read as
small core objects through `NativeArchiveRecord::object_bytes`.

The archive directory is private to its effective UID. Its separate persistent
32-byte key is a private, regular, single-link file. Incomplete key creation is
refused on reopen. Retaining this key permits a daemon restart to authenticate
the same local archive; copying an index to a different archive key does not.
Core records, index metadata, file counts, individual file sizes, aggregate bytes
and restore resources all have independent finite limits. Native image files
never enter a JSON byte array. Immutable executable closure currently enters
the bounded core content verifier, so an installed profile must select explicit
measured core byte limits that hold its complete executable/tool closure.

## Inactive restoration and authority

`AuthenticatedNativeSource` is an archive-provenance seal with no public raw
constructor. It binds the owner's original ledger to the exact saved runtime and
authenticated core closure. `NativeWorldFactory::authenticate_source` validates
the installed backend codec and complete native artifact coverage;
`authenticate_coordinator` validates the complete cross-owner queues, payloads,
credits, reservations and transfer history.

`NativeWorldRestoreDriver` checks the unchanged world and backend bindings,
authenticates each owner once, and sums all peak reservations with checked
arithmetic. The factory creates an empty, nonautonomous staging capsule. The
driver installs it into `PreparedRestoreAllocation` under a pre-reserved
whole-world supervisor and verifies that it retains exactly the computed budget.
Only subsequent owner preparation may allocate native processes or helpers.
Partial allocations and the complete source remain in owning custody until
authentic reclamation finishes.

The existing restore transaction prepares all owners and the coordinator before
the replacement activation barrier can publish the complete world. A fresh
backend must requalify its actual live native closure and rebind continuation
through authentic local admissions. Historical receipt scopes remain historical;
saved native permissions and source certificates cannot be reused as fresh live
authority. A codec or factory without this proof continues to refuse durable
continuation.

## Verification scope

The generic storage tests exercise descriptor reads after the original file is
removed, persistent key reopening, independent stream cursors, changed bytes,
failed stream publication, independent key refusal and backend-metadata
authentication. These tests do not qualify a backend. Mixed host/native whole
world source-death, independently fresh restore scopes and unchanged future
output witnesses belong to the installed native factory's integration checks.

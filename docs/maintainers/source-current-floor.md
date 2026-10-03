# Local current Source floor

The RFC's selected fresh-install profile trusts protected Root state and
kernel/PID1. Root is independent of the Controller-owned Source writer; it is
not a hardware or off-host anchor and does not protect against rollback of the
whole host disk. Storage's method46 TPM floor remains unrelated and unchanged.

The real `RootSourceGenesisAuthorityV1` now derives a non-detachable
`CurrentRootSourceGenesisFloorV1` from its actual stored generation-one floor.
There is no constructor from a project, decoded record, structural
`AnchoredStructurally` classification, supplied key or signature alone.
Selection uses the already verified Controller completed readback. The owner
rechecks its fixed protected names, immutable role pins and complete semantic
history, then verifies the separately pinned Source answer under its original
Root challenge. That answer must be Anchored and match the exact receipt,
materialization and ACK floor digest; a Prepared receipt cannot qualify.

The actual normal Root stream continuation retains this owner borrow from
confirmation through Completed and the client's Finish acknowledgement.
Reads/writes borrow the same original socket; no duplicate or delegated server
FD is introduced. Original stream shutdown still precedes Root writer release
on success, error or unwind. Controller and Source retain their original
writers through that flight. Rechecking a saved signature outside such a held
cross-owner interval is not fresh Source currentness.

This is only the gen1 Source-floor component of a future Root-last barrier.
It supplies no Controller-side image/peer/current-invocation/nondelegation
proof, Policy/compiler authority, current Publisher/revocation history, Cache
read grant, assignment/lease, or connected worker disclosure guard. Public
Create, FUSE reads and the opaque client proof constructor remain closed.
An administrative historical recovery does not authorize a fresh mutation.

Later generations need a distinct administrative transition profile binding
the operation, prior Tree and lineage, exact next Tree/lineage/receipt,
administrative issuer epoch, current Controller/publisher/authorization cuts,
Root instance, predecessor semantic floor and reserved settlement suffix.
Reuse the existing contiguous Tree planner and Root-last journal CAS, but do
not promote the structural floor reducer or gen1 receipt into that authority.
Every Tree/lineage/receipt/pending/ACK writer and compaction/replay path must
honor the exact pending transition before such a successor is admitted.

The authored tests use actual protected Source append, read-only signed
observation, ACK, compaction and cold reopen. They deliberately do not mint the
production Root token or install fixed Root credentials. Compilation, live
normal-Root owner construction, installed original-flight qualification and
the independent remaining read-barrier joins are still pending.

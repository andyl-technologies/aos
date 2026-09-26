# Storage native held-snapshot readback status

Storage can select one snapshot from its authenticated transaction journal,
derive the latest exact HoldSnapshot transition, and require the protected
catalog cut to remain unchanged across a one-shot ZFS GUID and hold probe. It
also derives the source root-policy commitment from the authenticated Create
or Clone catalog and checks that policy's expected root attributes against the
retained AOSSMT01 Snapshot metadata. The expected pool GUID comes from the
root-owned `AOSSRPC2` assignment for that exact managed root, not the caller;
Storage rechecks the protected policy head after worker quiescence. These are
nonauthorizing observations.

| AOSPCZ01 field | Evidence available to Storage | Missing proof |
| --- | --- | --- |
| Dataset and snapshot GUIDs | Protected catalog identity and bracketed ZFS object probes | None for this read-only identity check |
| Pool GUID | Current `AOSSRPC2` exact managed-root assignment, bracketed `zpool list` probes, and a post-worker policy-head check | None for this read-only identity check |
| Hold generation and digest | Latest authenticated exact HoldSnapshot or ReleaseHold transition | Current physical hold must still be joined to the protected cut at receipt issuance |
| Root-policy digest | Canonical Create or Clone policy commitment, checked against AOSSMT01 root attributes | An independently observed read-only snapshot-root descriptor and attributes |
| Read-only content digest | None | A bounded, complete content traversal of the pinned snapshot root, with a defined digest format and coverage policy |

The fixed AOSSMT01 directory has a reader and canonical record codec, but no
producer that measures a real ZFS snapshot and publishes that record under
protected authority. Its identity-tree digest is not a file-content digest.
The existing guest-root tree scanner compares a fixed package template; it
does not measure an arbitrary held snapshot or cover all of its metadata.

There is no production AOSNHC01 publisher or monotone rollback floor. A
root-owned file containing a nonzero content digest would still be an assertion,
even if its fields matched the journal head. A publisher must derive every row
from protected Storage state and physical measurement, publish atomically, and
retain a rollback floor before Storage can use it for a receipt. The dedicated
AOSZHR01 key currently exposes no signing operation. Native Acquire, Q04, and
public Create remain closed.

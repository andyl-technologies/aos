# Storage native held-snapshot readback and custody

Storage can select one snapshot from its authenticated transaction journal,
derive the latest exact HoldSnapshot transition, and require the protected
catalog cut to remain unchanged across a one-shot ZFS GUID and hold probe. It
also derives the source root-policy commitment from the authenticated Create
or Clone catalog and checks that policy's expected root attributes against the
retained AOSSMT01 Snapshot metadata. The expected pool GUID comes from the
root-owned `AOSSRPC2` assignment for that exact managed root, not the caller;
Storage rechecks the protected policy head after worker quiescence. A readback
alone is nonauthorizing: receipt issuance additionally requires authenticated
intent, the unchanged protected cut, and custody of the original measured mount.

| AOSPCZ01 field | Evidence available to Storage | Missing proof |
| --- | --- | --- |
| Dataset and snapshot GUIDs | Protected catalog identity and bracketed ZFS object probes | None for this read-only identity check |
| Pool GUID | Current `AOSSRPC2` exact managed-root assignment, bracketed `zpool list` probes, and a post-worker policy-head check | None for this read-only identity check |
| Hold generation and digest | Latest authenticated exact HoldSnapshot or ReleaseHold transition and physical hold probes before and after reader quiescence | The same live hold and protected cut must be rejoined at issuance and delivery |
| Root-policy digest | Canonical Create or Clone policy commitment, checked against AOSSMT01 and physically measured portable root attributes | Protected metadata production and installed composition must be qualified |
| Read-only content digest | Complete bounded traversal of the freshly mounted, pinned snapshot root | Measurement supports a deliberately closed portable subset; unsupported state fails closed |

The confined reader creates a fresh detached ZFS snapshot mount rather than
cloning a host mount that might contain overlays. It applies read-only, nodev,
nosuid, and noexec attributes before measurement. The walker resolves every
descendant beneath the root without following symlinks or crossing mounts,
including same-filesystem bind mounts. It accepts at most 4,096 nodes, depth 64,
16 MiB per file, and 64 MiB of logical file bytes. Unsupported identity-bearing
xattrs, symlinks, and hardlinks close measurement. Content and portable identity
have distinct digests; an identity-tree digest is not a file-content digest.

The descriptor-bearing reader exchange returns exactly one original read-only
mount FD. Storage verifies its kernel identity and the measured attributes,
waits for reader quiescence, and rejoins the protected catalog, policy, physical
hold, and metadata. The dedicated `AOSZHK01` credential exposes a narrow native
signing path, not a raw key or general signing operation. The resulting
`AOSZNA03` acceptance binds the exact request, receipt, original descriptor, and
nonrecursive topology with physically measured node and logical-byte counts.

Storage retains its primary, workspace, and issuance writers through signing,
durable acceptance/readback, and transfer. Consumer interest is recorded in the
separate native issuance journal before send, leaving the receipt's catalog head
unchanged. An ambiguous send retains the exact signed packet and original FD.
Retries cannot create another mount, receipt, issuance identity, or deadline:
they must reuse that original under its fixed paired-clock/BOOTTIME budget. An
accepted row after process restart without local escrow is unavailable, not
proof that the Provider lost its descriptor. Outstanding consumer interests
continue to fence physical hold release and snapshot destruction.

The fixed AOSSMT01 directory has a reader and canonical record codec, but no
producer that publishes measured records under protected authority. The
held-snapshot walker supplies physical measurements, but it does not itself
publish AOSSMT01 or establish its rollback-resistant authority. The guest-root
template scanner is not a substitute for this held-snapshot measurement.

There is no production AOSNHC01 publisher or monotone rollback floor. A
root-owned file containing a nonzero content digest would still be an assertion,
even if its fields matched the journal head. A publisher must derive every row
from protected Storage state and physical measurement, publish atomically, and
retain a rollback floor before its rows become production authority. Installed
reader confinement and the complete Provider/Root/Storage acceptance and
terminal-cleanup composition still require qualification. Neither expiry nor
one owner's restart proves total descriptor-custody loss, and durable issuance
tombstones require exact authenticated retirement. These remaining obligations
keep public native Acquire, Q04, and Create closed; the private signing path is
not evidence that those public operations are ready.

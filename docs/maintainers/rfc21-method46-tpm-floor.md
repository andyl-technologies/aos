# RFC-0021 method-46 TPM floor

This source-only checkpoint is a private codec, protected HEAD derivation,
checked NV-extension backend boundary, and crash reducer. No production TPM
transport implements that sealed boundary yet. No prepared transaction is
persisted, no live journal owner attaches it, and no readiness or method
advertisement changes. Unit tests, authenticated TPM execution, power-cut
behavior, restart/rollover, and installed sender/recipient gates remain unrun
and unqualified. This checkpoint is not completion of the rollback workstream.

## Exact scope

Method 46 is `StorageReserveExecutionCapture`, the logical execution-output
reserve step of public `CreateExecution`. It is not the public RPC or general
Host execution history. Method 48 joins the original method-46 request.

The independent floors belong to the existing fixed endpoints:

| Endpoint | Existing protected journal | Owner NV assignment |
| --- | --- | --- |
| Controller Storage client | `/var/lib/aos/sandboxd/broker-session/storage/session.journal` | `0x0180A046` |
| Storage broker | `/var/lib/aos/sandbox-storage/broker-session/session.journal` | `0x0180A047` |

Each HEAD commits the exact next-frame sequence and **all** sorted namespace-47
key/value bytes, including current histories and retained archives. No key is
excluded. A foreign namespace is rejected. Separate floor protocol state will
use a separate protected Journal, not disappear from the traffic HEAD under an
informal exclusion rule. Existing endpoint revalidation, fixed directory/name,
role/stable manifest identity, protected authority claim, snapshot, and
transaction preflight remain prerequisites; a digest alone is not authority.

## Provisioning contract

The assignments are collision-checked local owner usages in the TCG owner
range, not globally registered handles. An administrator must reject an
occupied handle, explicitly choose the deployment epoch, and provision both
endpoints before allowing method 46. Runtime never selects the first free
index, adopts an existing unrelated index, or falls back to a virtual/off-host
authority. A TPM whose state can be snapshotted with the journal does not meet
this independent rollback requirement.

Use a SHA-256 `TPM_NT_EXTEND`, 32-byte owner-created index, empty authPolicy,
with only `AUTHREAD|AUTHWRITE|nt=extend` (`0x00040044`) at definition. Runtime
requires the exact written public area (`0x20040044`) and its recomputed
34-byte Name. ORDERLY, CLEAR_STCLEAR, owner/platform write/read, POLICY_DELETE,
locks, and any other attribute are rejected. Runtime never calls ordinary
NV_Write, NV_Increment, DefineSpace, UndefineSpace, Clear, or changes auth.

Provisioning uses the existing AOS `tpm2-tools` and `tpm2-tss` packages. Owner,
platform, and lockout/clear credentials remain outside both daemons. Each
daemon receives only its own strong index auth, with endpoint-local protected
credential custody and exclusive writer ownership; never pass a secret on a
command line or give Controller the broker's credential. Linux TPM device
access and service confinement must permit the authenticated transport without
granting hierarchy reset authority. No extra principal or service is assumed.

Pin a suitable provisioned Storage-hierarchy persistent salt-key **Name** to
the physical TPM during trusted provisioning. The profile commits SHA-256 of
that exact Name, not a self-selected key returned by a tool. A fresh ESYS HMAC
session must be salted to that pinned key, authenticate command/response
nonces, and retain the same fixed TPM device connection through public/name,
NV read, extend, and readback. A new boot establishes a new authenticated
session against the same provisioned pin; it does not import an old session
file. Tool stdout, cpHash/rpHash files, or an unauthenticated NV read do not
establish this continuity. Repeated CLI session files across `/dev/tpmrm0`
disconnects are not an assumed qualified session-gapping mechanism.

The scope commits endpoint role, node identity, nonzero deployment epoch,
stable endpoint manifest identity, and pinned salt-key Name digest. The fixed
role determines the NV handle and exact public Name. Provisioning must seed
ordinal one by extending the exact authenticated initial journal cut, then
durably install the same checkpoint/profile before enabling traffic. A zero
NV digest, missing/unwritten index, missing salt key, or absent checkpoint is
never a runtime genesis invitation.

Clearing the TPM deletes owner-created NV and Storage-hierarchy objects.
Changing/recreating them, replacing the TPM, losing preparation bytes, or
changing endpoint provisioning keeps method 46 closed. Authorized reset is a
deployment recovery operation: reconcile/retire old operation custody while
closed, install a new deployment epoch and fresh credentials/key pin, and
explicitly qualify a new seed. Do not reconstruct an old floor from the
restored `/var` or silently re-provision the same epoch. TPM NV Names alone do
not identify allocation instances. PCR-sealed disk storage is not a rollback
floor. The trust boundary does not claim to prevent an authorized administrator
from clearing/reprovisioning the TPM with retained hierarchy credentials.

## Canonical claims and hash contract

All integers are big endian; header version is one; reserved bytes are zero.
Decode accepts only the exact width. Profile/checkpoint/intent constructors are
shape-only private APIs and produce no readiness, replay, or effect token.

```text
profile112 = AOSBTP01 | u16(1) | reserved2 | role1 | reserved3 |
             node16 | deployment16 | stable-endpoint32 | salt-key-name-digest32
scope = SHA256("aos.sandbox.broker-session.tpm-floor.scope.v1\0" || profile112)

head = SHA256("aos.sandbox.broker-session.tpm-floor.head.v1\0" || u8(47) ||
              next-frame-sequence:u64 ||
              ordered(key-length:u64 || key || value-length:u64 || value) ||
              record-count:u64)

checkpoint156 = AOSBTF01 | u16(1) | reserved2 | ordinal:u64 | scope32 |
                next-frame-sequence:u64 | head32 | predecessor-NV32 |
                exact-transaction-digest32
input32 = SHA256("aos.sandbox.broker-session.tpm-floor.extend.v1\0" || checkpoint156)
NV-target = SHA256(predecessor-NV32 || input32)
intent324 = AOSBTI01 | u16(1) | reserved2 | predecessor156 | target156

transaction-digest = SHA256("aos.sandbox.broker-session.tpm-floor.transaction.v1\0" ||
                            transaction-ID16 || record-count:u64 ||
                            ordered(namespace:u8 || put-tag:u8 ||
                                    key-length:u64 || key ||
                                    value-length:u64 || value))
```

For a delete, put-tag is zero and value length is zero; an empty put has tag
one. Record order and the existing JournalTransaction ID are exact. Reject
duplicate/empty keys and foreign namespaces. The target frame sequence is
exactly predecessor sequence plus record count plus two, using checked
arithmetic, not an independent traffic-sequence allocator. Ordinal one alone
has zero predecessor NV and transaction digest; subsequent ordinals must have
both nonzero. Ordinal and frame `u64::MAX` are exhausted sentinels.

The checkpoint retains the last extend preimage. Matching its recomputed NV
target to fresh authenticated TPM data binds the actual scope, HEAD, ordinal,
and exact transaction; trusting a disk-stored NV digest with an unrelated HEAD
would not. Earlier disk checkpoints or an equal-ordinal fork do not match.

Golden tests independently hash literal documented fields with the realized
AOS OpenSSL 4.0.2 binary. Fixture: role one, node `01` repeated 16, deployment
`02` repeated 16, endpoint `03` repeated 32, salt Name digest `04` repeated 32;
sequence/ordinal one, key `a`, value `z`, zero predecessor/transaction digest.
Expected scope is `b6eb9dba080a323b6f11937df70e87a8a1982ee31e1a99ff612ef2b7a675902e`,
HEAD `d56c7f4df877af36a1db91f7415f72a9ecb4480afec19c5fe4b00dc00dca717e`,
input `3af27fe0021a69eb0f383cbbab684a322672adb46510a46b9a1b3bfffac410cc`,
and NV `68ea818747c4236ba6bcd7acb4cdc00bfa4c75fc63dc12281dcdb5a49cae69ad`.
The NV public preimage is `0180a046000b2004004400000020`; its Name digest is
`1ed0ed8e68f053c45e3af51db9046cedc99519d8abec43142d3e78845db5e11e`.

## Commit, ambiguity, and restart

Retain the existing protected traffic writer, floor writer, endpoint/peer
custody, and exclusive index auth. Preflight the exact traffic transaction and
all floor suffix capacity before preparation. Persist the complete existing
JournalTransaction (ID and every ordered put/delete record), predecessor,
target, and preparation binding using the existing protected Journal. Sync
preparation before NV extension. The intent's transaction digest alone does
not persist those bytes or prove preparation. Do not dispatch/send from a
prepared claim.

Read authenticated NV and extend only from the exact predecessor. NV_Extend
is not a hardware CAS; competing credential holders can cause denial. Always
read back after success or error before deciding whether it advanced. Retain
the exact preparation and close dependent effects while a read is uncertain.
Once NV equals the target, commit only the retained exact traffic transaction,
re-read the protected target, and finalize the matching floor checkpoint.
Require exact NV/journal/endpoint agreement immediately before subsequent
request send, domain dispatch, outcome send, and exact replay.

| Authenticated NV | Traffic journal | Durable pending preparation | Reduction |
| --- | --- | --- | --- |
| Checkpoint | Checkpoint | None | Current, still requiring owner use-boundary checks |
| Predecessor | Predecessor | Exact | Extend that preparation only |
| Target | Predecessor | Exact | Commit that retained transaction only |
| Target | Target | Exact | Finalize that checkpoint only |
| Predecessor | Target | Any | Close: violates NV-first ordering |
| Third value/cut, absent/unwritten NV, changed public/key | Any | Any | Close |
| Target | Predecessor | Missing/lost | Close; never guess/reconstruct another transaction |

Lost replies do not mint new nonces, signed packets, session sequences,
receipts, or blind redispatch. A command error with exact old readback can
retry the same durable preparation; exact target readback must not extend it
again. An interrupted NV write is allowed to lose the index entirely, not
guaranteed to yield only old/target; recovery treats that as unavailable.

## Remaining implementation and qualification

Implement durable protected prepare/finalization by reusing the existing
Journal and retained role owner, then attach the floor to **every** mutation
of these two fixed session journals, including archive retention/retirement
and terminal process rollover. No traffic-journal compaction/reset is allowed
without an explicit independently anchored transition. Keep proof formats
private and avoid a parallel request replay allocator.

Implement the sealed ESYS producer against existing AOS tpm2-tss (no FAPI,
abrmd, generic signer, new daemon, or off-host dependency). Qualify key/device/
HMAC continuity, index auth isolation, all public attributes/Name, write-rate
errors/endurance, power loss/deletion, sidecar/main crash cuts, byte-exact lost
reply/restart replay, competing writes, and reset/re-provision rejection.

Only after that qualification may actual Controller send/prepare/replay and
Storage receive/reserve/dispatch/outcome hooks accept method 46. Missing TPM
or provisioning must deny it at **both** endpoints and close the dependent
public CreateExecution readiness path. Existing other-method broker policies
and separate Source/Host authority requirements are unchanged.

## Primary references

The durability, extend, and interrupted-write rules are in
[TCG TPM Library Part 1, sections 34.2 and 34.7.1](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Architecture_Version-185_pub.pdf).
Exact public attributes and Name input are specified in
[Part 2, sections 13.4 and 13.6](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf).
Reset/removal authorization is specified in
[Part 3, sections 24.6 and 31](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-3-Commands_Version-185_pub.pdf).
The local owner handle range follows the
[TCG handle registry, section 2.2.2.1](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p6_rc1_23July2025.pdf).
The AOS-packaged tools' session/Name and resource-manager limitations are
documented by [tpm2_startauthsession](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_startauthsession.1/);
tools are provisioning aids, not an assumed authenticated long-lived runtime
transport.

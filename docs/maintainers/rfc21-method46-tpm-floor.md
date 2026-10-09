# RFC-0021 method-46 TPM floor

This partial implementation connects protected exact-transaction preparation
and reconciliation to the actual fixed journal owners and a private persistent
ESYS helper. Required-mode journal open, replay, mutation, read and use pass
through the floor; the helper and both journal writers stay retained together.
Method 46 remains explicitly closed, including historical replay and effect
handoff. No readiness or method advertisement is opened. Native helper
compilation and the seven pinned-TSS cache regressions pass as described below.
The selected native Rust library suite also passes as described below.
Authenticated TPM execution, power-cut behavior, installed restart/rollover,
and installed sender/recipient gates remain incomplete or unqualified. This
is not completion of the rollback workstream.

## Exact scope

Method 46 is `BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT`, the logical
execution-output reserve step of public `CreateExecution`. It is not the
public RPC or general Host execution history. Method 47 is the output query;
method 48 (`BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT`) joins the original
method-46 request. Separate Host journal authority is outside this floor.

The independent floors belong to the existing fixed endpoints:

| Endpoint | Existing protected journal | Owner NV assignment |
| --- | --- | --- |
| Controller Storage client | `/var/lib/aos/sandboxd/broker-session/storage/session.journal` | `0x0180A046` |
| Storage broker | `/var/lib/aos/sandbox-storage/broker-session/session.journal` | `0x0180A047` |

Each HEAD commits the exact next-frame sequence and **all** sorted namespace-47
key/value bytes, including current histories and retained archives. No key is
excluded. A foreign namespace is rejected. Separate floor protocol state uses
a separate protected Journal rather than disappearing from the traffic HEAD under an
informal exclusion rule. Existing endpoint revalidation, fixed directory/name,
role/stable manifest identity, protected authority claim, snapshot, and
transaction preflight remain prerequisites; a digest alone is not authority.

## Provisioning contract

The deployment image always installs one exact mode record per existing daemon:
`/etc/aos/method46-tpm-floor/controller-mode` or `storage-mode`. The retained
record must resolve to a read-only, immutable root-owned Nix-store file with exact bytes
`legacy-closed-v1\n` or `required-v1\n`; absence or malformed bytes is not a
default mode. The service modules default to explicit legacy-closed mode.
`method46TpmFloor.required` pins required mode in the image rather than a
mutable owner file. It does not itself enable method 46.

Legacy mode keeps unrelated Storage methods usable but refuses execution-output
methods and any retained 46/47/48 history. Any sidecar, lock or compaction name
also refuses legacy opening. Required mode only opens existing main/sidecar
journals, never repairs their tails, and never falls back if a TPM, credential,
mode record or preparation is missing. Moving a provisioned deployment back to
legacy cannot silently discard anchored history.

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

The runtime fixes salt handles to `0x8100A046` (Controller) and `0x8100A047`
(Storage); these are local collision-checked deployment assignments, not a
claim of globally reserved handles. The key is RSA, SHA-256-named, fixed to the
TPM and parent, restricted/decrypt-capable and not a signing object. Before
starting the salted session, official TSS MU marshalling and AOS OpenSSL
recompute its Name from the exact initial public area cached by ESYS, before
any following command can replace the SAPI response buffer. A later separate
ReadPublic is not proof of that cached RSA key. Official SAPI Complete decodes
the retained initial response; no ESYS-private or TPM layout is reproduced.
Subsequent public and NV reads
use the same authenticated HMAC session. AES-128-CFB parameter encryption
protects extend input and NV read output; ESYS validates response HMACs.

### Pinned initial-response cache regression

The helper package asserts the exact AOS `tpm2-tss` release `4.2.0` and compiles
`pkgs/security/aos-method46-tpm-helper/readpublic-cache-test.c` against that
package's public ESYS/SYS/MU interfaces and AOS OpenSSL. The test includes the
actual private helper validator with only its process entry point renamed; it
does not copy the validator or call the production entry point. Every TPM
operation goes to a bounded in-memory TCTI that permits only the fixed salt
handle's no-session ReadPublic. There is no device initialization, physical TPM,
StartAuthSession, credential, provisioning or hierarchy command. The regression
does not link Device-TCTI and provides a fatal test-only device-init guard; the
production helper's device linkage and behavior are unchanged.

Seven named regressions cover three rounds of repeated SAPI completion and the
actual production check over the exact initial canonical public/Name/distinct
qualifiedName with no new transmit or receive;
distinct later responses in both directions (a later valid read cannot repair
the initially cached RSA public); substituted initial RSA bytes with an asserted
pinned Name; substituted Name; weak/signing key shapes; a short response header;
and an oversized public declaration. Official MU codecs construct the response
and compare public bytes. Public and qualified-Name fields are synthetic: these
tests do not prove RSA salt encryption, a real hierarchy, response HMACs, device
identity or installed custody.

The sequence relies on the pinned
[FromTPMPublic implementation](https://github.com/tpm2-software/tpm2-tss/blob/4.2.0/src/tss2-esys/esys_tr.c),
[ESYS ReadPublic completion](https://github.com/tpm2-software/tpm2-tss/blob/4.2.0/src/tss2-esys/api/Esys_ReadPublic.c)
and [SAPI CommonComplete](https://github.com/tpm2-software/tpm2-tss/blob/4.2.0/src/tss2-sys/sysapi_util.c):
the initial all-NONE import has only one command, and CommonComplete resets the
decoder cursor while retaining its receive-response stage and buffer. No private
ESYS resource representation or TPM layout is parsed by the test.

A native helper package build executes the regression and retains its report at
`share/aos-method46-tpm-helper/readpublic-cache-regression.txt`. A cross build
compiles it but records explicit `NOT RUN`, requiring execution on the target;
it never labels a cross build as a passing test. A native ordinary build through
the release entry point has compiled both executables with AOS C17 and
`-O2 -Wall -Wextra -Werror`, then passed all seven regressions:

```text
bash ./aos-dev --release build package aos-method46-tpm-helper --no-out-link --max-jobs 1 --cores 1
```

The qualified mock-check artifact is
`/nix/store/73s3sk64815v86xw8563wp4kld3wbrdb-aos-method46-tpm-helper-0.1.0`,
from source commit `c9eb78a03e68a41f92b2b8b4e0233521b3f86bbc`. Its report records
seven passing tests. Readback of the stripped helper matches its installed
SHA-256 sidecar:
`76547a6577566bb775fe15413d5138304ecd6e472c3ada60919a02d10701e81f`.
Malformed-response negative cases emit expected TSS errors; the regression and
package both exit successfully. A future TSS upgrade requires review and actual
regression execution before producer qualification. This mocked check does not
open method 46 or replace physical/installed qualification.

Required mode loads these owner-specific systemd credentials under the existing
`aos-sandboxd.service` or `aos-storaged.service` credential directory:

```text
broker-method46-tpm-provision-v1 = AOSBTD01 | version:1u16be | reserved2 |
                                 profile112 | salt-key-Name34 | reserved2
                                 (exactly 160 bytes)
broker-method46-tpm-index-auth-v1 = exactly 32 nonzero high-entropy secret bytes
```

The public credential's role and SHA-256 of the exact salt Name must match its
profile. The protected endpoint's real node, role and stable manifest identity
must independently match it. Credentials are external to the Nix store; both
are mandatory in required mode and neither is loaded in legacy mode. Provision
the existing daemon UID's `/dev/tpmrm0` access separately. Required-mode units
allow only that TPM device under their existing closed device policy; no new
account, service, capability or hierarchy credential is installed.

The AOS-built `aos-method46-tpm-helper` is a private libexec child, not a service
or signing principal. Rust uses no new unsafe FFI: the C child owns official
ESYS/MU layouts and the single fixed Device-TCTI connection. The parent clears
the launch environment, retains root-owned read-only helper ELF/loader files
and hashes, checks the actual executable inode and loader mapping before
releasing auth, and retains the exact child/pidfd/private sequenced-packet channel. The helper
never execs/forks after this observation. No caller selects an image, device,
TCTI, command line or session file. Secret bytes travel only in the private
inherited channel, are zeroized, and never enter argv, environment or diagnostics.
The first packet transfers public role/salt/nonce fields and only two exact
protected lock open-file descriptions using the existing safe `SCM_RIGHTS`
carrier. The child verifies its enforcing role and the empty, private, RDWR
regular-file identities, sets nondumpable, and acknowledges both with the
original nonce. Only then does the parent send a separate bounded auth packet
on that same private carrier; the child rejects a different nonce or index
before opening the TPM. It
receives neither journal data descriptors nor writer APIs. A lock loan keeps
the original flock description alive but cannot prove TPM-close ordering or
authorize a journal read, write, or effect.

```text
hello160 = AOSBTH02 | version:2u16be | reserved2 | nonce32 | index:u32be |
           salt-handle:u32be | salt-key-Name34 | reserved34 |
           main-lock(device:u64be,inode:u64be,uid:u32be) |
           floor-lock(device:u64be,inode:u64be,uid:u32be)
locks48 = AOSBTK02 | version:2u16be | reserved2 | nonce32 | count:2u16be | reserved2
auth80 = AOSBTA02 | version:2u16be | reserved2 | nonce32 | index:u32be | index-auth32
request84 = AOSBTQ02 | version:2u16be | operation:u8 | reserved1 |
            nonce32 | sequence:u64be | input32
reply128 = AOSBTR02 | version:2u16be | operation:u8 | reserved1 |
           nonce32 | sequence:u64be | NV-Name34 | name-algorithm:u16be |
           attributes:u32be | size:u16be | policy-length:u16be | NV-value32
```

The private version-1 combined HELLO/auth format is rejected. No deployed
method-46 data is upgraded or reinterpreted by this unreleased correction.

## Existing-role confinement source contract

The normal Controller enters its distinct domain whenever the immutable
enforcing profile is selected, independently of TPM mode. This keeps the
purpose-specific Source/Cache journal writer out of `init_t`; legacy-closed
TPM mode still closes methods 46–48. Storage's current domain selection remains
required-mode-only pending its separate startup closure. The normal policy-authority unit
has a distinct Root domain in the immutable SELinux image; its same-ELF Cache
recovery invocation does not. These are explicit fixed-unit contexts, not a
default executable transition from `init_t`. The one private helper ELF has
source-specific Controller/helper and Storage/helper transitions. None of
these changes creates a Linux UID, service, key, capability or TPM namespace.

| Existing process | Domain / protected objects | Narrow boundary |
| --- | --- | --- |
| Controller | `aos_sandbox_controller_t`; Controller state, credentials and floor | Its own writer and status-only manager observations; Root socket pathname and `connectto` only |
| Storage | `aos_sandbox_storage_t`; Storage state, credentials and floor | Its own writer and status-only manager observations; no Controller credential or floor access |
| Normal Root | `aos_sandbox_policy_authority_t`; its own authority state, credentials and runtime socket | Own writer only; Controller cuts remain signed held-writer evidence, not direct UID-811 journal reads |
| Controller private child | `aos_method46_controller_helper_t` | Its owner's private carrier and exact empty RDWR lock OFDs; fixed `/dev/tpmrm0` only |
| Storage private child | `aos_method46_storage_helper_t` | Same boundary for Storage; no cross-owner lock, floor, credential or descriptor use |
| Existing Guest root publisher | `aos_sandbox_guest_root_publisher_t` | Exact fixed executable and existing unit; Guest projection/publication permissions are a separate reviewed dependency |

The existing compiled effective-policy checker expands attributes and checks
the positive/negative owner matrix. In addition, it searches *all* sources for
Root task-file read/open/ioctl, ptrace, accepted-endpoint FD use and socket
read/write. Only the trusted kernel/PID1 and Root itself may appear in those
task/endpoint cut queries; process entry into normal Root is restricted to
PID1. A legitimate Controller connection does not grant use or writing
of Root's accepted endpoint. Root self-ptrace, generic execution, role escape,
policy mutation and capability escalation are denied. Checking a SID or an
enforcing flag at runtime is not itself proof of this exact loaded matrix.
An unconfined same-SID PID1 worker cannot be distinguished from PID1 by a MAC
type; residual `init_t` actors therefore remain a preparation/installed-profile
audit requirement, not a blanket trusted-worker exception.

### Existing Source/Cache view producers (source-only)

The immutable configuration reuses the three existing checked idmapped-view
scripts, their actual Controller/signer UID/GID assignments and their existing
five-capability preparation boundary. It does not add a mount service or a
native duplicate of the mount implementation. Each exact script output is
labelled separately. A source-built private tool package copies only the AOS
Bash, stat, mkdir, chown, findmnt, mount and umount images into distinct immutable
inodes; only the two existing preparation roles may execute those private tools
without a domain transition. Shared `bin_t` interpreters are not an alias.
The scripts clear interpreter/loader injection variables and prevent mount
helper dispatch and writable mount-table updates. Mutable legacy scripts and
their existing tool paths remain unchanged.

The existing static fresh-only root provider runs as a fixed `ExecStartPre`
of the existing Cache-journal-view unit. This keeps each labelled script
package independent of the selected policy that labels it. Source and Cache
signer-view units depend on that first preparation; they do not rerun root
creation after a target has already been mounted. The provider preflights all
enabled original roots and `/run` targets before creating any missing peer,
rejects existing wrong type/mode/owner/label or a racing creation, and never
repairs or relabels existing state. Only freshly created held directories may
receive the image-compiled Controller UID/GID before durable admission.
The provider's metadata-directory reopens use the existing preparer capability
bound's DAC search permission. Its MAC profile explicitly denies protected
journal, key, floor and lock file open/read; this is not a data-reader grant
and adds no unit capability.

The ext4 path retains the original fixed `/var` block-device, root-inode,
mount-ID and attribute checks. A ZFS system-state image instead verifies the
separately declared `${pool}/var/lib` dataset using actual bounded `statmount`
filesystem type/magic, device, unique mount ID, source, mount root, mountpoint
and writable/nosuid/nodev attributes. A subtree bind, ID map, read-only mount,
foreign pool or undeclared mountpoint is refused. Its mounted `/var` and
`/var/lib` root contexts are explicit image configuration, not relabelling
stored children. The existing Network/ext4 provisioner behavior is unchanged;
this view extension does not qualify a separate Network-on-ZFS producer.

Normal Source and Cache signers have distinct cap-empty read-only domains,
purpose-specific credential and socket types, and explicit fixed-unit contexts.
Pinned systemd 261.2 uses that service context to select the activated listener's
creation SID. The listener's `SO_PEERCRED` still names PID1, not the signer;
this source change does not reinterpret it as actual signer-process evidence.
Original and idmapped views share inode labels, while original-root DAC stays
Controller-only. Root reads Cache through its existing checked view, never
through a new capability or direct Controller-owned 0700-root grant.

Protected types deliberately remain outside `file_type`. Explicit
`filesystem:associate` grants follow the pinned refpolicy's actual `fs_t`
ext4/ZFS xattr superblocks, `tmpfs_t` runtime/credential mounts and `device_t`
devtmpfs. These source rules are not proof of actual mounted labels or delivery.

The pure C reducer cases and shared effective-checker regressions are authored
but unrun in this leaf. Module evaluation, compiled expanded policy, actual
idmapped mount/association and signer/Controller startup all remain unqualified.
In particular, `.fc` patterns do not prove that PID1's raw credential-file
creation receives the intended type: the actual unit credential-root label,
creation transition, input custody and delivered readback need a separate
measured closure. Normal Controller/Root private-state preparation, the Storage
prestart install/chmod contradiction, Cache-recovery's distinct state access,
and deployment-provisioned broker peer SIDs are still explicit prerequisites.
No signed manifest is rewritten, and neither selected policy paths nor a
point-in-time policy-byte comparison mint a normal-Root matrix proof.

The helper never receives a journal-data or credential FD. `SCM_RIGHTS`
receive checks the descriptor's RDWR access mode, so its own lock type permits
read/write but not pathname open, flock, append, truncate, rename or unlink.
Both Rust and C require a regular, singly linked, empty 0600 descriptor with
the original owner/device/inode. These permissions cannot grant the child a
journal writer. Image/loader observation occurs before nondumpable and auth;
the subsequent owner/helper SID and pidfd checks must also pass on the actual
installed kernel without ptrace or `CAP_SYS_PTRACE` exceptions.

### Fixed fresh owner-root preparation

The existing static runtime-root program gains one fixed boot phase, not a
generic directory or privileged-copy API. Required-mode flags and the actual
Controller UID/GID are compiled from the immutable module assignment; no
runtime scalar may select ownership. The same package, selected-kernel
canonical `/policy.33` readback and source identity are used by stage 0,
existing `/var` preparation, and Network preparation. The original Network
root:root assignments and no-repair rules are unchanged.

The phase preflights every enabled existing owner topology before creating a
missing peer. It validates the exact ext4 `/var`, ancestry, labels, modes,
mount IDs, inode identities and reopened names. Only a just-created, retained,
correctly labelled Controller directory may be changed from birth root:root
to the compiled owner before sync; an existing wrong-owner inode is refused,
never repaired. It creates no credential, salt key, NV index, traffic/floor
journal or initial checkpoint. Required owner-root preparation currently uses
the existing ext4 state substrate; ZFS data pools are unaffected.

### Explicit remaining startup dependencies

File-context patterns do not prove PID1's effective credential-file creation
label. The real `LoadCredential` input/delivery types and every residual
root/`init_t` credential reader must be measured and narrowly closed. The
existing Cache and Source view preparer subroles are named but their generated
script/interpreter/tool, credential-input and mount producer closure is not
implemented by this checkpoint. Their existing setup capabilities are not
delegated to a normal owner. The Guest publisher still needs its independently
reviewed template/workspace/authority/replay/loader and socket preparation
closure. There is no generic `file_type`, `bin_t` or `init_t` access substitute.

The actual Storage unprivileged `ExecStartPre` install/chmod commands also
conflict with its chmod-denying syscall profile; this checkpoint does not
make them privileged to hide that dependency. Normal Root signer-peer SIDs
and each broker's signed peer configuration must be deliberately provisioned
for the new roles. No `init_t` peer alias or silent signed-configuration rewrite
is allowed. The source alone consequently does not claim working required-mode
startup or a positive Root sender proof. Installed tests must additionally
cover the real notify/logging/activation descriptors and each dependency/IPC
path rather than treating a successful status-only manager call as startup
closure.

Only read (1, zero input) and extend (2, nonzero input) exist. Width, version,
reserved bytes, correlation nonce/sequence, operation and public geometry are
strict. Framing decode alone produces raw shape, never authenticated NV
authority. The sealed producer combines the measured owned carrier with ESYS
authentication. All transport errors poison that carrier; the parent stops and
waits for only its child before releasing journal custody. Successful owned
child wait fences that child's exit work during in-process cold recovery.
Daemon-crash restart also requires the actual PID 1 service-population barrier
described below; an orphan's shared flock release alone is insufficient.
Cold reconciliation uses a fresh session after the old RM carrier has closed. The 30-second parent
exchange deadline does not claim that blocking ESYS one-call wrappers honor
their configured timeout; driver-close quiescence remains an installed gate.

### Required-mode restart policy is observed, not frozen

Only required-mode instances of the same existing `aos-sandboxd.service` and
`aos-storaged.service` set `ExitType=cgroup`, `KillMode=control-group`, and
`TimeoutStopSec=infinity`. Legacy units are unchanged. Before helper launch
and each physical floor command, the shared PID 1 property reader requires
the genuine unique PID 1 bus owner, exact unit ID/MainPID/invocation, and only
`activating/start` or `active/running`. This allows startup checks before a
notify service reports ready; it does not manufacture readiness.

The owner also verifies the retained actual PID 1 launch image against the
independently compiled package pin, its own direct parent
and retained pidfd/cgroup, the helper's exact process and same cgroup, a
nontransient immutable image fragment, empty drop-ins, and the selected
effective lifetime/kill/stop properties. This is a point-in-time observation,
not a policy freeze. `RefUnit` is a lifetime reference, not a property lock.
Ordinary fixed-unit live property setters are restricted by systemd, but root
administrative reload, a replacement image/drop-in, or cgroup migration can
still weaken the contract after a read. The observation does not deny those
administrative changes.

RFC-0021 [trusts the kernel, boot chain, system manager and privileged brokers](../rfcs/0021-sandbox-runtime/10-security.md#trust-model)
within its selected tier; the deployment must preserve that trust for these
two unit policies. A trusted administrator actively replacing the deployed
policy is not automatically an adversary outside that model. This checkpoint
does not claim immunity from such administration or expand PID 1 authority.
If final readiness must mechanically prohibit weakening during the invocation,
the existing PID 1 launch-policy boundary must additionally seal these exact
unit properties against reload/replacement. No such seal for these units is
established by this checkpoint. Neither an immutable fragment alone nor
repeated reads close that stronger root-attack threat-model gap. Method 46
remains closed for the physical and installed qualification below, not because
this tranche imposes a blanket new PID 1 policy mechanism.

The conditional crash rationale uses cgroup population, not a PID list. Linux
can hide an exiting process from `cgroup.procs` before deferred file-release
work completes. Kernel exit task work precedes cgroup population removal;
systemd's cgroup lifetime waits for `cgroup.events/populated=0`. Infinite stop
timeout avoids the ordinary timer transition to restart while a member remains.
Ascending descriptor close order is also insufficient because `fput` can defer
release through LIFO task work. The packaged kernel 7.2.3/systemd 261.2 crash,
signal, blocking-RM-close, and policy-change behavior still require installed
tests; nearby upstream source is rationale, not that qualification.

### Existing confinement is not an inferred cross-broker denial

The [Controller unit](../../modules/sandbox/controller-service.nix) uses the
dedicated `aos-sandboxd` UID, no capabilities, `NoNewPrivileges`, strict system
protection, and read-only cgroup protection. The [Storage unit](../../modules/sandbox/storage-broker.nix)
has the same capability and filesystem/cgroup restrictions but runs as UID 0.
These restrictions block direct writes through each unit's protected mounts;
they do not block AF_UNIX system-bus requests or independently prove denial of
manager methods. No public floor interface accepts a unit name/property text;
the shared reader only observes the two fixed service names and never sends a
unit mutation or Reload request.

Systemd separately authorizes management operations. The AOS
[unit-reference patch](../../pkgs/system/patches/0012-restrict-unit-reference-methods.patch)
restricts reference lifetime control; it is not a reload/property seal. The
[bus module](../../modules/services/dbus.nix) includes the packaged systemd
policy and explicitly supports administrative bus-policy reload/drop-ins.
`ProtectSystem` is not a D-Bus authorization policy, and dropping capabilities
does not change a root sender's UID. Other broker code's fixed-function API
does not itself prove that a compromised root process cannot send management
requests directly.

The [current AOS MAC declarations](../../pkgs/security/_aos-selinux-production-policy/aos_sandbox.te)
and [executable labels](../../pkgs/security/_aos-selinux-production-policy/aos_sandbox.fc)
provide distinct Host/Network/worker domains but do not yet establish distinct
Controller/Storage transitions. Therefore this checkpoint does not claim a
MAC denial of Storage's root D-Bus management, another broker's manager access,
or all direct cross-domain cgroup migration. Final installed tests must measure
the actual enforcing policy, manager authorization and unit-mount boundaries
for these negative cases; nominal Nix settings are not that evidence.

### Original PID 1 launch image (source-only)

Required mode adds only this existing systemd activation contract to the same
two fixed units, with no `graceful` option or new service/capability:

```text
OpenFile=/proc/1/exe:aos-method46-pid1-image:read-only
FileDescriptorStoreMax=0
```

systemd 261.2 selects `OpenFile` only for `ExecStart`, not `ExecStartPre`.
Its executor opens the original regular inode and reopens that inode read-only
before service mount/proc confinement or UID reduction. The FD joins the
existing named activation table; it is not a tool-produced copy or a path claim.
See the pinned [service spawn](https://raw.githubusercontent.com/systemd/systemd/v261.2/src/core/service.c)
and [execution ordering](https://raw.githubusercontent.com/systemd/systemd/v261.2/src/core/exec-invoke.c).

The Controller captures zero to two entries (optional existing publisher plus
required-only image); Storage captures two to seven (its existing exact socket
roles plus required-only image). Every slot is copied before opening retained
credentials, state, bus or cgroup files. Existing safe `F_DUPFD_CLOEXEC` and
original `FD_CLOEXEC` operations avoid new Rust unsafe ownership transfer. Two
complete bounded procfs scans reject extra inherited entries, not just entries
named by `LISTEN_FDS`; temporary scanners close before other state opens.
The earlier no-set-ID startup check also closes its temporary scanner. The
single-threaded startup interval, not environment values or the scan itself,
establishes table stability. Names/PID/count remain correlation hints only.

Only actual process-start capture creates the opaque parent-only launch
observation. Immutable mode requires its exact presence, and the existing
fixed Storage role/handshake carries it into the journal floor. Constructors
lacking that observation remain required-mode closed. Legacy mode accepts no
image slot and continues to close execution-output methods. This introduces
no scalar or caller-FD authority factory, global image registry, helper frame
field, or extra child descriptor: the child still receives only two lock OFDs.

Before helper spawn and each physical floor operation, the existing genuine
PID 1/fixed-unit/direct-parent/cgroup/invocation guard requires the exact
`OpenFile` `(path,name,read-only flags)` tuple, empty extra-FD names, zero store
maximum and zero stored FDs, alongside the effective exit/kill/timeout policy.
The parent retains the actual launch FD, not a reopened package ELF used as
executed-image evidence. Its read-only regular inode, dev/inode/length, owner,
mode, immutable lower-store mount/name and SHA-256 content must match the
independently compiled AOS PID 1 package artifact. Offset-independent reads
preserve shared-OFD cursors across session reconnects and revalidate contents
at every NV boundary. No confined `/proc/1/exe` reopen or `CAP_SYS_PTRACE` is
needed in this source path.

The retained FD measures PID 1's actual image at launch, not a subsequent
trusted-administrative manager reexec, and property readback still does not
freeze policy. Genuine installed 261.2 launch delivery/property encoding,
confinement, descriptor lifecycle, wrong/extra/missing slot failures and
original-image identity must qualify; source inspection is not that evidence.
The native image-hash, read-only descriptor, shared-offset and Controller
launch-table regressions pass in the selected library run below. They do not
exercise installed PID 1 descriptor delivery or the full production process.

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

All floor claim and prepared-wrapper integers are big endian; header version
is one; reserved bytes are zero. Embedded native journal record payloads retain
the existing little-endian journal format rather than a new record codec.
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

The same endpoint owner opens the fixed `session-floor.journal` beside
`session.journal`, without creating or repairing missing state. Lock order is
traffic writer, floor writer, then retained TPM transport. Both names and the
full production root-to-owner ancestry are revalidated through the existing
Journal owner. A missing checkpoint, torn tail, stale compaction, occupied
writer lock, or changed path closes the operation. Runtime has no initializer.

The sidecar owns namespace 47 and only three keys: `checkpoint` (156 bytes),
`intent` (324 bytes), and `transaction` (bounded `AOSJPT01`). The last two are
present together or absent together. Preparation appends exactly two puts;
finalization atomically replaces the checkpoint and deletes both preparation
keys in one three-record transaction. Before the first preparation append,
native preflight validates the actual prospective traffic transaction and
both sidecar transactions, including frame/byte/count/materialized bounds.
The sidecar exposes no unrelated writer or compactor, so its exact final suffix
cannot be spent by another operation while preparation is pending.
Preparation validates its exact two-transaction preflight token before append.
That token becomes stale after preparation commits. Recovery takes a fresh
final-suffix token at the actual pending sidecar cut and validates it after
fresh NV plus exact held main/sidecar rechecks before extend or main commit.
The final sidecar append takes and validates another fresh native token. No
token survives reopen or an intervening sequence change by assumption.

```text
prepared = AOSJPT01 | u16(1) | reserved2 | original-transaction-ID16 |
           record-count:u32 | ordered(record-length:u32 | native-record-payload)
```

This nonauthorizing wrapper reuses the existing native record encoder, decoder,
and transaction validator. It preserves ID, order, namespace, put/delete tag,
and every key/value byte. Byte/count/offset and aggregate payload bounds are
checked before corresponding allocations; an ordinary decoded transaction
does not prove durable preparation. Only the retained protected sidecar plus
current native journal cut and authenticated NV can supply that ordering.

Let `E = 32 + 4 * main.maximum_records_per_transaction +
main.maximum_transaction_bytes`. The separate journal keeps the main journal's
existing 4 GiB file ceiling; this is an independent ceiling, not another 4 GiB
traffic allowance. Its bounded configuration permits three materialized keys,
three records per transaction, keys up to 11 bytes, and at most
`2 * main.maximum_transactions + 1` transactions. Record/payload/materialized
limits are checked sums of `E`, the fixed 156-/324-byte claims, key widths, and
existing seven-byte native record headers; no production main budget changes.
If either journal cannot fit the complete transition, preparation is refused
before NV or traffic changes.

The trusted ordinal fixes sidecar next-frame geometry: the provisioned
one-record checkpoint ends at sequence 4; each two-record preparation adds
four frames and each three-record finalization adds five. Current ordinal `n`
requires `4 + 9 * (n - 1)`; pending requires four more. Unexpected rewrites,
compaction, or extra history therefore cannot be silently adopted on restart.
Compacting the initial single checkpoint is physically equivalent to that
same initial snapshot and creates no earlier accepted state; runtime exposes
no such operation. After any transition, or while pending, compaction changes
geometry and closes recovery.

Read authenticated NV and extend only from the exact predecessor. NV_Extend
is not a hardware CAS; competing credential holders can cause denial. Always
read back after success or error before deciding whether it advanced. A retained
ESYS producer must finish or fence the prior command before readback; an old
read that could overtake a still-queued extension cannot authorize retry. Retain
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

## Remaining qualification

The durable coordinator, sealed physical producer, image/credential wiring and
actual owner hooks remain installed-unqualified. The selected combined native
library run on `0aba3a682b64f0c67dc495b4a02532b9cc8df398` exits successfully:
17 libraries, 3,032 distinct tests passed, zero failed, and 15 ignored. The
broker-session security library contributes 291 passing tests. The run uses
the AOS development shell with frozen, offline Cargo dependencies, two jobs,
and `--no-fail-fast`; ignored kernel/installed prerequisites remain unqualified.
This is selected library qualification, not the full package, daemon or
installed RFC qualification. Existing native Journal commits are reused
through one mutation funnel, including archive
retention/retirement and terminal process rollover. Schema-only validation is
private to the opaque retained reconciliation borrow; ordinary reads cannot
skip the floor. No traffic-journal compaction/reset is exposed. Fixed-name
open/reopen requires noncreating, nonrepairing replay before reconciliation.
The test-local factory and fake NV do not qualify installed startup, physical
authentication, service confinement or effect boundaries.

The native lock-loan, helper framing, startup-state, image-hash,
weakened-property, durable recovery and mocked physical-backend tests pass in
that run. Their temporary journals and fake NV do not establish actual TPM or
service custody. Compiler/API qualification must cover the packaged TSS 4.2.0
initial-response SAPI decode, not assume that a later public read refreshed
the cached salt key. The exact packaged-4.2.0 repeated-Complete regression and
check wiring above passed natively; neither uses a physical TPM. They must pass
again before a future TSS upgrade or producer qualification. Required-mode
effective unit policy and the exact old
helper's TPM-close-before-next-owner ordering need genuine installed tests.

Qualify the AOS-built helper and both normal daemon binaries, then key/device/
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
The [stable safe Rust ESYS API](https://docs.rs/tss-esapi/7.7.0/tss_esapi/struct.Context.html)
does not expose NV_Extend; the private C child avoids unsafe Rust pointer access
or a forked FFI layout. The authoritative ESYS session and response-HMAC rules
are documented by [StartAuthSession](https://tpm2-tss.readthedocs.io/en/stable/group___esys___start_auth_session.html)
and [NV_ReadPublic](https://tpm2-tss.readthedocs.io/en/stable/group___esys___n_v___read_public.html).
Linux's [TPM common close path](https://github.com/torvalds/linux/blob/master/drivers/char/tpm/tpm-dev-common.c)
flushes asynchronous command work, and the
[RM close path](https://github.com/torvalds/linux/blob/master/drivers/char/tpm/tpmrm-dev.c)
calls it before releasing the resource-manager space. This source rationale
does not replace qualification of the packaged AOS kernel/device and owned
helper stop/wait ordering.
The ESYS [resource cache](https://raw.githubusercontent.com/tpm2-software/tpm2-tss/master/src/tss2-esys/esys_tr.c)
and [StartAuthSession](https://raw.githubusercontent.com/tpm2-software/tpm2-tss/master/src/tss2-esys/api/Esys_StartAuthSession.c)
show why initial salt metadata must be verified before use;
[SAPI Complete](https://raw.githubusercontent.com/tpm2-software/tpm2-tss/master/src/tss2-sys/sysapi_util.c)
restarts decoding over the retained response. These current upstream sources
do not substitute for packaged TSS 4.2.0 qualification.
The kernel [exit path](https://raw.githubusercontent.com/torvalds/linux/v7.2/kernel/exit.c),
[deferred file release](https://raw.githubusercontent.com/torvalds/linux/v7.2/fs/file_table.c),
and [cgroup iterator/population paths](https://raw.githubusercontent.com/torvalds/linux/v7.2/kernel/cgroup/cgroup.c)
distinguish PID-list disappearance from final population removal.
The systemd 261.2 [service lifetime](https://raw.githubusercontent.com/systemd/systemd/v261.2/src/core/service.c),
[cgroup emptiness](https://raw.githubusercontent.com/systemd/systemd/v261.2/src/basic/cgroup-util.c),
and [fixed-unit setter](https://raw.githubusercontent.com/systemd/systemd/v261.2/src/core/dbus-service.c)
sources support the conditional policy rationale above, not a property freeze.

# Fixed original-ticket monitor custody and confined relay

This Linux-only patch applies to the hash-pinned OpenSSH 10.5p1 source in
`../openssh.nix`. Ordinary OpenSSH defaults `AosAttachMonitorV2` to `no`.
The existing Guest daemon owner opts in with fixed launch arguments; no new
listener, principal, key, credential issuer, or authentication bypass is added.
Original configuration, AOSAPG01, certificate and base-route bytes are unchanged.

The fifth patch follows the pinned binary object ownership: `session.o` is
linked into both `sshd-auth` and `sshd-session`. Both therefore link the existing
relay and shared `aos-attach-client.o` mechanics. The client object contains only
the unchanged fixed MM request encoders/answer parsers and protected Guest
connector; it has no accepted authentication record, retained root custody or
monitor dispatcher. Authentication capture, full-auth acceptance, held
pidfd/Guest connection, and confinement setup remain session-only objects.
The pre-auth binary still sends its authenticated key state and exits; linking
its shared session dependencies does not add a post-auth dispatch or authority.

The privileged `mm_answer_keyverify` retains the actual Ed25519 certificate,
original SSH userauth message, signature and root-held KEX session identifier
only after its signature/session checks and authentication-option activation.
The record stays a candidate through partial authentication. The final root
pre-auth decision marks it accepted only after required methods, account checks,
valid-user and password-change restriction checks. PAM credential establishment
and session opening must also succeed before the post-auth fork.

The root monitor opens a pidfd for its own unreaped post-auth fork. Its new
private monitor connection accepts exactly one empty readiness message after
that child drops privilege and adopts the verified key state. This message
identifies the child; it is not holder-signature authority. The root publishes
its retained witness and that child pidfd only through the existing protected
Guest exec-gate listener, and retains its private monitor connection, pidfd and
Guest connection until exit. No callback result or nominated PID/executable is
used to establish custody.

The Guest joins kernel peer/record identity, its live start-opened root-monitor
helper measurement and listener pidfd, the exact immutable original ticket,
certificate/holder/session proof, protected gate/runtime and active process
ledger. Partial, substituted, expired, foreign-process and wrong-descriptor
records fail closed. Custody is memory-only: a restart cannot adopt historical
monitor proof from ticket files or callback metadata. Before consume, exit,
expiry, ambiguity and cancellation close retained handles; no cached success
restores custody. A consumed session's terminal-data lifetime is distinct and
cannot authorize another consume or control.

The v3 wire profile is `AOSAMR03`, account UID/GID as big-endian u32 values, then
four u32-length-prefixed sections: KEX session (32–64 bytes), actual binary
certificate (1–4096), original signed userauth message (1–8192), and original
SSH Ed25519 signature (1–128). The complete record is bounded to 13312 bytes,
with exactly one transferred child pidfd. `AOSAMB02` acknowledges binding only
and contains no descriptor. Unknown versions, zero/overflowing section lengths,
trailing bytes and unexpected ancillary data are rejected.

The second patch adds a fixed no-exec internal relay, not a passwd-shell
`-c` dispatch or a second certificate parser. Before privilege drop it requires
the real procfs `suid_dumpable=0` policy and nondumpability. After drop and before
readiness it installs no-new-privileges and a TSYNC seccomp filter. The filter
rejects exec, new executable mappings, memory/process injection, namespace or
credential changes, dumpability resets and shared-memory/shared-FD-table clone.
Only private-memory/private-FD-table descendants inherit this loaded image;
there is no later exec boundary that can reset dumpability. No tenant
environment, home-directory hook, RC file or passwd shell runs on this path.
The existing non-PAM nologin and PAM session checks precede readiness as well.

The retained private monitor channel carries exactly one empty relay request
and the actual, still-unreaped fork's pidfd. The measured root monitor forwards
`AOSRLY03` plus that descriptor on the same retained Guest connection. Its
`AOSRAK03` acknowledgement contains no I/O. Only that exact kernel-identified
descendant can join the empty `AOSRIO03` request. Public claim bytes, ancestry
alone, a nominated PID and callback output cannot reconstruct this custody.

The existing Controller forward channel polls the original accepted ticket as
data. Consume independently reauthorizes its original capability and holder
under genuine current policy/revocation/trust heads and exact registration,
holding the sole writer through Host exchange. The fixed ATTACH plan commits
the unchanged original grant/ticket plus custody digest and a fresh readback
challenge, not a replacement grant or nonce. Host keeps its original runtime
claim, assignment and route/revocation journal cut continuously borrowed.
The authenticated plan's narrowed exclusive expiry and already-admitted local
BOOTTIME effect deadline are carried on the private agent frame; Guest
intersects them with a monotonic deadline and rereads both
immediately before SCM and after the relay receipt. Installed native clock and
topology assumptions still require qualification.

Guest retains one shared barrier across terminal/cancel publication, the exact
original-ticket reservation and final SCM/receipt. Only Stream or PTY topology
admitted by the original ExecutionSpec is eligible; historical Observe evidence,
detached/capture specifications and legacy process rows cannot be relabeled.
The one logical per-execution marker is create-new, synced and read back exactly.
Any legacy, partial, conflicting, ambiguous or already-present marker stays
closed. The relay receives exactly one PTY or three stream descriptors, sends
`AOSRID03`, then performs bounded-buffer transport without exec or claim parsing.
That receipt does not close its original Guest connection: the connection
remains live until the relay ends and is the retained disconnect observation.
Cold restart and cached broker completion cannot recover handles or transfer
again. Public Create/launch/readiness activation remains closed pending complete
installed qualification; source availability is not readiness.

The existing Guest owner now retains a proper per-execution descendant cgroup,
blocked-helper membership and durable original row before spec release. Its
enforcing Owner/Tenant projection preserves admitted UID0 credentials while
denying tenant migration and access to owner control objects. Disconnect
cancel holds the shared barrier through `cgroup.kill`, recursive empty and
leader-exit readback, and durable terminal publication. This source is not
installed delegation, MAC or accepted-Create qualification. Public readiness
remains closed until the full original-ticket producer is qualified.

Original execution terminal status is distinct from relay exit. After retained
subtree emptiness and the original child's actual wait result, Guest persists
the exact Linux raw status and sends nonauthorizing `AOSIOE04 | raw:u32be` on
the same consumed I/O connection. EOF alone does not let the relay declare
execution success. The relay drains original output before ending; it cannot
nominate the status that the root monitor later reports.

The confined post-auth child requests a fixed empty terminal read on private
MM opcodes120/121. The retained root monitor constructs `AOSMCT04` with its own
strictly increasing sequence and Terminal action, using the original Guest
connection. Guest requires the same pinned root sender/child, original witness,
ticket bytes, protected claim/config inode/trust and measured runtime. Only a
canonical `AOSMCA04` carrying actual protected original waitstatus permits SSH's
exit-status/exit-signal message. Missing, pending, partial or substituted data
disconnects; relay exit never supplies a fallback. This read-only reporting may
outlive original certificate validity or leader liveness but cannot renew the
ticket, create custody, control execution or release another descriptor.

[RFC4254 section6.10](https://www.rfc-editor.org/info/rfc4254/)
permits vendor exit-signal names. Standard POSIX names stay unchanged; other
genuine Linux terminal signals use `LINUX<number>@andyl.com`, not the upstream
shared unknown-signal sentinel. Public terminal result V2 separately retains
exact native signal/core status without expanding the seven selectable control
signals.

The fourth patch routes original PTY setup, resize and the seven existing SSH
signal names through private monitor opcodes122/123. The confined child supplies
bounded mode/geometry/signal data only, never a PID/PGID, ticket, route, expiry or
sequence. The already authenticated root monitor assigns the next sequence on
the same retained Guest connection. Initial PTY acknowledgement precedes relay
registration and SCM; no intermediate sshd PTY, passwd shell or replacement TERM
environment is introduced. Resize preserves row, column and both pixel counts
without truncating SSH unsigned values. The Guest applies the bounded RFC4254
mode table to its actual retained original master and requires native readback;
unknown platform modes remain ignored according to the RFC.

`AOSMCQ05` contains a root-owned sequence, closed action and bounded payload.
The Guest can queue this data before or after original SCM, but queuing grants
nothing. The existing Controller forward poll reauthorizes the original
LifecycleControl capability/holder under current protected policy, revocation,
trust and registration. Its borrowed writer signs an exact Host ATTACH plan
committing the original grant/ticket, monitor binding, readback challenge and
request bytes. Host retains the original runtime/assignment and named route
journal writer through a durable per-ticket/session/sequence reservation,
protected Guest dispatch and final receipt. A partial or equal reservation is
not recoverable permission or a redispatch path.

The Guest holds one barrier across its monitor lock, actual original execution
tree/PTY owner, durable sequence reservation, kernel effect and original-root
acknowledgement. Whole-tree Signal uses the existing freeze/pin/preflight/recheck
producer and restores exactly its own original freezer request; KILL uses the
original descendant `cgroup.kill`. No leader-only/PGID substitute is accepted.
The narrowed original certificate/capability/policy expiry and local BOOTTIME
deadline remain mandatory for controls even when the original leader exited or
descendants legitimately changed credentials or session IDs. The V4 terminal
reader remains separately nonauthorizing after expiry.

Signed `AOSHCR05` queue/effect evidence uses the existing provisioned agent
runtime key for readback only, not a grant or second certificate. The packet
commits the original monitor witness, physical ticket readback, exact request
and whether original SCM was attempted; an attempt may be ambiguous and cannot
authorize another transfer. Sequence state moves with actual consumed custody
and is never re-created from a cold row. Any partial effect/readback/ACK is
ambiguous and drops custody without automatic redispatch. This full source
producer is still unqualified, not an installed readiness assertion.

Initial registration, relay and consume now also require the original unexpired
root/holder/ticket custody and active original execution subtree, not a live
leader with unchanged effective UID. The Guest retains that actual in-memory
tree borrow, the shared barrier and monitor custody through SCM and receipt.
The callback's separately named protected profile reader checks the original
expiry and installation without treating historical leader fields as authority.
Its output still cannot bind custody or authorize IO. Issuance, provisioning,
original route installation and immutable ticket binding retain their stricter
leader checks; this path cannot recover or recreate those earlier mutations.
V4 historical terminal evidence remains separately nonauthorizing.

Compatibility follows the pinned upstream private monitor layout. The patch
adds a default-off global option. V3 uses private readiness opcodes 118/119 and
relay opcodes116/117, data-only terminal opcodes120/121 and original control
opcodes122/123. Legacy114/115 cannot
mint v3 custody. It does not widen
the public SSH protocol. The Guest registration decoder has an explicit v3
magic and closed canonical profile, not a generic root-command
transport. Darwin retains ordinary unpatched OpenSSH.

Primary source boundaries are OpenSSH `V_10_5_P1` `monitor.c` (key verification,
full method/account decision, post-auth private channel), `sshd-session.c`
(PAM setup, exact post-auth fork/drop/key-state ordering), and `auth-pam.c`
(credential/session result state). Linux7.2.3 pidfs and Unix peer/record pidfd
carriers remain the existing `aos-sandbox-linux` boundary.

The inspected official tarball SHA-256 is
`d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11`,
matching the package pin. The patch passes a non-mutating applicability check
against that unpacked source. Tagged primary references are
[monitor.c](https://github.com/openssh/openssh-portable/blob/V_10_5_P1/monitor.c),
[sshd-session.c](https://github.com/openssh/openssh-portable/blob/V_10_5_P1/sshd-session.c),
and [auth-pam.c](https://github.com/openssh/openssh-portable/blob/V_10_5_P1/auth-pam.c).
Linux-PAM 1.7.1
[pam_private.h](https://github.com/linux-pam/linux-pam/blob/v1.7.1/libpam/pam_private.h)
and [pam_handlers.c](https://github.com/linux-pam/linux-pam/blob/v1.7.1/libpam/pam_handlers.c)
use `/etc/pam.d` for the service-file search; the VM's test services are written
there, not through package symlinks or into a host/store/cache directory.

Qualification is pending. Rust hostile/canonical/signature tests and the pinned
OpenSSH VM fixture are **UNRUN**. The native fixture checks an actual fully
authenticated root monitor record and child/relay pidfds, foreign monitor/child/
wrong-descriptor rejection, same-login ptrace/process-vm/proc-memory/proc-FD
denial, hostile passwd-shell bypass, old-child pidfd closure, incomplete MFA,
nologin and PAM account/credential/session denials. A fixed fixture process's
real stdin/stdout/stderr pipes exercise the native relay transport and receipt.
The native terminal case uses the real fixture process's raw waitstatus for
exit code37 and checks SSH returns37 rather than relay success. The fixture,
including its socket responder, is not a production original-execution
authority source.
Those test pipes do not qualify production Guest reservations or the held
Controller/Host currentness cut; complete installed end-to-end qualification
is still required before public readiness or I/O activation.
The denial fixture also asserts actual root signature verification and its
expected partial/PAM denial phase, so a bad configuration or missing PAM service
file cannot count as qualification. The old-child test checks the retained
original pidfd becomes unusable; it does not force actual numeric PID reuse.

The repository's exact
[Linux7.2.3 primary archive](https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.2.3.tar.xz)
has SHA256 `8ba259e8e7b13ec6ef0941c8a39ad90b24bd4a4d6c0010ba6bafb794550ecd03`.
Its `kernel/ptrace.c` checks credential equality and nondumpability before the
LSM hook; Yama is not a blanket proc-read proof. `fs/exec.c` can reset
dumpability on ordinary exec, hence the no-exec boundary. `net/socket.c`
preserves requested `MSG_CMSG_CLOEXEC` in receive output; relay accepts only
that bit and rejects truncation/other flags. `security/selinux/hooks.c` checks
both cross-subject FD use and inode access after the Owner/Tenant transition.
The production copied-TCB/loader/config/namespace and MAC projection, not
fixture ancestry or UID alone, remain required installed prerequisites.

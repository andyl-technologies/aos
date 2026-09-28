# Fixed original-ticket monitor custody and confined relay

This Linux-only patch applies to the hash-pinned OpenSSH 10.5p1 source in
`../openssh.nix`. Ordinary OpenSSH defaults `AosAttachMonitorV2` to `no`.
The existing Guest daemon owner opts in with fixed launch arguments; no new
listener, principal, key, credential issuer, or authentication bypass is added.
Original configuration, AOSAPG01, certificate and base-route bytes are unchanged.

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
monitor proof from ticket files or callback metadata. Exit, expiry, ambiguity
and cancellation close retained handles; no cached success restores custody.

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
Cold restart and cached broker completion cannot recover handles or transfer
again. Public Create/launch/readiness activation remains closed pending complete
installed qualification; source availability is not readiness.

Original Stream/OpenSSH execution admission requires disconnect cancellation.
This checkpoint does not yet retain post-transfer session liveness or an exact
per-execution cgroup subtree. The existing Guest cancellation uses a process
group, which cannot contain every descendant of an arbitrary admitted command;
the retained Host payload cgroup instead contains the entire sandbox. Neither
is promoted to whole-execution custody. A subsequent existing-owner slice must
provision a private execution subtree, pin membership before payload exec,
exclude tenant migration, and hold the same barrier through disconnect,
`cgroup.kill`, empty-subtree readback and terminal publication. Disconnect
cancellation and public I/O readiness remain closed until that path is
implemented and installed qualification succeeds.

Compatibility follows the pinned upstream private monitor layout. The patch
adds a default-off global option. V3 uses private readiness opcodes 118/119 and
relay opcodes 116/117; legacy 114/115 cannot mint v3 custody. It does not widen
the public SSH protocol. The Guest registration decoder has an explicit v3
magic and closed canonical profile, not a generic root-command
transport. Darwin retains ordinary unpatched OpenSSH.

Primary source boundaries are OpenSSH `V_10_5_P1` `monitor.c` (key verification,
full method/account decision, post-auth private channel), `sshd-session.c`
(PAM setup, exact post-auth fork/drop/key-state ordering), and `auth-pam.c`
(credential/session result state). Linux 6.18 pidfs and Unix peer/record pidfd
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
Those test pipes do not qualify production Guest reservations or the held
Controller/Host currentness cut; complete installed end-to-end qualification
is still required before public readiness or I/O activation.
The denial fixture also asserts actual root signature verification and its
expected partial/PAM denial phase, so a bad configuration or missing PAM service
file cannot count as qualification. The old-child test checks the retained
original pidfd becomes unusable; it does not force actual numeric PID reuse.

Linux 6.18 [ptrace.c](https://github.com/torvalds/linux/blob/v6.18/kernel/ptrace.c)
checks credential equality and nondumpability before its LSM hook. Yama is not
used as a blanket proc-read proof. Ordinary exec can reset dumpability in
[exec.c](https://github.com/torvalds/linux/blob/v6.18/fs/exec.c), hence the no-exec
boundary. [socket.c](https://github.com/torvalds/linux/blob/v6.18/net/socket.c)
preserves the requested `MSG_CMSG_CLOEXEC` flag in receive output; the relay
allows only that bit and rejects truncation or any other returned flag.

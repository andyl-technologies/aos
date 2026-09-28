# Fixed attach monitor custody (v2)

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

The wire profile is `AOSAMR02`, account UID/GID as big-endian u32 values, then
four u32-length-prefixed sections: KEX session (32–64 bytes), actual binary
certificate (1–4096), original signed userauth message (1–8192), and original
SSH Ed25519 signature (1–128). The complete record is bounded to 13312 bytes,
with exactly one transferred child pidfd. `AOSAMB02` acknowledges binding only
and contains no descriptor. Unknown versions, zero/overflowing section lengths,
trailing bytes and unexpected ancillary data are rejected.

V2 `reserve_attach` and execution SCM_RIGHTS remain closed. This patch does not
make the unprivileged post-auth child a continuously trusted relay. Shell-free
dispatch, memory/procfd/descriptor confinement and a held Controller policy/
revocation plus Host assignment/current runtime cut through one-use consume and
final transfer are separate, unsatisfied prerequisites. Future consume must use
this same retained root connection and original ticket, not a reconstructed
grant, callback reflection, replacement child or renewed certificate.

Compatibility follows the pinned upstream private monitor layout. The patch
adds a default-off global option and reserves private readiness opcodes 114/115;
it does not widen the public SSH protocol. The Guest registration decoder has
an explicit v2 magic and closed canonical profile, not a generic root-command
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
authenticated root monitor record and child pidfd, foreign monitor/child/wrong
descriptor rejection, old-child pidfd closure, incomplete MFA, and PAM account,
credential and session denials. It serves no execution descriptor and does not
qualify Controller currentness, continuous confinement or production I/O.
The denial fixture also asserts actual root signature verification and its
expected partial/PAM denial phase, so a bad configuration or missing PAM service
file cannot count as qualification. The old-child test checks the retained
original pidfd becomes unusable; it does not force actual numeric PID reuse.

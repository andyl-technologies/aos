# RFC-0013 implementation plan

This plan sequences the recovery UKI so that every intermediate state is
explicitly safer than the current one. File names are current-tree anchors;
implementation may factor helpers as needed while preserving the RFC's
invariants.

## Implementation status

Phases 1 through 8 are implemented. Final fleet qualification remains in
progress; the implementation details and remaining release prerequisite are
recorded below. Every base initrd now carries an impossible root
password hash and masks the upstream interactive emergency and rescue
services. The debug profile retains separate, explicitly enabled direct
gettys; its stage-2 empty root password remains part of that development-only
posture. Security checks distinguish those two configurations instead of
weakening the production assertion.

The fleet negative test boots a production-profile image directly into the
initrd emergency target, proves that the target was reached and switch-root
did not occur, and rejects any sulogin, login, or debug-shell prompt in the
serial transcript. The rendered initrd unit topology supplies the complementary
proof that both interactive upstream services resolve to `/dev/null`.

Verity images now install a single generator-path boot-identity guard. It
requires the complete canonical normal tuple, including exactly one
`rd.luks=0` so automatic LUKS discovery cannot race the AOS `/var` unlocker,
and rejects duplicate scalars,
uppercase hashes, recovery selectors, verity options, rd/non-rd systemd
control aliases, and generator-provided unit or drop-in controls. Non-verity
images do not install this strict production guard; they retain the locked
initrd boundary from Phase 1.

The guarded initrd removes `systemd-debug-generator`,
`systemd-run-generator`, and duplicate discoverable copies of the verity
generator from systemd's compiled-in immutable-store directory. One explicit
verity generator remains in `/lib`; debug images continue to use their
explicit gettys, not kernel-command-line generator controls. That verity
implementation is the only remaining generator allowed to consume verity
fields. After PID 1 has established procfs and the final `/run` mount, a
dedicated oneshot validates the command line, requires the complete generated
root unit to exist, and publishes the success marker. The generated verity unit
and all `/var` consumers require the static guard, so parsing untrusted input
does not authorize any storage effect. Validation deliberately does not depend
on generator-time `/proc`, and the generator itself never publishes success.
The validator accepts the exact root unit from any of systemd's three standard
generator output priorities, since that placement is an upstream implementation
detail, but it never accepts a different unit name. Rejection isolates to the
passive failure target; that target explicitly permits isolation and conflicts
with initrd root, switch-root, emergency, and rescue targets.
`systemd-veritysetup@root`, `/var` unlock, and `/var` mounting all require the
success marker. This makes the guard a storage dependency instead of a
diagnostic race.

Phase 2 validates internal consistency but cannot by itself distinguish a
complete valid slot-A tuple appended in place of slot B (or the reverse),
because both UKIs currently share the same initrd. Phase 3 closes that
authorization gap: `/var` enrollment pins PCRs 7 and 12 and uses the signed
PCR-11 policy. Recovery-key-authorized migration keeps the old TPM token until
the exact replacement token has been tested and durable transaction evidence
has been published. Quote verification retains PCR 12 through both local and
remote policy decisions.

Secure Boot plus verity images now build two separately signed, uncounted
recovery UKIs. Each contains a copy-specific dedicated initrd, the exact
recovery command line, an embedded db-signed slot manifest, and no normal
`.pcrsig`. The recovery unit graph has no normal root, switch-root, TPM unlock,
provisioning, activation, package management, debug getty, or automatic
network path. The console application accepts only fixed menu operations.

Normal slot verification shares the Phase-2 command-line parser. It verifies
the UKI's Authenticode signature, copy/slot/release identity, root hash, and
dm-verity tree without mounting the root. One-shot boot consumes an in-memory
capability created by a successful verification in the same process. Access
to `/var`, a maintenance shell, or restore writes requires the exact retained
`systemd-recovery` token and its off-machine recovery key; no credential is
embedded in the image.

Image-generation state records the paired recovery copy, known-good copy, and
pending publication. The existing inactive-slot transaction writes root and
verity data, stages the normal UKI, publishes and read-back-verifies the
matching recovery UKI and uncounted entry, and exposes the counted normal UKI
last. Injected cuts at every publication boundary in both A-to-B and B-to-A
directions must leave the opposite recovery copy unchanged.

Neither the state record nor an ESP digest is retention authority. Initial
seeding and every later inactive-slot update re-verify the retained recovery
UKI against the deployment db snapshot stored in the immutable running
toplevel, then require its signed command line, release, copy, and ABI to match
the canonical record. The updater likewise authenticates every discoverable
normal UKI and derives its slot from the signed command line; mutable
generation state must agree. A retry after candidate publication first
disarms that exact candidate again and replays the transaction, while any
other mixed discoverable/disabled state fails closed.

The image build also emits a fixed-layout removable-media bundle. Its strict
ten-component manifest is authenticated by the deployment db key and repeated
in the signed release catalog; the consumer requires both representations to
agree. Recovery mounts only the fixed `AOS-RECOVERY` filesystem on a
kernel-reported removable parent outside the installed disk, read-only,
rejects unaccounted or non-regular files, verifies all sizes and digests before
authorization, re-verifies every UKI's Authenticode signature and signed
slot/copy identity, and permits writes only to the slot opposite the running
recovery copy. Recovery and its loader entry are published before the restored
normal counted UKI.

The same deployment db hierarchy authenticates recovery UKIs, slot metadata,
the release catalog, and the detached removable-bundle manifest. There is no
second ad-hoc recovery trust root. This authenticates code and payloads, not
the operator: destructive or state-bearing operations still require the
per-machine LUKS recovery key.

Production maintenance remains gated on the Phase-6 escrow prerequisite.
Building the recovery environment does not prove that a deployment has
off-host generation, retrieval, rotation, removal, and incident exercises for
its per-machine recovery keys.

## Phase 1: Lock the normal initrd

### 1.1 Base shadow entry

Change `modules/base/_initrd-builder.nix` from an empty password field to an
impossible hash:

```text
root:!*::0:99999:7:::
```

Do this for every base initrd, not only Secure Boot builds. An unsigned image
cannot protect a baked password, so it does not receive a fallback credential.

Keep `modules/profiles/debug.nix` as the only opt-in development autologin. Its
direct gettys do not authenticate through the base shadow field and therefore
do not require the empty password entry.

Omit or mask the upstream interactive `emergency.service` and `rescue.service`
in the base initrd. The targets may remain as dependency/failure states, but
must not start `sulogin`. The debug profile continues to provide its explicit
direct gettys when enabled.

### 1.2 Posture-aware checks

Replace `modules/tests/security.nix`'s file-existence check with an assertion
that parses the root shadow field and requires `!` or `*` in the base posture.
Keep separate assertions for debug autologin fixtures rather than weakening the
production check with a broad exception.

Add a fleet test that deliberately enters normal initrd `emergency.target` and
proves no shell prompt accepts input. The test must distinguish a blocked
`sulogin` from a boot that simply failed before reaching the service.

## Phase 2: Validate boot identity before use

### 2.1 Normal tuple parser

Implement one parser for the security-relevant command-line tuple:

```text
root
roothash
systemd.verity_root_data
systemd.verity_root_hash
systemd.verity_root_options, when configured
rd.systemd.unit
aos.recovery
rd.luks
```

The parser rejects repeated scalar keys even when the values match, validates
the root hash syntax, and enforces A/A-hash or B/B-hash pairing. Repeatable
non-identity fields such as `console=` remain permitted.

Share test vectors with the later recovery slot verifier so runtime and
off-line interpretation cannot drift.

The first implementation configures no verity options and therefore rejects
`systemd.verity_root_options` rather than accepting an arbitrary nonempty
value. A future configured option must be matched exactly before the allowlist
is widened.

### 2.2 Generator integration

Run validation before upstream verity generator output becomes actionable.
Supported implementation shapes are:

1. a small AOS wrapper installed at the normal generator path that validates
   then invokes the renamed upstream `systemd-veritysetup-generator`; or
2. a focused downstream systemd patch that performs the same uniqueness and
   tuple checks in the upstream parser; or
3. an unmodified, sole upstream verity generator whose generated root unit is
   statically ordered after and requires an AOS runtime guard. The guard runs
   only after procfs and `/run` are authoritative, verifies that the exact root
   unit was generated, validates the live command line, and publishes the
   success marker last.

A separate generator that merely races the upstream generator is not
acceptable. In the third shape, generated output is inert until the guard
succeeds: the verity unit and every `/var` path carry hard dependencies on the
guard rather than relying on generator order.

Make `aos-var-crypt.service` require a successful normal-mode guard and add an
explicit negative condition for `aos.recovery=1`.

Reject normal-mode `SYSTEMD_SULOGIN_FORCE`, alternate `rd.systemd.unit`, debug
shell, and recovery selectors unless they are part of the exact supported
signed posture. A guard failure enters a noninteractive fail-closed target; it
must not route attacker-controlled input into `emergency.target`.

Both `rd.` and non-`rd.` aliases are rejected for target, wants, debug shell,
breakpoint, transient command, and environment controls. Unit/drop-in command
line injection is rejected by prefix. The initrd also omits the upstream
generators that implement these controls, so later parser drift cannot silently
re-enable them.

### 2.3 Negative coverage

Boot with firmware/SMBIOS-added duplicates for each identity field and assert:

- the verity mapper is not accepted as the root;
- `/var` is not TPM-unlocked or mounted;
- no normal initrd root shell is available; and
- the failure is attributed to the guard in the journal/console.

## Phase 3: Bind `/var` to PCR 12

### 3.1 Qualification

Extend measured-boot fleet coverage to record PCR 12 for:

- clean slot A;
- clean slot B;
- a counted candidate boot;
- a committed candidate boot; and
- a normal reboot after commit.

Prove that supported clean boots share the policy's expected PCR-12 state. Any
current feature that intentionally extends PCR 12 must be modeled before the
default changes.

The measured-boot fleet path performs a bootloader/PCR qualification by
populating the inactive slot from the verified A bytes, booting the slot-B UKI
under a counted Type-2 filename, committing it with `systemd-bless-boot`, and
observing the subsequent stable reboot. Because the immutable payload is
intentionally identical, this does not claim to exercise APM's distinct-image
generation transition; the fixture restores the exact coherent slot-A image
index before later production-service tests. It requires the reset PCR-12
value for clean A, counted B, committed B, and the ordinary post-commit B
reboot. The test driver can relaunch the same writable disk,
firmware-variable store, and vTPM state with an exact SMBIOS Type-11 string set
so firmware-provided boot inputs are tested rather than simulated in the
guest.

### 3.2 Enrollment policy

Change `aos.boot.secureBoot.measuredBoot.pinnedPcrs` from `"7"` to `"7+12"`
(systemd's plus-separated command syntax) and update option documentation,
system fixture documentation, recovery docs, and tests.

Implement recovery-key-authorized token migration:

1. open the volume with the recovery key;
2. add a new TPM token bound to signed PCR 11 and pinned PCRs 7,12;
3. test the new token without removing the old one;
4. publish durable migration evidence; and
5. remove the PCR-7-only token only after successful verification.

`aos-var-policy-migrate` implements this as a recovery-key-authenticated,
idempotent transaction. It snapshots the LUKS2 JSON metadata, adds the new
token without wiping the old one, and validates the token ID and keyslot, PCR
7+12 pin, signed PCR 11 selection, embedded public-key bytes, SHA-256 bank, and
absence of alternate token modes. The supplied recovery key must open the
single keyslot named by the retained `systemd-recovery` token before and after
the transaction. The exact new external token is tested using systemd's
canonical runtime signature path.

Evidence advances atomically through `prepared`, `verified`, and `complete`
states, with file and containing-directory synchronization at each published
boundary. The `verified` record contains the exact retained and removal
keyslots before cleanup begins. Resume accepts only a subset of that recorded
removal set, so partial cleanup cannot expand its authority. Completed evidence
is validated and preserved byte-for-byte on idempotent reruns. The record
contains metadata digests, LUKS UUID, public-key digest, exact token identities,
and policy without recording key material.

An interrupted migration retains at least one working authorized unlock path.

Generation quote verification carries PCR 12 through the checked quote instead
of discarding it. Local boot commit compares quoted PCR 12 with the live TPM;
remote verification requires `aos.gen-attestation-policy/v2` and compares it
with the operator-authorized `expected_pcr12`. Version 1 policy is rejected
because it has no PCR-12 authorization field.

### 3.3 Injection tests

Inject an appended command line that changes PCR 12 and prove automatic unlock
fails. Exercise at least `SYSTEMD_SULOGIN_FORCE=1`, a duplicate `roothash=`, and
an alternate `rd.systemd.unit=`. The recovery key must still unlock the volume.
The fleet test also extends PCR 12 directly after a valid boot to isolate the
TPM-policy property: exact TPM-token use and local boot-commit verification
must fail, while the exact retained recovery keyslot must still open.

## Phase 4: Build the dedicated recovery initrd and UKI

### 4.1 Recovery initrd mode

Factor `_initrd-builder.nix` or add a focused sibling builder with an explicit
recovery mode. Do not build recovery by taking the normal initrd and relying on
one target to avoid dangerous units.

The closure excludes normal root mounting, switch-root, TPM `/var` unlock,
metadata acquisition, provisioning, activation, package installation, debug
gettys, and automatic networking. Add an evaluation check over the rendered
unit set and a closure check over forbidden executables/services.

### 4.2 Recovery target

Add `aos-recovery.target` with `DefaultDependencies=no`. It requires only the
console, minimal udev/device discovery, read-only EFI variable access, and the
recovery UI service.

The UI is a dedicated Rust subcommand or binary using structured operations.
Do not construct a shell script that interpolates user-selected devices,
paths, or commands.

### 4.3 UKI builder

Extend `pkgs/boot/aos-uki.nix` or add a typed wrapper for recovery UKIs. Recovery
uses the normal Secure Boot key/certificate but omits `pcrPrivateKey` and
`pcrPublicKey`, yielding no signed normal PCR-11 authorization.

Produce `recovery-a.efi` and `recovery-b.efi` with release/recovery-ABI metadata
and the signed recovery command line. Verify their PE signatures during the
build.

### 4.4 Image assembly

Place recovery UKIs under `EFI/AOS/` and add explicit, uncounted loader entries.
Update `image-info.json` with recovery paths, digests, byte sizes, release
identity, and recovery ABI.

Replace heuristic ESP sizing with a fit calculation that covers the installed
set and one complete inactive update transaction, including temporary files.

## Phase 5: Recovery menu and slot verification

### 5.1 Bounded status model

Define a typed recovery status document containing firmware state, recovery
copy, normal slots, UKI identity, verity result, and boot-count state. Do not
expose arbitrary file contents or raw block reads through the unauthenticated
interface.

### 5.2 Slot verifier

Reuse the boot-identity parser from Phase 2. For a selected slot:

1. verify the normal UKI and signed release identity;
2. extract the embedded command line;
3. enforce the slot tuple;
4. compare the root hash with authenticated image metadata; and
5. run `veritysetup verify` without mounting the root.

Return a structured reason for every failure. Never downgrade a signature,
metadata, or verity failure to a warning that still enables one-shot boot or
restore.

### 5.3 One-shot boot

Add a narrow helper that accepts only the resolved enum `SlotA` or `SlotB`,
requires a successful verification result from the same recovery session, sets
the corresponding firmware one-shot entry, syncs, and reboots.

Prove that the helper does not edit durable image-generation JSON or normal
boot counters.

## Phase 6: Recovery-key maintenance

### 6.1 Unlock flow

Prompt through `systemd-ask-password` and invoke `cryptsetup` with token-based
automatic unlock disabled. Select the LUKS recovery slot by its supported token
semantics rather than guessing a keyslot number.

On success, mount `/var` with the normal security flags and record that the
session is authenticated. On failure, close any partial mapping, erase key
material from temporary storage, and return to the bounded menu.

### 6.2 Maintenance shell

Only an authenticated recovery session may start the maintenance shell. The
shell receives an explicit PATH of AOS-built tools, no automatic network, and a
clear banner describing the mounted state and selected recovery copy.

Ending the shell unmounts `/var`, closes the mapping, clears session evidence,
and returns to the menu or powers off. A shell exit must not implicitly bless a
normal image.

### 6.3 Escrow prerequisite

Do not advertise maintenance recovery as production-ready until LUKS recovery
key generation, off-host escrow, retrieval, rotation, and removal are exercised
end to end. The existing `/run` output alone is not a durable escrow solution.

## Phase 7: A/B recovery lifecycle

### 7.1 State model

Extend image-generation state with recovery copy metadata sufficient to prove:

- which recovery file is paired with each slot;
- its release identity, digest, and recovery ABI;
- which copy is retained as known good; and
- whether an inactive-copy publication transaction is pending.

The state is evidence, not authority for Secure Boot or component digest
verification. At seed and immediately before the inactive slot is touched,
authenticate the retained recovery copy against the immutable running
toplevel's configured db-certificate snapshot and its signed
command-line/os-release identity. The snapshot includes the current image
signer and every build-configured rotation-overlap certificate, so an old-slot
UKI remains usable during an intentional overlap. It is not the mutable
registry roster: retiring a provisioned certificate requires a replacement
image that removes it from `sbDbCerts`, followed by qualification and firmware
db/dbx rollout. Mutable `/etc` trust files are never authority for this check.
Authenticate each installed normal UKI the same way and classify its slot from
that signed command line; reject disagreement with mutable generation state.

### 7.2 Transaction integration

Extend the existing inactive-slot transaction; do not create a parallel ESP
writer. The ordered write set is root, verity, normal UKI, then matching
recovery UKI/entry, followed by candidate arming.

Use temporary files, read-back verification, sync, and recoverable journals in
the same manner as the current normal UKI transaction. Recovery of an
interrupted journal must never choose deletion of the opposite known-good
recovery copy. A cut after normal-UKI publication but before stale-file cleanup
is replayable only when the sole discoverable inactive UKI is the exact
intended destination; disarm it again before replaying writes.

### 7.3 Boot tests

Exercise power cuts before and after each publication boundary in both A-to-B
and B-to-A directions. After every cut, boot at least one recovery copy under
enforcing Secure Boot and verify the known-good normal slot.

Stage a valid candidate, corrupt a block in its real root partition after
staging, and attempt the counted boot. Prove dm-verity prevents switch-root,
the failure exposes neither `/var` nor an initrd shell, boot counting falls back
to the retained slot, and the opposite recovery copy remains bootable. This is
stronger than the existing test that corrupts only a copied image and invokes
`veritysetup verify` directly.

## Phase 8: Authenticated recovery bundles

### 8.1 Bundle manifest

Define a versioned manifest over the existing root, verity, slot UKI, recovery
UKI, image metadata, platform, and module/recovery ABI outputs. Publication
requires exact equality with the copy in the signed system-image release
catalog. The removable copy also carries a direct deployment-db signature so
the offline initrd can authenticate it without registry state or networking.

Add strict size limits, path-free component identifiers, exact digests, and
architecture/platform constraints. The parser rejects unknown required fields,
duplicate components, traversal, symlinks, device nodes, and trailing
unaccounted payloads.

### 8.2 Offline transport

Support a removable filesystem with a fixed label and fixed bundle location.
Mount it read-only with `nodev,nosuid,noexec`. Verification copies no executable
content into the recovery environment.

Network download is deferred until the same bundle verifier is complete. It
must reuse the catalog trust model and may not introduce an unauthenticated
recovery URL or TLS bypass.

### 8.3 Restore transaction

Require successful LUKS recovery-key authentication before enabling any
restoration write. The authorization check may close the mapping without
mounting `/var`. Default restoration targets only the slot opposite the
recovery copy selected as known good. Display the resolved persistent devices,
source generation, and destructive effect; require exact confirmation; then
use the dedicated-initrd writer with the same inactive-slot ordering and
read-back contract as the normal writer. It remains dependency-free so the
recovery closure does not acquire APM, registry, or activation code; shared
crash-cut tests are the compatibility boundary between the two implementations.
Disabled inactive-slot UKIs are removed only after the new counted UKI is
synced and read back successfully. A retry reclassifies and disarms the exact
authenticated target set before replay, preventing both stale bootability and
unbounded ESP accumulation.

An authenticated maintenance session may request replacement of the retained
slot, but the tool must first prove the other recovery copy boots and validates
or require external rescue media. There is no `--force` shortcut that silently
removes the last recovery environment.

## Validation matrix

At minimum, add or extend these gates:

| Gate | Required proof |
| --- | --- |
| Eval | Recovery units/closures exclude forbidden normal services |
| VM boot | Locked normal initrd still boots healthy paths |
| Debug VM | Explicit debug autologin remains usable |
| Secure Boot | Both recovery copies boot; each tampered copy is rejected |
| Measured boot | Normal PCR 7/11/12 unlock works across A/B |
| Injection | Appended/duplicate identity cannot mount root or unlock `/var` |
| Recovery isolation | No TPM attempt, `/var` mount, switch-root, or network |
| Key auth | Wrong recovery key denied; correct key permits maintenance |
| Verity | A/B good, corrupt, and cross-slot tuples classified correctly |
| Live verity failure | Corrupt counted candidate cannot switch root and falls back |
| Boot counting | Recovery attempts leave candidate counters unchanged |
| Power failure | Opposite recovery copy survives every inactive update cut |
| Bundle | Valid restore succeeds; tamper is rejected before the first write |

Every negative gate records both the expected refusal and the absence of the
protected effect. A unit failure alone is not proof that `/var` stayed sealed
or that no shell was reachable.

## Documentation completion

After implementation, update:

- `docs/users/aos/recovery.md` with the exact menu, key workflow, slot restore,
  and external-reimage boundary;
- `docs/users/aos/security.md` with PCR 12 and recovery-key authority;
- `docs/users/aos/installation.md` with the paired recovery artifacts;
- `docs/users/aos/upgrades.md` with recovery-copy retention; and
- maintainer system-image documentation with recovery bundle publication and
  ESP budget inspection.

Until all relevant phases are implemented, documentation must label the
recovery UKI as unavailable and continue directing operators to tested external
rescue/reimage procedures.

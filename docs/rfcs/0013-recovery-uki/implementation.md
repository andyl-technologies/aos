# RFC-0013 implementation plan

This plan sequences the recovery UKI so that every intermediate state is
explicitly safer than the current one. File names are current-tree anchors;
implementation may factor helpers as needed while preserving the RFC's
invariants.

## Implementation status

Phases 1 and 2 are implemented. Every base initrd now carries an impossible root
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
requires the complete canonical normal tuple, rejects duplicate scalars,
uppercase hashes, recovery selectors, verity options, rd/non-rd systemd
control aliases, and generator-provided unit or drop-in controls. Non-verity
images do not install this strict production guard; they retain the locked
initrd boundary from Phase 1.

The guarded initrd deliberately omits `systemd-debug-generator` and
`systemd-run-generator`. Debug images continue to use their explicit gettys,
not kernel-command-line generator controls. The verity wrapper runs the
upstream generator against private output directories and publishes its unit
output and success marker only after both validation stages succeed. Rejection
selects the passive failure target through the early generator directory.
`systemd-veritysetup@root`, `/var` unlock, and `/var` mounting all require the
success marker. This makes the guard a storage dependency instead of a
diagnostic race.

Phase 2 validates internal consistency but cannot by itself distinguish a
complete valid slot-A tuple appended in place of slot B (or the reverse),
because both UKIs currently share the same initrd. The PCR-12 binding in Phase
3 is the required authorization boundary for any appended tuple substitution;
the implementation must not claim that guarantee until Phase 3 lands.

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
Preferred implementation order:

1. a small AOS wrapper installed at the normal generator path that validates
   then invokes the renamed upstream `systemd-veritysetup-generator`; or
2. a focused downstream systemd patch that performs the same uniqueness and
   tuple checks in the upstream parser.

A separate generator that merely races the upstream generator is not
acceptable. A later oneshot remains useful for image-state reconciliation but
is not the security boundary.

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

The measured-boot fleet path populates the inactive slot from the verified A
bytes, boots the slot-B UKI under a counted Type-2 filename, commits it with
`systemd-bless-boot`, and observes the subsequent stable reboot. It requires
the reset PCR-12 value for clean A, counted B, committed B, and the ordinary
post-commit B reboot. The test driver can relaunch the same writable disk,
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
verification.

### 7.2 Transaction integration

Extend the existing inactive-slot transaction; do not create a parallel ESP
writer. The ordered write set is root, verity, normal UKI, then matching
recovery UKI/entry, followed by candidate arming.

Use temporary files, read-back verification, sync, and recoverable journals in
the same manner as the current normal UKI transaction. Recovery of an
interrupted journal must never choose deletion of the opposite known-good
recovery copy.

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
UKI, image metadata, platform, and module/recovery ABI outputs. Authenticate it
through the current signed system-image release catalog.

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
reuse the normal inactive-slot writer and read-back verification.

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

# RFC-0013: A/B-aware signed recovery UKIs and initrd fail-closed hardening

- **Status:** Proposed
- **Date:** 2026-08-17
- **Audience:** maintainers of `modules/image/`, `modules/base/_initrd-builder.nix`,
  `modules/base/secure-boot.nix`, `modules/services/boot-substrate.nix`,
  `pkgs/boot/aos-uki.nix`, the APM system-image lifecycle, and Secure
  Boot/measured-boot fleet tests.
- **Relates to:** [RFC-0006](../0006-secure-boot/README.md),
  [RFC-0011](../0011-on-host-config-eval/README.md).
- **Plan:** [`implementation.md`](implementation.md)

## Summary

AOS will ship two separately signed, uncounted recovery UKIs alongside its
counted A/B normal boot UKIs. Recovery copy A and recovery copy B follow the
same overwrite discipline as the immutable root slots: an update may replace
only the inactive copy, so a power loss or bad candidate cannot destroy the
last recovery environment.

The normal initrd root account is locked with an impossible shadow hash. AOS
does not ship a default password: a password shared by every image is public
once the image or Nix store closure is available. Ordinary initrd
`emergency.target` and `rescue.target` therefore fail closed. The existing
explicit debug autologin posture remains the development escape hatch and does
not depend on a password.

Booting a recovery UKI authenticates the recovery *code*, not the person at the
console. Recovery initially exposes a constrained local menu. Inspecting and
verifying immutable slots is available without a credential. Access to
encrypted persistent state or an unrestricted maintenance shell requires the
off-machine LUKS recovery key. The recovery UKI carries no normal signed PCR-11
authorization, does not start `aos-var-crypt`, and cannot auto-unseal `/var`.

This RFC also includes three security fixes that remain applicable to the
current A/B design:

1. reject ambiguous boot-identity command-line fields before verity assembly,
   root mounting, or TPM unlock;
2. bind the normal `/var` TPM policy to PCR 12 as well as the existing signed
   PCR 11 and pinned PCR 7; and
3. replace the current no-op root-lock test with posture-aware assertions and
   negative fleet coverage.

This RFC does **not** adopt a single-ESP installer, ESP-resident `rootfs.bin`,
or first-boot root `CopyBlocks=` design. Those ideas conflict with the
implemented A/B image lifecycle and RFC-0011's authenticated, host-driven
storage provisioning boundary.

## Current state

The current raw image contains an ESP followed by immutable `root-a`,
`root-a-hash`, `root-b`, and `root-b-hash` slots. APM stages a system-image
candidate into the inactive root/hash slot, writes its slot-specific UKI, and
uses sd-boot boot counting for acceptance or automatic fallback. First-boot
`systemd-repart` owns mutable host storage only; it treats the ESP, roots, and
verity partitions as frozen image state.

The verified-boot path already provides important foundations:

- the build-time dm-verity root hash is baked into the signed and measured UKI
  command line;
- normal slot A and slot B UKIs name matching root and hash devices;
- the measured-boot suite verifies the live `/dev/mapper/root`, root hash, and
  slot pairing; and
- the image-generation transaction retains a known-good slot until a candidate
  has booted and committed.

Four gaps remain:

1. The initrd shadow file gives root an empty password. Outside the explicit
   debug profile, an ordinary `sulogin` fallback can therefore become an
   unauthenticated root shell.
2. Duplicate `roothash=`, `root=`, and verity device hints are rejected only by
   profile seeding after `/sysroot` and `/var` are mounted. That is a useful
   consistency check but is too late to protect verity selection or TPM
   unsealing.
3. `/var` is sealed to signed PCR 11 plus pinned PCR 7. PCR 12 is quoted for
   attestation but is not part of the LUKS unlock policy, so appended command
   line, profile, credential, or confext measurements do not currently deny
   automatic state access.
4. AOS has no signed on-disk recovery environment independent of the normal
   root slots. Recovery from a failed candidate depends on automatic fallback,
   a still-bootable normal slot, or external rescue media.

## Security work accounting

An earlier single-ESP installer design combined its obsolete layout with
several independent hardening observations. This RFC accounts for each
security-relevant item so rejecting that installer layout does not lose valid
work:

| Security item | Current disposition |
| --- | --- |
| Root hash in the signed UKI command line | Already implemented by RFC-0011; retained unchanged |
| Stable ESP partlabel | Already implemented as `/dev/disk/by-partlabel/ESP` |
| Signed recovery profile | Redesigned here as separate, paired, uncounted recovery UKIs |
| Exclude recovery from normal PCR-11 authorization | Required here by building recovery without the normal `.pcrsig` |
| Lock the initrd root account | Required in Phase 1, with no unsigned-image default password |
| Pin PCR 12 for `/var` | Required after clean A/B measurement qualification and token migration |
| Reject duplicate injected root identity | Moved to an early generator/wrapper boundary rather than the current late check |
| Prove dm-verity rejects corrupted root data | Existing copy-based test retained; add a real candidate-slot corruption/fallback test |
| Assert stage-2 root is locked | Replace the current file-existence check with an actual shadow-field assertion |
| ESP-resident `rootfs.bin` and root `CopyBlocks=` | Rejected as incompatible with the implemented A/B image/storage boundary |

## Goals

- Make ordinary initrd failure paths fail closed without a shared password.
- Preserve a signed recovery environment across every A/B update transaction.
- Keep normal boot counting and recovery selection independent.
- Prevent a recovery boot from automatically unlocking or mounting `/var`.
- Use the existing off-machine LUKS recovery key as authorization for
  persistent-state access and a full maintenance shell.
- Verify both immutable slots without trusting their root filesystems.
- Reject ambiguous boot identity before any consumer acts on it.
- Close the appended-command-line-to-`/var` path by pinning PCR 12.
- Preserve the explicit debug/autologin development posture.
- Provide executable negative tests for every security boundary.

## Non-goals

- Replacing the current A/B root and verity partitions with a single-ESP
  installer.
- Storing a root image or general reinstallation payload on the ESP.
- Shipping a universal recovery password, password hash, key, or derivation
  recipe.
- Treating Secure Boot signature verification as operator authentication.
- Automatically unlocking `/var` from recovery.
- Making first-boot storage provisioning replayable after its durable commit.
- Guaranteeing confidentiality for operator-created unencrypted data
  partitions. A passwordless diagnostic path must not mount or expose them.
- Making remote/network recovery the default. Recovery is local-console and
  network-off until an authenticated operation explicitly enables it.

## Security invariants

The implementation MUST preserve all of the following:

1. **No shared credential.** Neither the initrd, recovery UKI, ESP, Nix store,
   nor image metadata contains a reusable root or recovery password.
2. **Locked normal initrd.** The normal initrd shadow field is an impossible
   hash such as `!*`. The base initrd also omits or masks the interactive
   `emergency.service` and `rescue.service`; debug gettys remain an explicit
   opt-in rather than a fallback reached through `sulogin`.
3. **Explicit insecure development posture.** Debug autologin is enabled only
   by its existing opt-in module and is visibly incompatible with production
   recovery guarantees.
4. **Recovery code authentication is not operator authentication.** A db
   signature allows firmware to execute the recovery UKI; it grants no access
   to encrypted state and no unrestricted shell.
5. **No TPM auto-unseal in recovery.** Recovery has no normal signed PCR-11
   policy, does not start `aos-var-crypt`, and never mounts `/var` unless the
   operator supplies its recovery key.
6. **At least one retained recovery copy.** No transaction may overwrite both
   recovery UKIs. The copy paired with the known-good normal slot remains
   untouched while the inactive slot is staged.
7. **Recovery is uncounted.** Selecting recovery never consumes or resets a
   normal candidate's sd-boot attempt counter.
8. **Immutable-slot verification is external.** Recovery verifies the signed
   UKI/root/hash tuple without executing or mounting the candidate root.
9. **Boot identity is unique.** Normal boot cannot proceed when security-
   relevant identity parameters are repeated, missing, cross-slotted, or
   outside the supported value set.
10. **Appended input denies state access.** Any PCR-12-changing boot input makes
    normal TPM unlock fail closed and require the recovery key.
11. **Unauthenticated operations do not expose or replace mutable state.**
    Before recovery authentication there is no general shell, network,
    arbitrary mount, raw read/write command, caller-supplied executable, or
    slot-restoration operation.
12. **Physical denial of service is not confused with confidentiality.** A
    local attacker may erase a disk. The design prevents unauthorized code
    execution and state disclosure; it cannot make physical storage
    indestructible.

## Boot artifacts and menu entries

The ESP carries normal Type #2 UKIs and explicit Type #1 recovery entries:

```text
ESP
├── EFI/Linux/
│   ├── aos-<generation>-slot-a+<left>-<done>.efi
│   └── aos-<generation>-slot-b+<left>-<done>.efi
├── EFI/AOS/
│   ├── recovery-a.efi
│   └── recovery-b.efi
└── loader/entries/
    ├── recovery-a.conf
    └── recovery-b.conf
```

The exact counted filenames remain owned by the existing image-generation
transaction. Recovery filenames and loader entry IDs MUST NOT match the
`default aos-*.efi` selector. Each recovery entry has a stable title that
includes the recovery copy and release identity, for example:

```ini
title AOS Recovery A (2026.08)
efi /EFI/AOS/recovery-a.efi
```

The entries are not assigned `tries`. Firmware still verifies the recovery PE
through Secure Boot, but sd-boot does not rename it or charge a normal image
candidate for the attempt.

Two copies are required even when they initially contain identical bytes. APM
associates recovery A with normal slot A and recovery B with normal slot B.
Staging an inactive normal slot may replace only its matching recovery copy.

The builder replaces the current ESP size heuristic with an actual fit budget
covering every normal and recovery artifact plus transaction headroom. A build
fails with a clear error rather than emitting an ESP too small for one complete
inactive-slot update.

## Why separate UKIs instead of UKI profiles

The earlier installer design proposed a recovery profile joined into the
install UKI. Profiles save duplicated kernel bytes, but they couple recovery
selection to the lifecycle of the normal boot file. In the current
implementation normal UKIs are renamed by sd-boot boot counting. A recovery
profile selected from a counted candidate can consume the candidate's attempts
or disappear when that candidate is replaced.

Separate recovery UKIs provide stronger and simpler invariants:

- recovery is never counted;
- each A/B overwrite has an independent retained recovery copy;
- recovery carries no normal `.pcrsig` by construction;
- its initrd can omit normal unlock/provisioning units rather than relying only
  on target ordering; and
- firmware rejection of a tampered recovery artifact can be tested directly.

The storage cost is accepted. Correctness takes precedence, and the ESP is
sized from actual contents rather than fixed at 512 MiB.

## Recovery UKI contents

Each recovery UKI is Authenticode-signed with the same deployment db identity
used for normal UKIs. It contains:

- the release kernel and a dedicated recovery initrd;
- a signed command line selecting `aos-recovery.target`;
- release identity and recovery ABI metadata;
- embedded public trust anchors required to verify AOS system-image metadata;
  and
- no PCR policy signature authorizing normal `/var` unlock.

The signed command line is equivalent to:

```text
console=ttyS0,115200 rd.systemd.unit=aos-recovery.target aos.recovery=1 rd.luks=0
```

The fixed serial console makes the bounded operator interface available on
headless systems without accepting a mutable console selector. It does not
contain `root=`, `roothash=`, or normal verity device hints because
the recovery environment runs entirely from the initrd. The recovery initrd
does not switch root.

The recovery closure contains only AOS-built tools needed for:

- block/GPT/EFI inspection;
- PE and release-signature verification;
- dm-verity verification;
- LUKS recovery-key unlock;
- A/B state inspection and one-shot selection;
- bounded inactive-slot restoration; and
- an authenticated maintenance shell.

The recovery build explicitly excludes or masks:

- `aos-var-crypt.service`;
- normal `sysroot.mount` and switch-root;
- provisioning evaluation and `aos-repart.service`;
- configuration activation and package installation;
- debug autologin gettys;
- automatic filesystem discovery/mounting; and
- network activation before operator authentication.

Exclusion from the closure is preferred over target ordering. A unit that is
not present cannot be pulled in accidentally by a future dependency.

## Recovery interface and authorization tiers

Recovery starts one console application, not `sulogin`, `agetty --autologin`,
or a shell. Its initial interface is deliberately bounded:

```text
AOS Recovery

1. Show firmware, disk, and A/B status
2. Verify slot A
3. Verify slot B
4. Boot slot A once
5. Boot slot B once
6. Authenticate and restore an inactive slot from signed recovery media
7. Unlock persistent state and enter maintenance
8. Power off
```

Operations 1 through 5 do not mount mutable filesystems. They expose only
normalized status needed to choose a known-good signed image. They do not
provide arbitrary paths, commands, mounts, or byte reads.

Operation 6 requires the LUKS recovery key before any write. The tool may close
the successfully authenticated mapping without mounting `/var`; possession of
the key is the authorization event, not a requirement to expose state. This
prevents an unattended console user from using an old but correctly signed
bundle to expand the machine's rollback window. The bundle must still be a
versioned AOS artifact whose manifest is covered by the existing signed
system-image release authority. After authenticating, the tool verifies the
complete trust chain and payload digests before displaying the exact
destination slot and asking for an explicit destructive confirmation. It
refuses the slot associated with the retained known-good recovery copy unless
an authenticated maintenance session requests the override.

Operation 7 calls `cryptsetup` against the `var` partlabel and prompts through
`systemd-ask-password` for the off-machine LUKS recovery key. Only a successful
recovery-slot unlock may mount `/var` and start the maintenance shell. The TPM
token is not attempted. A wrong key returns to the menu without revealing a
shell or network service.

If `/var` and its recovery slot are destroyed, no universal fallback credential
exists. The supported paths are bounded immutable-slot restore, separately
controlled signed rescue media, or reprovisioning. This is an intentional
fail-closed boundary.

## A/B-aware slot verification

Recovery treats each normal image as a tuple:

```text
normal slot UKI
    ├── signed release and UKI identity
    ├── embedded root/hash partlabels
    └── embedded roothash
               │
               ▼
root-{a,b} + root-{a,b}-hash
    └── veritysetup verify
```

For each slot, verification MUST:

1. locate the exact normal UKI associated with that slot;
2. verify its Authenticode/release identity against recovery's trust anchors;
3. extract its embedded command line without executing it;
4. require exactly one `root=`, `roothash=`, `systemd.verity_root_data=`, and
   `systemd.verity_root_hash=` field;
5. require `/dev/mapper/root` plus the matching A/A-hash or B/B-hash pair;
6. require a well-formed SHA-256 root hash matching signed image metadata; and
7. run `veritysetup verify` over the selected data/hash devices and extracted
   root hash.

Recovery never mounts a slot merely to decide whether it is valid. A valid
result means the signed tuple is internally consistent and all verified blocks
match. It does not claim that stage-2 configuration or application services
will succeed; sd-boot boot counting and the normal image commit gate retain
that responsibility.

## One-shot normal boot selection

The unauthenticated menu may request a one-shot boot of a verified normal slot.
The helper:

1. resolves the exact sd-boot entry for that slot;
2. refuses an unverified entry;
3. writes only the firmware one-shot selection, using `bootctl set-oneshot` or
   the equivalent EFI variable operation;
4. does not change the durable image-generation state; and
5. reboots.

Selecting recovery never blesses, commits, resets, or consumes the pending
normal candidate. Normal boot remains responsible for reconciling firmware
selection with `/var/lib/profiles/image/state.json` after `/var` is available.

## Recovery bundle

The current image derivation already produces the components needed to stage
either slot: `root.img`, `root.verity`, slot-specific UKIs, root-hash metadata,
and `image-info.json`. The release pipeline will expose a versioned recovery
bundle containing those existing outputs plus a signed component manifest.

The manifest binds at least:

```text
schema version
system image generation and module ABI
architecture and platform constraints
root image digest and byte size
verity image digest and byte size
root hash
slot-A UKI digest and signed identity
slot-B UKI digest and signed identity
recovery-A UKI digest and recovery ABI
recovery-B UKI digest and recovery ABI
```

Publication requires the manifest to equal the copy in the signed system-image
release catalog. Offline recovery additionally verifies a direct signature by
the deployment db key already embedded in the recovery UKI; it does not carry
or replay the registry catalog chain. This makes the same deployment trust root
usable without networking and does not introduce an ad-hoc recovery signing
hierarchy. Recovery media may be removable local storage. Network retrieval is
a later transport over the same authenticated bundle format, not a second
trust model.

Inactive-slot restoration follows the existing system-image transaction's
write, read-back verification, ESP temporary-file, sync, and publication
contract. The dedicated initrd cannot link the full APM/sysroot implementation
without defeating its closure boundary, so its small dependency-free writer
implements the same ordered state machine: disarm the inactive normal UKI,
write and read back root and verity, publish recovery UKI and entry, then
publish the counted normal UKI last. Both writers share the same crash-cut
invariants and qualification matrix rather than a process or library
dependency. The running normal slot concept is absent in recovery, so the
retained recovery-copy rule supplies the safety boundary: by default only the
slot opposite the selected known-good recovery copy may be overwritten.

## Recovery update lifecycle

For an ordinary inactive-slot update from A to B:

1. Authenticate and fully materialize the candidate payload.
2. Verify that recovery A and normal slot A remain the retained known-good set.
3. Write and read-back-verify `root-b` and `root-b-hash`.
4. Publish the counted normal slot-B UKI using the existing ESP transaction.
5. Publish `recovery-b.efi` and its entry without touching recovery A.
6. Arm the counted normal candidate.
7. Boot B and run the existing configuration/image commit gate.
8. Preserve recovery A until a later accepted generation stages slot A.

Failure before step 6 leaves A and recovery A authoritative. Failure after
step 6 is handled by existing boot counting. Recovery B need not be promoted or
blessed: it is an independently signed tool and remains usable for inspection
even when normal B fails its userspace acceptance gate.

The same sequence applies in the opposite direction. Garbage collection MUST
never remove the sole recovery UKI whose signature and recovery ABI are known
good.

## Normal initrd root lock

The normal initrd shadow entry becomes:

```text
root:!*::0:99999:7:::
```

`!*` is not a password hash and cannot authenticate. No build option supplies
a default password. In particular, unsigned developer images do not receive a
shared password hash; inspectable unsigned media cannot keep that value secret.

The explicit debug autologin module continues to launch its direct root gettys
only when opted in. Those gettys do not need password authentication, so the
base initrd shadow entry can remain locked in every build. Tests and help text
must identify debug autologin as an intentional waiver of the production
console boundary.

The stage-2 default root entry remains locked. A host configuration may define
operator access through supported user, SSH, or debug policy, but the base
image does not silently create a root credential.

## Early boot-command-line guard

The current late duplicate check remains useful as defense in depth, but a new
guard runs before normal verity/root activation and before `aos-var-crypt`.

For a normal slot it requires exactly one of each:

- `root=/dev/mapper/root`;
- `roothash=<64 lowercase SHA-256 hex>`;
- `systemd.verity_root_data=/dev/disk/by-partlabel/root-{a,b}`; and
- `systemd.verity_root_hash=/dev/disk/by-partlabel/root-{a,b}-hash`.

The data and hash labels must name the same slot. Repeated fields are rejected
even when their values are identical. Any supported verity options also receive
single-value validation.

For recovery it requires exactly one `aos.recovery=1`, exactly one recovery
target selection, `rd.luks=0`, and the absence of normal root/verity identity.

This validation belongs at generator/wrapper level, before
`systemd-veritysetup-generator` emits an actionable root mapping. A later
oneshot alone is insufficient: generator output and unlock dependencies must
not be created from ambiguous input. The implementation may use an AOS wrapper
around the upstream generator or a focused downstream systemd patch, but must
not depend on generator enumeration order.

`aos-var-crypt` additionally requires the successful normal-mode guard and has
an explicit negative condition for `aos.recovery=1`. Thus a future regression
in recovery target composition cannot silently restore TPM unlock.

## PCR-12 binding

Normal `/var` enrollment changes from:

```text
signed PCRs: 11
pinned PCRs: 7
```

to:

```text
signed PCRs: 11
pinned PCRs: 7,12
```

PCR 11 remains signature-flexible across authorized normal UKIs. PCR 7 retains
the Secure Boot state binding. PCR 12 measures boot inputs outside the embedded
base command line, including appended/override command line and selected
profile/credential inputs. Pinning it makes such input deny unattended `/var`
access.

PCR 12 is pinned by value, not blessed by the PCR-11 policy key. The design
therefore carries an explicit compatibility rule: a feature that intentionally
changes the clean normal-boot PCR-12 event stream must version the measured-
boot policy and provide a recovery-key-authorized re-enrollment transition.
Silently broadening the accepted PCR-12 state is forbidden.

The rollout must first prove that clean normal A and B boots produce the
expected PCR-12 value and that ordinary boot counting does not perturb it.
Recovery may retain the clean reset value in PCR 12 because its recovery
selection lives in the embedded command line measured through the UKI/PCR-11
path. The no-unseal guarantee therefore does not rely on recovery producing a
different PCR-12 value: recovery has no authorized PCR-11 signature and omits
the automatic unlock service.

Existing LUKS tokens enrolled under the PCR-7-only policy are not rewritten
without authorization. Migration requires the recovery key, creates and tests
the new TPM token, and only then removes the old token. The current measured-
boot systems use test keys and are documented as validation fixtures, but the
transaction must still be implemented as if state were valuable.

## Threat analysis

### Shared-password disclosure

An attacker downloads the public image and reads the initrd shadow hash. With a
default password, the attacker either already knows the value or cracks the
same hash once for every AOS machine. This RFC ships no such hash; normal
`sulogin` cannot authenticate.

### Signed recovery selected by an unauthorized console user

Firmware executes authentic recovery code. The user can inspect normalized
immutable-slot status and request a verified one-shot boot. They cannot obtain
an arbitrary shell, mount `/var`, start networking, or TPM-unseal state. They
may erase hardware through physical means regardless; preventing physical
denial of service is out of scope.

### Appended `roothash=` or slot device

For a db-signed addon or SMBIOS source, the AOS EFI stub measures the external
fragment into PCR 12 but does not append it when the UKI has an embedded signed
command line. The kernel therefore sees the single signed root identity, while
the changed PCR 12 denies `/var` TPM unlock. Under enforcing Secure Boot,
systemd-boot measures Type #1 entry options into PCR 12 and the stub discards
them when an embedded command line exists. Unsigned addons are rejected by the
image loader before command-line measurement and leave PCR 12 unchanged. If a
duplicate or invalid tuple reaches the effective command line by another path,
the initrd guard rejects it before verity/root activation.

Recovery UKIs have no TPM-authorized degraded mode to preserve. If a db-signed
addon or SMBIOS source supplies an external command-line fragment, the stub
measures it and refuses the recovery launch before starting the kernel. A clean
relaunch remains available from the separately signed recovery entry.

### Appended `SYSTEMD_SULOGIN_FORCE=1`

When supplied by a db-signed addon or SMBIOS, the AOS EFI stub measures but
does not append the token, so it cannot select an init process or force a
prompt before userspace validation. PCR 12 denies `/var` auto-unseal, and the
base initrd contains no interactive `sulogin` unit. EFI LoadOptions and unsigned
addons follow the separate handling described above. If the token reaches the
effective command line by another path, the normal-mode guard rejects it into
the noninteractive fail-closed target rather than `emergency.target`. No
persistent state or shell is exposed.

### Tampered recovery UKI

UEFI Secure Boot rejects it. Fleet coverage corrupts each recovery copy and
proves firmware refusal independently, while retaining the other copy for the
test's continuation.

### Interrupted inactive-slot update

The update touches only the inactive root/hash/normal UKI/recovery UKI set. The
known-good normal and recovery set is unchanged. Existing boot counting handles
a candidate that was armed but cannot commit.

### Malicious recovery media

Recovery rejects any bundle whose catalog authorization, manifest, component
digest, architecture, platform, slot-specific UKI identity, or verity root does
not validate. It never executes content from the bundle.

### Stolen LUKS recovery key

The holder can unlock persistent state and obtain the maintenance shell at the
console. That is the declared authorization capability. Key escrow, rotation,
revocation, and incident response must treat it as a root-equivalent secret.

## Alternatives considered

### A default or image-wide password

Rejected. The password and its hash are shared public material, not an
authentication factor.

### A build-time password embedded in a private image

Rejected as the base mechanism. Nix store paths and build logs are not secret
storage, key rotation is coupled to rebuilding the image, and cloned machines
still share one credential. Deployments may add an independently reviewed,
machine-specific authentication mechanism without weakening the base policy.

### Passwordless full recovery shell

Rejected. Secure Boot authenticates code, not the console operator. An
unrestricted shell can inspect unencrypted devices, activate networking, and
invoke interfaces beyond the bounded recovery contract even if `/var` remains
sealed.

### Joined recovery profiles in each normal UKI

Rejected for v1. Profiles couple recovery to counted normal files and make PCR
policy scoping easier to misconfigure. Separate UKIs cost more ESP space but
make counting, update retention, initrd contents, and TPM exclusion explicit.

### One singleton recovery UKI

Rejected. Updating it creates a transaction in which power loss can remove the
only recovery environment. An A/B pair follows the already proven inactive-
slot rule.

### ESP-resident root image and `CopyBlocks=` reinstall

Rejected. It conflicts with the implemented frozen A/B root layout, consumes
ESP capacity, weakens the image/host storage boundary, and duplicates the
authenticated system-image staging transaction. Recovery media supplies large
repair payloads when needed.

### External rescue media only

Retained as the final fallback, but insufficient as the primary path. It does
not guarantee that every installed machine retains a firmware-trusted tool for
inspecting and selecting its A/B images.

## Rollout and compatibility

The rollout is deliberately staged:

1. lock the normal initrd and strengthen root-lock tests;
2. add the early normal boot-identity guard and its injection tests;
3. qualify and migrate the PCR-12 `/var` binding;
4. build one dedicated recovery initrd/UKI and prove its no-unseal boundary;
5. integrate the A/B recovery-copy update transaction and boot entries;
6. add the constrained menu and slot verification;
7. add authenticated `/var` unlock and maintenance;
8. publish and consume recovery bundles for bounded slot restoration.

Steps 1 through 3 are independently valuable and do not wait for the recovery
UI. After step 1, ordinary initrd failures intentionally have no interactive
shell until the signed recovery path lands. Operators of development fixtures
retain explicit debug autologin.

The recovery initrd publishes a `recovery_abi`. Version 1 accepts only ABI 1;
the build option is constrained to that value rather than advertising an
unsupported version. A recovery UKI may inspect slots only when their image
metadata version is supported and reports an unsupported version rather than
guessing. A future format transition must add an explicit qualification state
that retains the previous recovery copy until the new recovery ABI has booted
successfully in CI and on the candidate machine; the v1 paired-normal commit
record is not evidence of such a future ABI qualification.

## Acceptance criteria

The RFC is implemented only when all of the following are automated:

- the base initrd shadow field is locked in Secure Boot, measured-boot, and
  unsigned non-debug images;
- the debug autologin fixture remains reachable only when explicitly enabled;
- ordinary normal-mode emergency/rescue paths provide no shell;
- duplicate and cross-slot boot identity is rejected before root or `/var`;
- corruption of a staged real root slot prevents switch-root and falls back to
  the retained slot without exposing `/var` or an initrd shell;
- clean normal A and B boots unlock with PCRs 7, 11, and 12 as designed;
- PCR-12-changing injected input cannot TPM-unlock `/var`;
- recovery A and B each boot under enforcing Secure Boot;
- tampering with either recovery UKI is rejected by firmware;
- recovery boot never starts `aos-var-crypt`, mounts `/var`, or switches root;
- a wrong LUKS recovery key cannot reach maintenance;
- the correct key unlocks `/var` and permits the maintenance shell;
- both normal slots can be verified without mounting them;
- recovery one-shot selection does not change normal boot counters or durable
  image-generation state;
- an interrupted inactive-slot update leaves the opposite recovery copy
  bootable;
- a valid signed bundle restores an inactive slot and a tampered bundle is
  rejected before writes; and
- all new negative tests prove absence of access, not merely the presence of a
  unit or file.

## Documentation impact

Once implemented, the user recovery guide must distinguish:

- automatic counted-boot fallback;
- bounded unauthenticated recovery diagnostics;
- recovery-key-authorized maintenance;
- inactive-slot restoration from signed recovery media; and
- full external reimage when firmware, ESP, both recovery copies, or encrypted
  state is unrecoverable.

Until those gates pass, the current documentation remains authoritative: use a
known-good image, console or external rescue environment, and independently
escrowed deployment inputs.

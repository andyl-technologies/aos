# Recovery

AOS keeps two signed, uncounted recovery UKIs on the ESP beside its counted
A/B normal UKIs, and makes every normal initrd failure path noninteractive.
A recovery boot authenticates the recovery *code*; the person at the console
must still present the per-machine LUKS recovery key before touching
persistent state or getting a shell. Operator procedures are in [Recover an
AOS host](../../users/aos/recovery.md).

`aos.boot.recovery.enable` defaults to `aos.boot.secureBoot.enable &&
aos.security.verity.enable`, and evaluation asserts both prerequisites.
`aos.boot.recovery.abi` is constrained to `1`.

## Invariants

- No image, initrd, ESP file, or store path contains a reusable root or
  recovery credential.
- Normal initrds have a locked root account and no interactive emergency or
  rescue service. Debug autologin (`modules/profiles/debug.nix`) is the only
  explicit, opt-in exception.
- Recovery carries no normal `.pcrsig`, never starts `aos-var-crypt`, and
  never switches root, so it cannot unseal `/var` through the TPM.
- At most one recovery copy changes per transaction; the copy paired with
  the known-good slot is untouched while the other slot is staged.
- Selecting recovery never consumes or resets a normal candidate's boot
  counter.
- Slot verification never mounts or executes the slot being verified.

## Normal initrd boundary

The normal initrd seeds a locked shadow entry for root and masks the upstream
`emergency.service` and `rescue.service`
(`boot.initrd.systemd.maskedUnits`). On dm-verity images it also masks the
emergency and rescue targets, so a failure cannot reach `sulogin`.

dm-verity images add a boot-identity guard before any storage effect:

1. The upstream `systemd-veritysetup-generator` is not installed as a
   generator. A copy lives at `lib/systemd/aos-systemd-veritysetup-generator`,
   and `systemd-debug-generator` and `systemd-run-generator` are omitted, so
   command-line unit controls cannot be honored.
2. A runtime service validates `/proc/cmdline` with `aos-boot-identity`
   (`crates/boot/aos-boot-identity`) once procfs and `/run` are
   authoritative, then runs the private generator against staging
   directories, publishes only the expected root unit, and touches
   `/run/aos/boot-identity-valid` last.
3. `aos-boot-identity-guard.service` succeeds only when that marker exists.
   The verity root unit, `aos-var-crypt`, and the `/var` mount require it.
   Rejection isolates to the passive `aos-boot-integrity-failure.target`.

The parser requires exactly one each of `root=/dev/mapper/root`,
`roothash=<64 lowercase hex>`, `systemd.verity_root_data=`,
`systemd.verity_root_hash=`, and `rd.luks=0`. The data and hash devices must
be the `root-a`/`root-a-hash` or `root-b`/`root-b-hash` partlabel pair.
Repeated fields are rejected even with identical values, as are recovery
selectors and rd/non-rd systemd target, debug-shell, breakpoint, and
transient-command controls. Unrelated repeatable fields such as `console=`
pass through. The recovery verifier uses the same parser, so a tuple rejected
at boot cannot pass offline verification.

Because dm-verity authenticates blocks only when they are read,
`aos-verity-root-verify` reads the whole `/dev/mapper/root` before `/var` is
unlocked or mounted. A slot with a valid signed identity but corrupt data
fails into the same passive target and boot counting falls back.

Command-line injection is also stopped earlier. Under enforcing Secure Boot,
the stub treats an embedded `.cmdline` as authoritative: it measures but
does not append db-signed addon, SMBIOS, or Type #1 entry fragments, and
unsigned addons are rejected before measurement. The changed PCR 12 then
denies TPM unlock (see [Measured boot](measured-boot.md)). A recovery UKI
refuses to launch at all when such a fragment is present.

## Boot artifacts

`_boot-artifacts.nix` builds the ESP tree:

```text
ESP
├── EFI/BOOT/BOOTX64.EFI              signed systemd-boot
├── EFI/systemd/systemd-bootx64.efi   same bytes
├── EFI/Linux/aos-generation-0000000001+<tries>.efi   counted slot-A UKI
│                                     (+ .measurement and .measurement.sig)
├── EFI/AOS/recovery-a.efi
├── EFI/AOS/recovery-b.efi
└── loader/
    ├── loader.conf                   default aos-*.efi
    └── entries/
        ├── recovery-a.conf           title AOS Recovery A (<version>)
        └── recovery-b.conf           title AOS Recovery B (<version>)
```

The recovery files sit outside `EFI/Linux` and do not match `default
aos-*.efi`, and their Type #1 entries have no boot-count suffix. The build
checks that each recovery UKI's `.cmdline` is exactly

```text
console=ttyS0,115200 rd.systemd.unit=aos-recovery.target aos.recovery=1 rd.luks=0
```

and that it has no `.pcrsig` section. The fixed serial console makes the
interface usable on headless machines without accepting a console selector.

The builder writes `transaction-size-bytes` (the slot-B UKI, measurement
sidecars, and one recovery UKI and entry). The image build sizes the ESP from
the installed set plus that transaction and fails rather than emitting an ESP
that cannot stage an update; the resulting budget is recorded in
`image-info.json` (see [Build and customize release
images](../../maintainers/system-images.md)).

Each recovery UKI embeds a db-signed slot manifest
(`aos.recovery-slot-manifest/v1`, at `/lib/aos/recovery/slot-manifest.json`)
describing the release's normal slots, and an os-release with
`ID=aos-recovery` and `AOS_RECOVERY_ABI`.

## Recovery initrd

`_recovery-initrd-builder.nix` builds a separate archive per copy rather than
masking units in the normal initrd: a unit that is not present cannot be
pulled in by a future dependency change. Its closure is limited to
`aos-recovery`, bash, coreutils, cryptsetup, jq, kmod, openssl, pe-tools,
sbsigntools, systemd, util-linux, and `aos.boot.recovery.extraPackages` (for
storage backends whose state recovery must reach). It contains no normal root
mount, switch-root, provisioning, activation, package installation, TPM
unlock, debug getty, or automatic networking.

`aos-recovery.target` is the default target. Kernel-module loading is ordered
before the UI so dm-crypt and storage targets exist. The UI service binds
directly to `/dev/ttyS0` and, before starting, remounts efivarfs read-only,
unmounts any `/var`, and closes any `var` mapping. The authorized db
certificate snapshot is copied to `/etc/aos/trust/authorized-db-certs.pem`;
it holds the image signer plus every registry `sbDbCerts` entry kept for
rotation overlap.

## Console operations

`crates/boot/aos-recovery` validates the recovery command line, then loops
on a fixed menu at the `AOS recovery>` prompt. Operations are an enum, not
caller-supplied commands or paths.

| Operation | Credential | Effect |
| --- | --- | --- |
| Status | none | Normalized firmware, copy, and slot state |
| Verify slot A/B | none | Authenticode and signed identity of the slot UKI, command-line tuple, manifest root hash, `veritysetup verify`; no mount |
| Boot slot A/B once | none | Requires a successful verification in the same process; temporarily remounts efivarfs read-write, `bootctl set-oneshot`, sync, reboot |
| Restore inactive slot | recovery key | See below |
| Unlock `/var` | recovery key | Opens the keyslot of the single `systemd-recovery` token, never the TPM token |
| Maintenance shell | unlocked session | Explicit PATH of AOS tools; exiting unmounts and closes `/var` |
| Lock `/var`, power off | none | |

The key prompt uses `systemd-ask-password` on the service TTY and pipes the
response to cryptsetup's passphrase stdin, not `--key-file=-`, so the line
delimiter is not treated as key material.

## Removable-media restore

The image build exposes `system.build.recoveryBundle`, whose fixed
`aos/recovery/` directory holds ten components and a manifest:

| Component ID | File |
| --- | --- |
| `root-image`, `root-verity`, `root-hash` | `root.img`, `root.verity`, `root.roothash` |
| `normal-uki-a`, `normal-uki-b` | Slot UKIs named by `image-info.json` |
| `recovery-uki-a`, `recovery-uki-b` | `recovery-a.efi`, `recovery-b.efi` |
| `recovery-entry-a`, `recovery-entry-b` | `recovery-a.conf`, `recovery-b.conf` |
| `image-metadata` | `image-info.json` |

`recovery-bundle.json` (`aos.recovery-bundle/v1`) records release,
architecture, platform, recovery ABI, and each component's size and SHA-256.
`recovery-bundle.json.sig` is a direct signature by the db key, so the offline
initrd authenticates it without registry state or networking. Release
publication additionally requires the same manifest in the signed release
catalog.

The restore path:

1. Finds the unique filesystem labeled `AOS-RECOVERY` on a kernel-reported
   removable parent that is not the installed disk, and mounts it read-only
   with `nodev,nosuid,noexec`.
2. Verifies the manifest signature against the authorized db snapshot,
   rejects unknown or non-regular files, and checks every size and digest.
3. Re-verifies each UKI's Authenticode signature and signed slot or copy
   identity.
4. Targets only the slot opposite the running recovery copy, displays the
   release, and requires the exact confirmation `RESTORE SLOT A` or
   `RESTORE SLOT B`, then the recovery key.
5. Disarms the inactive normal UKI, writes and reads back root and verity
   data, publishes the matching recovery UKI and entry, and publishes the
   counted normal UKI last. Disabled old UKIs are removed only after that
   publication is synced and verified.

The writer is a small dependency-free implementation inside the recovery
initrd so the closure does not acquire APM, registry, or activation code. It
follows the same ordering and crash-cut invariants as the normal image
transaction.

## Update lifecycle

Image-generation state carries a `recovery` object per generation (copy,
paths, digest, size, release, recovery ABI), validated by
`crates/boot/aos-boot-runtime/src/recovery.rs`. The state is evidence, not
authority. Initial seeding re-verifies the paired recovery UKI against the db
certificate retained in the initrd closure, and each later inactive-slot
update re-verifies the retained copy against the running image's
certificate snapshot and its signed command line, release, copy, and ABI.
Each installed normal UKI is authenticated the same way and its slot is
derived from its signed command line; disagreement with mutable state fails
closed.

Normal UKIs carry their release as `AOS_RELEASE_ID` in the signed
os-release and omit `VERSION_ID`, so the local generation filenames remain
the only input to sd-boot's Type #2 ordering. Recovery UKIs keep
`VERSION_ID` for display.

For an update from A to B, the transaction writes and verifies `root-b` and
`root-b-hash`, stages the normal slot-B UKI, publishes `recovery-b.efi` and its
entry, then exposes the counted slot-B UKI. Recovery A stays untouched until a
later accepted generation stages slot A. A retry after publication first
disarms that exact candidate and replays; any other mixed state fails closed.

## Tests

| Check | Proves |
| --- | --- |
| `checks.fleet.initrd-emergency-fail-closed` | Requesting `emergency.target` yields no prompt and no switch-root |
| `checks.fleet.boot-identity-fail-closed` | An appended recovery marker reaches the passive target before root or `/var` |
| `checks.fleet.measured-boot` | Recovery boots without normal storage, refuses SMBIOS command-line input, rejects a wrong key, accepts the per-machine key, restores the opposite slot from signed media, rejects a corrupted manifest before any prompt, and leaves recovery A unchanged when a corrupt counted root falls back |

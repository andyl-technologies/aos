# Measured boot

Measured boot records what actually ran into a TPM and lets AOS seal the
`/var` encryption key so it opens only for an authorized boot. It is enabled
by `aos.boot.secureBoot.measuredBoot.enable` and requires Secure Boot.

## Signed PCR policy

Sealing `/var` to literal PCR values would break on the first upgrade: a new
UKI changes PCR 11. AOS instead uses systemd's signed policy model.

- `ukify build --pcr-private-key --pcr-public-key` (in
  `_uki-builder.nix`) measures the UKI's sections, signs a policy for every
  boot phase, and embeds it in the `.pcrsig` and `.pcrpkey` sections.
- `systemd-cryptenroll --tpm2-public-key` seals the key to "any PCR 11 value
  signed by this public key", not to one hash.

Any UKI carrying a valid signature from the PCR-policy key therefore unseals
`/var`, while an unsigned or tampered UKI does not. The policy also pins
other PCRs by value:

| PCR | Bound by | Records |
| --- | --- | --- |
| 11 | Signature (`signedPcrs`, default `11`) | UKI sections and boot phases |
| 7 | Value (`pinnedPcrs`, default `7+12`) | Secure Boot state and enrolled keys |
| 12 | Value | systemd-boot's entry selection plus any boot input outside the embedded command line: Type #1 entry options, db-signed addons, SMBIOS command-line fragments |

Pinned PCRs are not covered by the policy signature. Disabling Secure Boot,
enrolling a foreign key, or supplying external command-line input changes a
pinned value and denies unattended unlock; the recovery key is then the only
way in. A change that intentionally alters the clean PCR 12 event stream must
ship with a recovery-key-authorized re-enrollment.

The PCR-policy key is a third key, distinct from the db key and the
module-signing key. `ukify` invokes `systemd-measure`, which lives in
`${systemd}/lib/systemd`, so the UKI builder adds that directory to `PATH`.

## Build-time PCR 11 prediction

When a policy key is configured, the UKI builder also writes two sidecars
next to the UKI:

```text
aos-<name>-<version>.efi.measurement
  aos.uki-measurement/v1
  uki_sha256=<hex>
  expected_pcr11=sha256:<hex>
aos-<name>-<version>.efi.measurement.sig   (signed with the PCR-policy key)
```

`expected_pcr11` comes from `objcopy` dumps of each measured section
(`.linux .osrel .cmdline .initrd .ucode .splash .dtb .uname .sbat .pcrpkey`)
fed to `systemd-measure calculate --bank=sha256`. That tool prints one PCR 11
value per boot phase; the recorded value is the last one, the `ready` phase.
Feeding the whole UKI to `systemd-measure --linux` instead would measure it
as a kernel image and produce the wrong value.

The sidecar binds the prediction to the exact UKI bytes so it cannot be
replayed across slots or revisions. The boot runtime
(`crates/boot/aos-boot-runtime/src/measurement_index.rs`) verifies it against
the image's PCR-policy public key, and boot commit compares it with the PCR 11
value quoted after the `ready` phase. Live TPM readings never become
expectations. `/var` unlock does not consume this scalar; it uses the signed
multi-phase policy at `enter-initrd`.

## Platform pieces

| Layer | Implementation |
| --- | --- |
| Firmware | OVMF `TPM2_ENABLE` measures PCR 7 and provides TCG2 to sd-stub |
| Kernel | `pkgs/kernel/config/tpm.config`: `CONFIG_TCG_TPM`, `TCG_TIS`, `TCG_TIS_SPI`, `TCG_CRB`, `HW_RANDOM_TPM`, built in so the TPM exists before switch-root |
| TSS | `pkgs/security/tpm2-tss.nix`, built `--disable-fapi` |
| systemd | Built with `-Dtpm=true` and `-Dtpm2=enabled` |
| Emulator (tests) | `pkgs/security/libtpms.nix`, `pkgs/security/swtpm.nix` |
| Token plugin path | cryptsetup built with `--with-luks2-external-tokens-path=/run/cryptsetup/tokens` |

The last row is the subtle one. libcryptsetup loads external token plugins by
absolute path from its compiled-in directory, but systemd's
`libcryptsetup-token-systemd-tpm2.so` lives in systemd's store path.
`LD_LIBRARY_PATH` does not affect that lookup, so `aos-var-crypt` symlinks
`${systemd}/lib/cryptsetup` to `/run/cryptsetup/tokens` before unlocking.

## Sealing and unlocking `/var`

`aos-var-crypt` (`pkgs/system/_aos-systemd-var-policy/`) is an initrd
oneshot. It runs after the boot-identity guard, the initrd ability stage, and
udev settle (and after full verity root verification on dm-verity images),
before `mount-var.service` and `initrd-fs.target`. It is skipped when the
command line carries `aos.recovery=1`.

For each TPM2-encrypted volume in the validated storage plan (or, with no
plan, `var` by its fixed identities plus any LUKS2 volume tagged with the
`aos-volume` subsystem):

1. Wait up to about 30 seconds for the device; udev surfaces a `crypto_LUKS`
   partition late, so the unit has no `ConditionPathExists`.
2. If the device is already LUKS, attach it with `systemd-cryptsetup`
   using `tpm2-device=auto`, the sd-stub signature at
   `/run/systemd/tpm2-pcr-signature.json`, and `headless`. A failed unseal
   leaves the volume locked rather than prompting for a passphrase.
3. If Secure Boot is not yet enforcing (`SecureBoot` efivar is not 1), seal
   nothing. `/var` gets a plain ext4 filesystem so the machine can reach
   multi-user and enroll keys; other volumes stay raw.
4. On the first enforcing boot, format LUKS2 with a throwaway key, create the
   filesystem, enroll the TPM2 token (`--tpm2-public-key-pcrs=<signed>`,
   `--tpm2-pcrs=<pinned>`), enroll a recovery key, then wipe the throwaway
   password slot by type.

Sealing waits for enforcement because PCR 7 differs between Setup Mode and
User Mode. A volume sealed during Setup Mode would stop unlocking as soon as
keys were enrolled.
The plaintext Setup Mode `/var` is disposable by contract; any other volume
must be blank before it is sealed.

The recovery key is written to `recoveryKeyPath` (default
`/run/aos-var-recovery.key`) on tmpfs, never to the volume it unlocks.
Recovery enrollment is not masked: if it fails, the script aborts before
wiping the bootstrap slot so the volume is never left with only a TPM path.
Command substitution strips `systemd-cryptenroll`'s trailing newline because
cryptsetup treats every key-file byte as key material. Off-host escrow is a
deployment responsibility.

Some storage backends (`aos.boot.storage.backend = "zfs-zvol"`) use their own
sealing path; `aos.security.measuredVar.enable` defaults off for them.

## Migrating to the PCR 12 policy

`aos-var-policy-migrate DEVICE RECOVERY_KEY PCR_PUBLIC_KEY PCR_SIGNATURE
EVIDENCE` (`pkgs/system/aos-systemd-var-policy.nix`) moves a volume enrolled
with an older pinned set to the current one without ever leaving it with no
working unlock path:

1. Open the exact keyslot named by the volume's single `systemd-recovery`
   token with the supplied recovery key.
2. Add a new TPM2 token with the current pinned PCRs and the supplied PCR 11
   public key, leaving the old token in place.
3. Validate the new token's ID, keyslot, PCR selections, public key, and
   bank, and test it using the canonical runtime signature path.
4. Record evidence through `prepared`, `verified`, and `complete` states,
   syncing the file and directory at each step. The `verified` record names
   the retained and to-be-removed keyslots before cleanup starts; a resume may
   remove only a subset of that set.
5. Remove the older TPM keyslots.

Operator usage is in [Recover an AOS host](../../users/aos/recovery.md).

## Tests

`checks.fleet.measured-boot` boots `systems/server-verity.nix` with a vTPM
and the pinned set forced to the legacy `7`. It covers Setup Mode first boot,
enrollment, sealing on the first enforcing boot, in-place migration to
`7+12`, unattended unlock across reboots, verity root and PCR 11 agreement
with the UKI's measured sections, A/B slot and boot-counting PCR 12
stability, external command-line injection (addons, SMBIOS, Type #1 options)
denying unlock while the recovery key still opens the volume, and the
recovery UKIs described in [Recovery](recovery.md).
`tests/effects/measured-var.nix` checks the rendered `aos-var-crypt` service
contract.

# Secure Boot

AOS boots systemd-boot and a unified kernel image (UKI) from the EFI System
Partition. With Secure Boot enabled, the firmware verifies both PE binaries
against its enrolled `db` before executing them, and an optional lockdown
kernel prevents the running kernel from loading unsigned kernel code. This
page covers how each piece is built and why it is shaped that way.

## Reproducible base, signing as an overlay

The public package set owns no signing key. Anything reachable from a
derivation is distributable, and bit-for-bit reproducibility would otherwise
require every builder to share one private key. The same reasoning keeps
lockdown and module signing out of the base kernel config
(`pkgs/kernel/config/security.config`).

Every Secure Boot key is therefore a deployment input:

- With `aos.boot.secureBoot.enable = false` (the default), the UKI and
  systemd-boot are unsigned, byte-reproducible artifacts.
- With local signing (`dbKey` and `dbCert` set), the image build signs them
  inside the Nix build. The key enters the builder's store, so this mode is
  for disposable test or staging identities on controlled builders.
- With `externalFinalization.enable = true`, Nix emits an unsigned assembly
  and the release finalizer (`crates/release/aos-image-finalizer`) obtains
  every private-key operation from external signers bound to the roles
  `secureBootRole`, `moduleRole`, and `pcrRole`. Evaluation asserts that no
  `dbKey`, `lockdown.moduleSigningKey`, or `measuredBoot.pcrPrivateKey` is
  set in this mode, and that lockdown, measured boot, recovery, and dm-verity
  are all enabled.

Public material (the db certificate, module-signing certificate, PCR public
key, and enrollment `.auth` blobs) is copied into dedicated public-only
artifacts, so an image never references a store path that also contains a
private key unless the deployment chose local signing.

## Firmware

`pkgs/boot/edk2.nix` builds OVMF (`OvmfPkg/OvmfPkgX64.dsc`) for x86_64 and
`ArmVirtPkg/ArmVirtQemu.dsc` for AArch64. The x86_64 build passes:

| Flag | Why |
| --- | --- |
| `SECURE_BOOT_ENABLE=TRUE` | Compiles in authenticated variables and Secure Boot enforcement |
| `SMM_REQUIRE=TRUE` | OVMF exposes a working authenticated-variable store only from SMM; without it `SecureBoot`/`SetupMode` never appear and `bootctl` reports Secure Boot unsupported |
| `TPM2_ENABLE=TRUE`, `TPM2_CONFIG_ENABLE=TRUE` | Measures firmware state (PCR 7) into an attached TPM and exposes the TCG2 protocol sd-stub uses for PCR 11 |

A Secure Boot capable OVMF with no enrolled PK stays in Setup Mode and boots
anything, so the same firmware serves unsigned image tests.

SMM firmware needs a matching QEMU machine: `-machine q35,smm=on`,
`-global driver=cfi.pflash01,property=secure,value=on`,
`-global ICH9-LPC.disable_s3=1`, `OVMF_CODE` as read-only pflash unit 0, and
a writable per-machine `OVMF_VARS` copy as unit 1. The fleet driver applies
these for every image-boot machine; see [Image-boot
testing](image-boot-testing.md).

The kernel builds `CONFIG_EFIVAR_FS=y` (`pkgs/kernel/config/base.config`). As
a module it loads too late for systemd's early efivarfs mount, which hides
the Secure Boot variables and leaves enrollment nowhere to write. Because
efivarfs is then present on every boot, the systemd initrd's command-line
parts mask `systemd-boot-random-seed.service`, which would otherwise try to
write a seed to the read-only ESP.

## Signed artifacts

Only two PE binaries need signatures:

1. systemd-boot, installed as `EFI/BOOT/BOOTX64.EFI` (or the architecture's
   fallback name) and `EFI/systemd/systemd-bootx64.efi`. The ESP builder in
   `_boot-artifacts.nix` runs `sbsign` once and copies the result to both
   paths.
2. Each UKI. `_uki-builder.nix` passes `--signtool=sbsign
   --secureboot-private-key --secureboot-certificate` to `ukify build`, then
   runs `sbverify --cert` on the result so a signing success that produced
   the wrong identity fails the build.

The verity root hash and verity UUID are build outputs that cannot travel
through `aos.boot.kernelParams`. The UKI builder appends `roothash=` and
`aos.verity-uuid=` to the materialized command line before `ukify` runs, so
the same `.cmdline` section is both signed and measured into PCR 11. This
binds each UKI to exactly one root image.

Recovery UKIs use the same db identity but no PCR policy; see
[Recovery](recovery.md).

## Key enrollment

`aos-sb-enroll` (installed with `environment.systemPackages` when Secure
Boot is enabled) writes the deployment's authenticated variables through
efivarfs with `efi-updatevar`:

```text
db.auth  -> db
KEK.auth -> KEK
PK.auth  -> PK     (leaves Setup Mode; firmware now enforces)
```

The order matters: writing PK exits Setup Mode, after which unauthenticated
writes to db and KEK are refused. `efi-updatevar` locates efivarfs with
`mount -l`, so the script puts util-linux on `PATH`. The `.auth` blobs come
from `aos.boot.secureBoot.enrollAuthDir` and are public material.

Enrollment through efivarfs is the same path real hardware uses after it is
put into Setup Mode. AOS does not inject keys into firmware variable stores
offline, and it has no in-tree mechanism that applies `dbx` or SBAT updates
to firmware variables on a running machine.

## Lockdown kernel

`aos.boot.secureBoot.lockdown.enable` replaces the kernel with a deployment
variant built by `pkgs.linuxWith`, which appends kconfig to the base kernel:

```text
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_FORCE=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_MODULE_SIG_ALL=y          (n under external finalization)
CONFIG_MODULE_SIG_KEY=<key>      (or CONFIG_SYSTEM_TRUSTED_KEYS=<cert> externally)
CONFIG_KEXEC_FILE=y
CONFIG_KEXEC_SIG=y
CONFIG_KEXEC_SIG_FORCE=y
CONFIG_KEXEC_BZIMAGE_VERIFY_SIG=y
```

It also adds `lockdown=<mode>` (`confidentiality` by default) and
`module.sig_enforce=1` to the command line. Signed kexec keeps the kernel
hot-reload path usable under lockdown.

Two build details are easy to get wrong:

- `extraConfig` is an argument of `pkgs/kernel/linux.nix` consumed before
  `mkDerivation`, so `pkgs.linux.override { extraConfig = ...; }` silently
  builds the base kernel. `pkgs.linuxWith` calls the package function
  directly.
- `olddefconfig` drops options whose dependencies are unmet. The signed
  kexec options require `CONFIG_KEXEC_FILE`, which the base config does not
  set, so the fragment requests it explicitly. Verify the installed
  `config-*` rather than the fragment when changing these options.

The module-signing key is distinct from the db key. In local mode
`lockdown.moduleSigningKey` is a combined private-key and certificate PEM;
under external finalization the kernel embeds `lockdown.moduleSigningCert`
and the finalizer signs every shipped module.

## Key roles

| Key | Signs | Must never sign |
| --- | --- | --- |
| PK | KEK updates | Boot binaries, registry data |
| KEK | db and dbx updates | Boot binaries, registry data |
| db | systemd-boot, normal and recovery UKIs, the recovery bundle manifest | Registry history, NARs |
| PCR policy | The UKI `.pcrsig` policy and `.measurement` sidecar | Firmware-executed code |
| Kernel module | Loadable modules for one lockdown kernel | UKIs, registry data |

The registry signing keys sign metadata about artifacts. Keeping them unable
to mint a boot-valid UKI means a compromise of the online registry key does
not reduce the hardware-rooted boot guarantee to the registry's threat model.
[Maintain the AOS trust model](../../maintainers/trust-model.md) defines the
complete role table and incident response.

## Fixtures and tests

All checked-in Secure Boot systems use `pkgs.secure-boot-test-keys`, a
self-owned PK -> KEK -> db hierarchy plus `modsign.pem` and `pcr.key`/`pcr.pem`.
These keys are public and protect nothing.

| Fixture | Adds |
| --- | --- |
| `systems/server-secureboot.nix` | Local db signing and enrollment tooling |
| `systems/server-secureboot-lockdown.nix` | Lockdown kernel in `confidentiality` mode |
| `systems/server-measured-boot.nix` | Signed PCR policy and TPM-sealed `/var` |
| `systems/server-verity.nix` | dm-verity root on top of measured boot |

| Check | Proves |
| --- | --- |
| `checks.fleet.secure-boot` | Setup Mode boot, enrollment, enforcing reboot, and firmware refusal of a tampered UKI |
| `checks.fleet.secure-boot-lockdown` | Active lockdown and blocked `/dev/mem`; unsigned-module rejection is checked best effort |
| `checks.fleet.measured-boot` | See [Measured boot](measured-boot.md) |

The tamper test is the load-bearing one: without it, a regression that
enables Secure Boot but accepts every image would pass.

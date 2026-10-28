# Boot chain

This section describes how AOS implements verified boot: UEFI Secure Boot,
kernel lockdown, measured boot with TPM-sealed persistent state, the signed
recovery environment, and the image-boot test harness that exercises them.
Operator procedures live in [Use Secure Boot and verify package
trust](../../users/aos/secure-boot.md) and [Recover an AOS
host](../../users/aos/recovery.md); maintainer key and release policy lives in
[Maintain the AOS trust model](../../maintainers/trust-model.md).

| Page | Covers |
| --- | --- |
| [Secure Boot](secure-boot.md) | Firmware build, artifact signing, key enrollment, lockdown kernel, key custody |
| [Measured boot](measured-boot.md) | TPM stack, signed PCR policy, `/var` sealing and unlock, PCR 12 migration |
| [Recovery](recovery.md) | Locked initrd, boot-identity guard, paired recovery UKIs, offline restore |
| [Image-boot testing](image-boot-testing.md) | How fleet tests boot real images under OVMF with a vTPM |

## Shape of the chain

```text
  release signer (offline)      image (Nix build)           machine (per boot)
  ------------------------      -----------------           ------------------
  db key   -> UKI, sd-boot      unsigned assembly or        firmware db verifies
  PCR key  -> .pcrsig policy    locally signed fixture      sd-boot and UKI
  module key -> kernel modules  UKI carries cmdline,        sd-stub measures UKI
                                roothash, .pcrsig           sections into PCR 11
                                                            initrd guards identity,
                                                            verifies root, unseals
                                                            /var via signed policy
```

Three separate keys sign boot material: the UEFI db key (Authenticode over
systemd-boot and every UKI), the PCR-policy key (the UKI's `.pcrsig`
section), and the kernel module-signing key (lockdown kernels only). The
registry keys never sign anything the firmware or TPM policy trusts.

The UKI is the unit of authentication. Kernel, initrd, embedded command line,
os-release, and the dm-verity root hash are PE sections inside it, so one
Authenticode signature covers all of them. sd-stub does not re-verify inner
sections; coverage comes from the firmware's `LoadImage`/`StartImage` check
over the whole PE.

## Source map

| Path | Role |
| --- | --- |
| `pkgs/boot/edk2.nix` | OVMF / ArmVirtQemu firmware with Secure Boot, SMM (x86_64), and TPM2 |
| `pkgs/boot/efitools.nix`, `pkgs/boot/sbsigntools.nix` | Enrollment and Authenticode tools |
| `pkgs/boot/secure-boot-test-keys.nix` | Throwaway CI key hierarchy |
| `modules/base/secure-boot.nix` | `aos.boot.secureBoot` options, enrollment command, lockdown kernel |
| `pkgs/boot/_aos-boot-storage/measurement-options.nix` | `aos.boot.secureBoot.measuredBoot` policy options |
| `pkgs/boot/_aos-boot-storage/policy-options.nix` | `aos.boot.secureBoot.enable`, `aos.boot.recovery` |
| `pkgs/system/_systemd-abilities/platform/_uki-builder.nix` | `ukify` wrapper: signing, PCR policy, PCR 11 prediction |
| `pkgs/system/_systemd-abilities/platform/_boot-artifacts.nix` | ESP tree, slot UKIs, recovery UKIs and entries, ESP budget |
| `pkgs/system/_systemd-abilities/platform/_recovery-initrd-builder.nix` | Dedicated recovery initrd |
| `pkgs/system/_aos-systemd-var-policy/` | `aos-var-crypt` sealing and unlock service |
| `pkgs/system/aos-systemd-var-policy.nix` | `aos-var-policy-migrate` |
| `pkgs/security/_aos-boot-identity/`, `crates/boot/aos-boot-identity/` | Boot-identity parser and guard |
| `pkgs/security/_aos-verity-root-guard/` | Full read of the verity root before `/var` |
| `crates/boot/aos-recovery/` | Recovery console, slot verifier, restore writer |
| `crates/release/aos-image-finalizer/` | External signing and final image assembly |
| `systems/server-secureboot*.nix`, `systems/server-measured-boot.nix`, `systems/server-verity.nix` | Test fixtures |

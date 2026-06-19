# RFC-0006 — Current state

What exists and what is absent, file:line grounded as of this branch
(master + [RFC-0003](../0003-install-from-image.md) / #100). This is the
baseline the rest of the RFC builds on; later topic files reference it
rather than re-deriving it.

## Boot chain

**OVMF / EDK2** — `pkgs/boot/edk2.nix`

- Build invocation (`:141-146`): `build.py -a X64 -t GCC -b RELEASE
  -p OvmfPkg/OvmfPkgX64.dsc -n $NIX_BUILD_CORES`. **No `-D` flags** — no
  `SECURE_BOOT_ENABLE`, no `SMM_REQUIRE`. The SB drivers
  (SecureBootConfigDxe, authenticated variables) are therefore **not
  compiled in**; this firmware cannot enforce SB even with keys enrolled.
- Outputs (`:153-155`): `$out/FV/{OVMF.fd,OVMF_CODE.fd,OVMF_VARS.fd}`.
  `OVMF_VARS.fd` is a blank template — no PK/KEK/db.
- Source pin (`:40,44`): `edk2-stable202602`, rev `b7a715f7…`,
  `builtins.fetchGit submodules=true`.

**UKI** — `pkgs/boot/aos-uki.nix`

- `ukify build` (`:71-77`): `--stub --linux --initrd --cmdline --os-release
  --output`. **No `--secureboot-private-key`, `--secureboot-certificate`,
  `--pcr-private-key`, or `--signtool`.** Output is an unsigned PE.
- Docstring (`:3-4`) claims "produce a signed PE-COFF binary" — **inaccurate
  today**; should be corrected as part of phase 1.
- Stub (`:38`): `${systemd}/lib/systemd/boot/efi/linuxx64.efi.stub`, unsigned.

**sd-boot / ESP** — `modules/image/_builder.nix`

- ESP tree (`:6-9`): `EFI/BOOT/BOOTX64.EFI`,
  `EFI/systemd/systemd-bootx64.efi`, `EFI/Linux/aos-<ver>.efi`,
  `loader/loader.conf`. ESP is 512 MiB (`:44`).
- Copies (`:117-121`): `systemd-bootx64.efi` → both BOOTX64.EFI and the
  canonical path, then the UKI → `EFI/Linux/`. **No signing step** before any
  copy. sd-boot comes from `${pkgs.systemd}/lib/systemd/boot/efi` (`:91`).
- A/B: only `root-a` is pre-allocated; `root-b`/swap/`var` are created by
  ignition on first boot (`:13-14`). 512 MiB ESP has room for two UKIs.

**systemd** — `pkgs/system/systemd.nix`

- EFI/UKI enabled (`:228-230`): `-Defi=true -Dbootloader=enabled
  -Dukify=enabled`.
- SBAT distro metadata **is** set (`:231-236`): `-Dsbat-distro=aos`,
  `-Dsbat-distro-generation=1`, summary "ANDYL OS", pkgname systemd,
  version, url. So sd-boot and the stub carry `.sbat` sections already — the
  substrate SBAT-based revocation needs.
- **No** `-Dsecureboot`/`-Dgnuefi` meson options; no signing keys passed to
  the systemd build.

**Signing tools** — present but unused

- `pkgs/boot/sbsigntools.nix` builds sbsigntools 0.9.5 (sbsign/sbverify/
  sbattach/sbsiglist), links gnu-efi, openssl, util-linux. **Never invoked
  anywhere.**
- `pkgs/boot/gnu-efi.nix` (4.0.4) — headers/libs/CRT only.
- Tree-wide grep: **no** use of sbsign, sbverify, cert-to-efi-sig-list,
  sign-efi-sig-list, virt-fw-vars, EnrollDefaultKeys, KEK, PK.auth, db.auth,
  MokList, shim.

**Test harness** — `tests/fleet/install-from-image.nix`,
`lib/testing/fleet.nix`, `pkgs/tools/aos/aos-test-driver/.../qemu.py`

- Image-boot machine maps OVMF via pflash: `firmware_code =
  ${pkgs.edk2}/FV/OVMF_CODE.fd`, `firmware_vars = …/OVMF_VARS.fd`
  (`fleet.nix`, image-boot branch), per-run writable vars copy
  (`qemu.py`: `shutil.copyfile(self.firmware_vars_src, self.vars_copy)`).
- Ignition delivered via `-fw_cfg name=opt/com.coreos/config` (qemu
  platform). **No SB enforcement, no enrolled keys, no vTPM device** in the
  QEMU argv.

## Measured boot / TPM

- **No TPM packages.** No tpm2-tss, tpm2-tools, libtss, or swtpm under
  `pkgs/` (`pkgs/security/` has cryptsetup, openssl, selinux tooling, etc.,
  but nothing TPM).
- **systemd TPM off** — `pkgs/system/systemd.nix:237` `-Dtpm=false`, `:293`
  `-Dtpm2=disabled`. libcryptsetup **is** on (`:280-281`
  `-Dlibcryptsetup=enabled`, `-Dlibcryptsetup-plugins=enabled`).
  `systemd-cryptsetup`/`systemd-cryptenroll` are wrapped for LD_LIBRARY_PATH
  (`:382-393`) but built without TPM2 support.
- **initrd strips the measured-boot tools** —
  `modules/base/_initrd-builder.nix:632` removes `systemd-measure
  systemd-creds systemd-cryptenroll` from the initrd closure.
  `systemd-pcrphase`/`systemd-pcrlock` are not present at all.
- **No kernel TPM drivers** — no `CONFIG_TCG`, `CONFIG_TCG_TPM`,
  `CONFIG_TCG_TIS`, `CONFIG_TCG_CRB`, `CONFIG_HW_RANDOM_TPM` in any
  `pkgs/kernel/config/*`.
- **No vTPM in CI** — `qemu.py` argv has no `-tpmdev`/`-device tpm-tis`;
  `pkgs/emulation/qemu.nix` neither enables nor packages swtpm/libtpms.
- **IMA/EVM measure-only** — `pkgs/kernel/config/security.config:40-43`:
  `CONFIG_IMA=y`, `CONFIG_IMA_MEASURE_PCR_IDX=10`, `CONFIG_EVM=y`. Measures
  to PCR 10 but **there is no TPM to extend or seal to**, and no
  `IMA_APPRAISE` (measure, not enforce).

## Disk encryption

- `modules/base/filesystems.nix:272-327` `cryptswap`: **plain dm-crypt**
  (not LUKS), `aes-xts-plain64`, key from `/dev/urandom` (`:310`) — discarded
  on reboot. Swap only.
- `/var` (generations, apm state, user data, the /nix overlay upper) is
  **not encrypted**.
- `pkgs/security/cryptsetup.nix` present (OpenSSL backend, Argon2). Kernel
  `CONFIG_DM_CRYPT=m` (`pkgs/kernel/config/storage.config:26`) — module.

## Kernel — Secure Boot relevant

- **Lockdown + module signing deliberately OFF**
  (`pkgs/kernel/config/security.config:27-36`), with a rationale comment that
  is load-bearing for this RFC:
  > Lockdown LSM and module signing are not part of the public reproducible
  > base. … MODULE_SIG defaults to generating a private signing key during the
  > build — which is incompatible with third-party bit-reproducibility. Module
  > signing belongs to deployments that own a non-public key, not the base
  > image.

  So `CONFIG_SECURITY_LOCKDOWN_LSM`, `…_EARLY`, `CONFIG_MODULE_SIG`,
  `MODULE_SIG_ALL`, `MODULE_SIG_FORCE` are all unset **on purpose**.
- **Absent**: `CONFIG_KEXEC_SIG`, `CONFIG_KEXEC_BZIMAGE_VERIFY_SIG`,
  `CONFIG_SYSTEM_TRUSTED_KEYS`, `CONFIG_SYSTEM_BLACKLIST_KEYS`,
  `CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT`. `CONFIG_EFI_PARTITION=y` is the only
  EFI-relevant setting (`storage.config:63`).
- Cmdline (assembled from `aos.boot.kernelParams`, `modules/image/_builder.nix:37`,
  base in `modules/base/boot.nix:107-129`): `console=… systemd.gpt-auto=0
  root=/dev/disk/by-partlabel/root-a ro` + `audit=1` + x86 hardening +
  `selinux=1 security=selinux`. **No** `lockdown=`, `module.sig_enforce`,
  `ima_appraise=`.

## Provisioning / trust delivery

- `modules/services/ignition.nix`: platform detect → fetch → disks → mount →
  files. **No EFI-variable / SB-key enrollment path anywhere.** GPT-relocate
  (`:173-216`), growfs (`:218-238`), disks (`:264-285`).
- Registry trust anchor delivered baked into the image:
  `modules/base/apm-registries.nix` writes
  `/etc/apm/registries.d/<name>.toml` (`[registry.signing] public_key =
  "name:Ed25519:base64"`, `:34-40`) and `/etc/apm/trusted-keys.d/<name>.pub`
  (`:44`). This is the *parallel* mechanism a SB db-cert delivery would mirror.

## Registry / metadata

- `crates/aos-package/src/types.rs`: `PackageMeta` (`:447`) — name, version,
  description, homepage, license, maintainer, platform, store_path,
  `nar_hash`, nar_size, references, source_drv, source_nar_hash,
  closure_size, `sysroot: bool`, previous, `images: Vec<SysrootImageEntry>`.
  `SysrootImageEntry` (`:1267`) — format, store_path, `nar_hash`, nar_size.
  **No SB fields** (no signer cert, SBAT generation, or expected PCR).
- Registry trust roots in **signed git tag objects** (SSH Ed25519), not
  signed commits — `docs/registry/signing-and-trust.md` §1-2. Per-package
  metadata is TOML in the git tree; the signed tag covers the tree state.
- narinfo: `apm` verifies `file_hash` (compressed) and `nar_hash`
  (decompressed) + store-path integrity on import
  (`crates/aos-package/src/{download,verify,sysroot}.rs`); it does **not**
  verify narinfo `signatures:` — provenance comes from the signed tag, not
  per-NAR sigs.
- `apr publish --sysroot` records `sysroot = true` + `[[images]]` entries
  (`crates/aos-package/src/registry_ops.rs`).

## Existing docs to align with (not duplicate)

- `docs/registry/signing-and-trust.md` — the registry PKI (signed tags,
  baked anchor, in-band roster). The catalog work in
  [`registry-catalog.md`](registry-catalog.md) extends this, it does not
  restate it.
- `docs/boot/qemu-uefi.md` — operator UEFI boot flow; will gain a SB section.
- `modules/security/verity.nix` — dm-verity exists, default off; relevant to
  the "what protects the rootfs" question but distinct from SB (block
  integrity vs boot-binary authenticity).
- No existing Secure Boot / measured-boot / attestation design doc.

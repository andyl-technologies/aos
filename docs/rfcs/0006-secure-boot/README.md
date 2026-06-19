# RFC-0006: Full Secure Boot integration — sign, measure, attest

- **Status:** Phases 1–4 implemented and CI-green (PR [#102](https://github.com/andyl-technologies/aos/pull/102)). Phase 3's TPM-sealed `/var` is verified end to end by `checks.fleet.measured-boot`, including unattended TPM2 unlock across a reboot. Phase 4's download-time catalog gate is verified end to end by `checks.fleet.registry-sb-catalog` (publish a signed UKI → refuse on unknown signer / SBAT floor → accept), which also cross-checks the recorded `expected_pcr11` against an independent `systemd-measure` recompute
- **Date:** 2026-06-13
- **PR:** [#102](https://github.com/andyl-technologies/aos/pull/102)
- **Audience:** anyone working on `pkgs/boot/`, `pkgs/system/systemd.nix`,
  `pkgs/kernel/`, `modules/security/`, `modules/services/ignition.nix`,
  `crates/aos-package/`, `lib/testing/`, or release/key operations.

This is a directory RFC. The README carries the status header, the trust
model, and the phased plan; the topic files hold the detail:

- [`current-state.md`](current-state.md) — exactly what exists and what's
  absent today, file:line grounded.
- [`key-custody.md`](key-custody.md) — the central decision: who holds
  which key, and why the reproducible base can't hold any of them.
- [`boot-chain.md`](boot-chain.md) — enforce SB at the firmware: SB-enabled
  OVMF, signed UKI + sd-boot, enrollment, kernel lockdown + module signing.
- [`measured-boot.md`](measured-boot.md) — the companion that makes SB pay
  off: TPM bring-up, signed PCR policy, TPM-sealed disk encryption, vTPM in CI.
- [`registry-catalog.md`](registry-catalog.md) — the registry as the central
  catalog that records and validates SB signing facts (never a signer of them).
- [`test-plan.md`](test-plan.md) — CI: positive + negative SB enforcement and
  measured-boot tests, extending `checks.fleet.install-from-image`.

## Problem

AOS ships a UEFI image that boots sd-boot → UKI → kernel
([RFC-0003](../0003-install-from-image.md), `checks.fleet.install-from-image`).
**Nothing in that chain is signed or measured, and the firmware does not
enforce Secure Boot.** Concretely (see [`current-state.md`](current-state.md)):

- `pkgs/boot/edk2.nix` builds `OvmfPkgX64.dsc` with no `-D SECURE_BOOT_ENABLE`
  — the firmware has no authenticated-variable / SB drivers compiled in.
- `pkgs/boot/aos-uki.nix` calls `ukify build` with no
  `--secureboot-private-key`/`--secureboot-certificate` — the UKI is
  assembled, not signed (the docstring's "signed PE-COFF" is wrong).
- `modules/image/_builder.nix` copies `systemd-bootx64.efi` to the ESP
  unsigned.
- `pkgs/system/systemd.nix` builds with `-Dtpm=false` / `-Dtpm2=disabled`;
  `modules/base/_initrd-builder.nix:632` strips `systemd-measure`,
  `systemd-creds`, `systemd-cryptenroll` from the initrd; no kernel TCG/TPM
  drivers exist; the QEMU harness attaches no vTPM. There is **no measured
  boot**.
- Encrypted swap (`modules/base/filesystems.nix`) is plain dm-crypt keyed
  from `/dev/urandom` — nothing is sealed to boot state; `/var` (which holds
  every generation, the apm state, and user data) is **not encrypted at all**.

So the artifact we ship can be silently modified offline — swap the UKI on
the ESP, alter the kernel, plant an initrd — and the machine boots it. There
is no hardware root of trust, no tamper evidence, and no basis for remote
attestation.

This RFC closes that gap end to end, and connects it to the registry so a
fleet has a single place to validate signed components against.

## The trust architecture

Three roles, three keys, deliberately separated — the whole design is
keeping them apart so that compromising one does not collapse the others:

```text
  OFFLINE SIGNER            ONLINE CATALOG              HARDWARE ENFORCER
  (release, HSM/airgap)     (registry, per-publish)     (firmware + TPM, per-boot)
  ───────────────────       ─────────────────────       ─────────────────────
  db key   → signs UKI      Ed25519 git-tag key →       enrolled db cert →
  + sd-boot (Authenticode)    records "this UKI is        firmware verifies the
  PCR-policy key → signs      signed by cert X, SBAT      embedded Authenticode
  the .pcrsig section         gen N, expected PCR-11=Y"   sig before StartImage
                              over the metadata           TPM → seals secrets
                              (signed-tag trust chain)    to measured PCRs
        │                            │                            │
        └──── signs the artifact ────┴──── records facts about ───┘
                                            the artifact, never
                                            re-signs it for boot
```

- The **offline db key** is the only thing that can make a UKI bootable. It
  signs at release, lives airgapped/HSM, and is **not in the build closure**
  (the reproducible base deliberately owns no signing key —
  `pkgs/kernel/config/security.config:27-31`).
- The **registry key** (the existing signed-git-tag Ed25519 key,
  `docs/registry/signing-and-trust.md`) signs *metadata about* artifacts. The
  RFC extends that metadata to carry SB facts so the registry is the central
  validation catalog — but it **never signs anything the firmware trusts**.
  A compromised registry can lie about an artifact; the firmware still rejects
  an artifact whose embedded sig doesn't verify against its enrolled db.
- The **firmware (+ TPM)** is the hard root. It enforces at boot, independent
  of the network. The registry catalog is a second, independent cross-check
  that moves most failures from boot time (a brick) to download time (a clean
  refusal).

This is the [TUF](https://theupdateframework.io/) / sigstore separation —
the role that *signs the binary* is not the role that *records and distributes
the validation facts*, and neither is the role that *enforces at runtime*.

## Goals

1. The firmware refuses to boot an unsigned or tampered UKI/sd-boot (SB
   enforcing, own keys) — **load-time** boot authenticity. (Runtime integrity
   — stopping a signed kernel from being turned into an unsigned-code loader —
   is the phase-2 lockdown overlay, not phase 1 alone.)
2. The boot is measured into a TPM, and disk encryption (`/var`) is sealed to
   a **signed PCR policy** so it survives OTA upgrades to any
   db-key-signed UKI.
3. The registry records, per component, the SB signing facts (signer cert,
   SBAT generation, expected PCR-11) and `apm` validates a download against
   them **before reboot**, with a central SBAT revocation floor.
4. CI proves all of the above on every run: a signed image boots under
   SB-enforcing OVMF with a vTPM, a tampered UKI is rejected, and the
   download-time catalog check refuses a revoked component.

## Non-goals

- **Microsoft-CA signing / third-party hardware.** AOS is an appliance you
  control; we enroll our own keys. Shipping shim for arbitrary OEM firmware
  is a separate effort (noted in [`key-custody.md`](key-custody.md)).
- **Production key-management infrastructure** (HSM procurement, signing
  ceremony, rotation runbook). This RFC fixes the *boundaries and formats* so
  that infra slots in; it does not stand up the HSM.
- **Remote-attestation service.** The RFC produces the *inputs* (recorded
  expected PCRs, a TPM that measures) but the verifier/quote service is
  future work.
- Changing the reproducible base's no-signing-key invariant — SB material is
  a **deployment overlay**, never baked into the public base.

## Current state (summary)

| Layer | Today | Source |
|---|---|---|
| OVMF | no SB drivers compiled | `pkgs/boot/edk2.nix:141-146` |
| UKI | assembled, unsigned | `pkgs/boot/aos-uki.nix:71-77` |
| sd-boot | copied unsigned to ESP | `modules/image/_builder.nix:117-118` |
| SBAT | distro metadata set on sd-boot/stub | `pkgs/system/systemd.nix:231-236` |
| sbsigntools | packaged, never invoked | `pkgs/boot/sbsigntools.nix` |
| TPM (systemd) | `-Dtpm=false`, `-Dtpm2=disabled` | `pkgs/system/systemd.nix:237,293` |
| TPM (kernel) | no `CONFIG_TCG_*` drivers | `pkgs/kernel/config/*` |
| measured-boot tools | stripped from initrd | `modules/base/_initrd-builder.nix:632` |
| lockdown / module sig | deliberately off (reproducibility) | `pkgs/kernel/config/security.config:27-36` |
| IMA/EVM | measure-only, PCR 10, no TPM to seal to | `pkgs/kernel/config/security.config:40-43` |
| dm-verity | module exists, default off | `modules/security/verity.nix` |
| disk encryption | swap only, random key, unsealed | `modules/base/filesystems.nix:272-327` |
| registry trust | signed git tags, baked anchor | `docs/registry/signing-and-trust.md` |
| package metadata | `PackageMeta`/`SysrootImageEntry`, no SB fields | `crates/aos-package/src/types.rs:447,1267` |

The one real asset already in place: the UKI design itself is exactly right
for SB — kernel, initrd, and cmdline are PE sections *inside* the UKI, so
signing the UKI covers all three. No shim, no MOK, no separate kernel
signing.

## Phased rollout

Each phase is independently shippable and CI-gated; later phases assume the
earlier ones.

- **Phase 1 — Sign & enforce (firmware root). ✅ Implemented.** SB-enable OVMF
  (+SMM), build the enrollment tool, generate CI keys, sign the UKI and sd-boot,
  enroll PK/KEK/db, CI positive+negative SB tests. ([`boot-chain.md`](boot-chain.md))
- **Phase 2 — Lockdown overlay. ✅ Implemented.** Kernel lockdown LSM + module
  signing as a *deployment overlay* (never the base), cmdline `lockdown=`, signed
  extra modules. ([`boot-chain.md`](boot-chain.md) §lockdown)
- **Phase 3 — Measure & seal (TPM). ✅ Implemented.** TPM packaging (tpm2-tss,
  libtpms, swtpm + nettle/gnutls/json-glib/libtasn1) + kernel TCG drivers +
  systemd `-Dtpm2`, signed PCR policy in the UKI, TPM-sealed LUKS2 for `/var`
  with a recovery key, vTPM in CI. `checks.fleet.measured-boot` proves the
  whole flow end to end: enroll → enforcing seal → reboot → **unattended TPM2
  unlock** of `/var`. ([`measured-boot.md`](measured-boot.md))
- **Phase 4 — Catalog & revoke (registry). ✅ Implemented.** SB fields on
  `SysrootImageEntry`, an `sb-certs.toml` roster (active db-cert set + SBAT
  revocation floor) with `apr sb-certs` authoring, `apr publish` fact
  extraction from the real UKI, `apm` download-time validation before reboot,
  `trusted-sb-certs.d/` delivery. ([`registry-catalog.md`](registry-catalog.md))

Phases 1–3 are deployment/build concerns; phase 4 is the fleet concern that
ties an over-the-wire upgrade to the boot trust chain.

## Implementation notes

What the implementation surfaced that the design didn't predict — recorded so
the next implementer doesn't relearn it.

### Phases 1–2

- **SMM is mandatory, not the optional follow-up the open question floated.**
  OVMF only exposes a real authenticated-variable store (so `bootctl` reports
  SB state and enrollment sticks) when built with **both**
  `-D SECURE_BOOT_ENABLE=TRUE` **and** `-D SMM_REQUIRE=TRUE`
  (`pkgs/boot/edk2.nix`). QEMU must match: `-machine q35,smm=on`,
  `-global driver=cfi.pflash01,property=secure,value=on`,
  `-global ICH9-LPC.disable_s3=1`, with `OVMF_CODE` as read-only pflash unit 0
  and `OVMF_VARS` as unit 1 (`aos_test_driver/qemu.py`). Without SMM the SB
  variables silently don't exist and `bootctl` reports "unsupported".
- **`CONFIG_EFIVAR_FS` must be `=y`, not `=m`.** As a module it is never
  auto-mounted early enough, so `/sys/firmware/efi/efivars` is empty, systemd
  reports SB unsupported, and enrollment has nowhere to write. Built-in fixes
  it (`pkgs/kernel/config/base.config`).
- **Enrollment needs `util-linux` on PATH.** `efitools`' `efi-updatevar` shells
  out to `mount -l` to locate efivarfs; the fleet test agent's PATH lacks it,
  so the enroll script and the test prepend `${pkgs.util-linux}/bin`. Order is
  load-bearing: db → KEK → PK, because writing PK is what exits Setup Mode into
  enforcing User Mode (`modules/base/secure-boot.nix`).
- **`systemd-boot-random-seed.service` breaks on the read-only ESP** once
  efivarfs is present (it tries to write the seed back). Masked via the base
  `systemd.mask=systemd-boot-random-seed.service` kernel param
  (`modules/base/boot.nix`). This surfaced as an install-from-image regression
  the moment efivarfs went built-in.
- **The lockdown kernel needs `pkgs.linuxWith`, not `pkgs.linux.override`.**
  `extraConfig` is a `linux.nix` *function argument* consumed before
  `mkDerivation`, so `.override` is a silent no-op for it — the overlay kernel
  built identically to the base and `lockdown=` was rejected as an unknown
  cmdline param. `pkgs.linuxWith = extraConfig: callPackage …` (`pkgs/default.nix`)
  threads it correctly. The fragment is merged via a heredoc, not
  `builtins.toFile`, because `CONFIG_MODULE_SIG_KEY` references a store path and
  `toFile` rejects derivation references.
- **`olddefconfig` silently drops options whose deps are unmet.**
  `CONFIG_KEXEC_SIG`/`KEXEC_BZIMAGE_VERIFY_SIG` depend on `CONFIG_KEXEC_FILE`,
  which the base config doesn't set; the overlay must request `KEXEC_FILE=y`
  explicitly or signed-kexec quietly vanishes from the built `.config`. Always
  verify the installed `config-*` rather than trusting the fragment.
- **`pkgs/tools/fakeroot.nix`** was repointed to a content-addressed
  `snapshot.debian.org` URL after the Debian pool dropped the original tarball
  (unrelated to SB, but blocked the image build).

### Phase 3 (measured boot)

- **The TPM stack is a real packaging chain, not a tweak.** swtpm pulls
  `libtpms` → `gnutls` → `nettle` + `libtasn1` + `json-glib`, all newly built
  from source (`pkgs/security/`, `pkgs/libs/`). GCC 14 needs `-Wno-error` for
  libtpms/swtpm; swtpm's configure hard-requires test-only tools (expect,
  socat, ss) — shimmed rather than packaged; its `make install` runs a
  `/usr/bin/env bash` helper whose shebang must be patched. tpm2-tss is built
  `--disable-fapi` (drops json-c/curl) and needs a `groupadd` shim.
- **`glib` had a latent bug** that only measured boot exercised:
  `python3` was a build-only dep, so `nuke-references` rewrote the shebang of
  the installed `glib-mkenums`/`glib-genmarshal` to a placeholder, breaking any
  downstream build (json-glib) that runs them. Fixed by moving `python3` to
  glib's `runtimeDeps`.
- **OVMF must be built `-D TPM2_ENABLE=TRUE`** (`pkgs/boot/edk2.nix`) or the
  firmware measures nothing into the vTPM — PCR 7 (SB state) and the TCG2
  protocol sd-stub needs for PCR 11 are both absent. Harmless without a TPM.
- **The PCR-policy key is a third distinct key** (`pcr.key`/`pcr.pem` in the
  test keys), separate from the db key and the module-signing key. ukify signs
  the UKI's PCR policy with it (`--pcr-private-key`/`--pcr-public-key`); ukify
  shells out to `systemd-measure`, which lives in `${systemd}/lib/systemd`
  (not on PATH by default).
- **Sealing must wait for enforcing SB.** With runtime key enrollment (the CI
  path), PCR 7 differs between the Setup-Mode first boot and the enforcing
  boot, so `/var` is sealed on the first *enforcing* boot (ignition formats a
  plain `/var` for the Setup-Mode boot; `aos-var-crypt` LUKS-converts it once
  `SecureBoot=1`). Production that ships pre-enrolled keys seals on first boot.
- **The vTPM must outlive guest reboots in CI.** swtpm dies when QEMU
  disconnects, so the driver (re)launches it per QEMU launch against a
  persistent `--tpmstate` dir (NV/keys persist, PCRs reset — real-hardware
  semantics).
- **The unattended unlock-on-reboot took the most work** and its lessons are
  worth keeping (full detail in [`measured-boot.md`](measured-boot.md)):
  vTPM continuity needs an *in-VM reset* (not QEMU relaunch) + `wait_down`
  reboot detection; ignition must NOT own `/var`'s filesystem (it fails on the
  now-`crypto_LUKS` partition and cascades into a stuck initrd); `aos-var-crypt`
  polls for the late-surfacing LUKS2 device instead of a `ConditionPathExists`;
  and — the crux — the systemd-tpm2 cryptsetup **token plugin** must be on
  cryptsetup's external-tokens path (built `--with-luks2-external-tokens-path=
  /run/cryptsetup/tokens`, symlinked to systemd's plugin dir at unlock) because
  libcryptsetup dlopens it by absolute path, so the `LD_LIBRARY_PATH` wrapper
  alone never found it.

### Phase 4 (registry catalog)

- **Facts are derived from the real signed binary at publish time**, never
  hand-entered: `apr publish` runs `sbverify --list` + an in-Rust PE/PKCS#7
  walk to hash the signer *leaf* cert (selected by matching the SignerInfo
  issuer+serial, not blindly taking cert `[0]`), `objcopy` to dump `.sbat`, and
  `systemd-measure` over the UKI's PE *sections* for the predicted PCR-11. It
  refuses to catalog an image whose embedded signature doesn't verify against
  the declared db cert.
- **`expected_pcr11` is the genuine sd-stub section measurement** — `objcopy`
  dumps each measured section (`.linux`/`.osrel`/`.cmdline`/`.initrd`/`.uname`/
  `.sbat`/…) and `systemd-measure calculate` reproduces what sd-stub extends
  into PCR 11 (the same value `ukify` signs into `.pcrsig`). `systemd-measure`
  emits one value per boot phase; the recorded one is the **`enter-initrd`**
  phase, where `systemd-cryptsetup` unseals `/var`. A verifier comparing a live
  `systemd-analyze pcrs` reading must account for the phase the quote was taken
  at. It is recorded for attestation, not compared in the download-time gate;
  `checks.fleet.registry-sb-catalog` cross-checks it against an independent
  recompute so the value can't silently drift from the binary. (Feeding the
  whole UKI to
  `systemd-measure --linux` — the original implementation — measured the binary
  as a kernel image and was wrong; fixed.)
- **The catalog must reach the validator.** The download-time gate reads
  `sb-certs.toml` from the same dir sync extracts registry-root files to
  (`registries_path()/<name>`) — an early version read a different dir and the
  whole check silently no-op'd. Lesson the adversarial pass drove home: test
  the *production* validator (`validate_image_secure_boot`), not a
  re-implementation, or a delivery-path break passes green.
- **Revocation is operator-authored** via `apr sb-certs add/retire/set-floor`
  (committed on the signed tag like `keys.toml`); `set-floor` only raises, so
  it can't silently re-admit a revoked component.

## Open questions

- **Key custody mechanism for production** — HSM vs offline host vs cloud KMS;
  out of scope to *implement*, but the signing interface
  (`ukify --signtool`/`--secureboot-private-key`, `sbsign`) must not assume a
  key file on disk. See [`key-custody.md`](key-custody.md).
- ~~**Enrollment tooling**~~ — *resolved in phase 1:* `efitools` packaged
  (`pkgs/boot/efitools.nix`); keys/`.auth` blobs generated by
  `pkgs/boot/secure-boot-test-keys.nix`; the guest enrolls db→KEK→PK through
  efivarfs at first boot (`aos-sb-enroll`, `modules/base/secure-boot.nix`) — the
  same path hardware uses, so no offline `virt-firmware` injection was needed.
- **Setup Mode vs pre-enrolled on hardware** — ship in Setup Mode and enroll
  PK on first boot (via an ignition-ordered oneshot), or pre-enroll at image
  build. Tradeoff in [`key-custody.md`](key-custody.md).
- **`/var` encryption rollout** — sealing `/var` to PCRs changes the
  first-boot provisioning order (ignition disks → LUKS format → enroll); needs
  a recovery path (recovery passphrase escrow) for TPM/PCR mismatch. See
  [`measured-boot.md`](measured-boot.md).
- ~~**SMM in OVMF**~~ — *resolved in phase 1:* SMM is **mandatory**, not
  optional. OVMF exposes no working authenticated-variable store without
  `-D SMM_REQUIRE=TRUE` (plus the matching QEMU `smm=on` globals), so SB cannot
  ship without it. See implementation notes above.
- **dbx/SBAT *apply* path** — phase 4 distributes a revocation floor and
  catches revoked components at download time, but applying an actual
  KEK-signed `dbx`/SBAT update to firmware variables on a running fleet
  machine has **no in-tree mechanism** today (ignition has no EFI-variable
  path — [`current-state.md`](current-state.md)). The first-boot PK-enroll
  hook ([`boot-chain.md`](boot-chain.md)) is the closest precedent; the
  ongoing-revocation-apply agent is unowned future work that an implementer
  will hit in phase 4. Decide: a privileged local oneshot, or rely on
  download-time refusal + reimage for revocation?
- **Recovery-key escrow target** — where the TPM-sealed `/var` recovery
  passphrase is stored (provisioning channel vs operator-key-sealed inventory)
  is a deployment decision; "escrowed off the machine, never on `/var`" is the
  hard requirement ([`measured-boot.md`](measured-boot.md)).
- **Predicted vs measured PCR-11** — resolved: `expected_pcr11` is now
  `systemd-measure` over the UKI's PE *sections* (the sd-stub section
  measurement), not the UKI-as-kernel, recorded at the `enter-initrd` boot
  phase (where `/var` unseals); a verifier comparing a live reading must
  account for the quote's phase. `checks.fleet.registry-sb-catalog` cross-checks the recorded value
  against an independent recompute ([`registry-catalog.md`](registry-catalog.md)).

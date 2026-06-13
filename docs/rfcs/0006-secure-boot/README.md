# RFC-0006: Full Secure Boot integration — sign, measure, attest

- **Status:** Proposed
- **Date:** 2026-06-13
- **PR:** _(pending)_
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

- **Phase 1 — Sign & enforce (firmware root).** SB-enable OVMF (+SMM), build
  the enrollment tool, generate CI keys, sign the UKI and sd-boot, enroll
  PK/KEK/db, CI positive+negative SB tests. ([`boot-chain.md`](boot-chain.md))
- **Phase 2 — Lockdown overlay.** Kernel lockdown LSM + module signing as a
  *deployment overlay* (never the base), cmdline `lockdown=`, signed extra
  modules. ([`boot-chain.md`](boot-chain.md) §lockdown)
- **Phase 3 — Measure & seal (TPM).** TPM packaging + kernel drivers +
  systemd `-Dtpm2`, signed PCR policy in the UKI, TPM-sealed LUKS for `/var`,
  vTPM in CI. ([`measured-boot.md`](measured-boot.md))
- **Phase 4 — Catalog & revoke (registry).** SB fields on `PackageMeta`,
  `apr publish` extraction, `apm` download-time validation, SBAT revocation
  floor. ([`registry-catalog.md`](registry-catalog.md))

Phases 1–3 are deployment/build concerns; phase 4 is the fleet concern that
ties an over-the-wire upgrade to the boot trust chain.

## Open questions

- **Key custody mechanism for production** — HSM vs offline host vs cloud KMS;
  out of scope to *implement*, but the signing interface
  (`ukify --signtool`/`--secureboot-private-key`, `sbsign`) must not assume a
  key file on disk. See [`key-custody.md`](key-custody.md).
- **Enrollment tooling** — package `virt-firmware` (`virt-fw-vars`, pure
  Python, injects keys into `OVMF_VARS.fd` offline) vs `efitools`
  (`cert-to-efi-sig-list`/`sign-efi-sig-list`) + OVMF's `EnrollDefaultKeys.efi`.
  Lean: `virt-firmware` for CI (no boot needed), efitools-style `.auth` for
  hardware first-boot enrollment. See [`boot-chain.md`](boot-chain.md).
- **Setup Mode vs pre-enrolled on hardware** — ship in Setup Mode and enroll
  PK on first boot (via an ignition-ordered oneshot), or pre-enroll at image
  build. Tradeoff in [`key-custody.md`](key-custody.md).
- **`/var` encryption rollout** — sealing `/var` to PCRs changes the
  first-boot provisioning order (ignition disks → LUKS format → enroll); needs
  a recovery path (recovery passphrase escrow) for TPM/PCR mismatch. See
  [`measured-boot.md`](measured-boot.md).
- **SMM in OVMF** — `-D SMM_REQUIRE=TRUE` is needed for a tamper-resistant
  variable store but adds build complexity and CI boot cost; ship SB without
  it first, add in a follow-up?
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
- **Predicted vs measured PCR-11** — `expected_pcr11` from `systemd-measure`
  over the UKI alone won't equal the machine's PCR 11 (which includes
  sd-boot/stub phases); pin the prediction method before the catalog records
  it ([`registry-catalog.md`](registry-catalog.md)).

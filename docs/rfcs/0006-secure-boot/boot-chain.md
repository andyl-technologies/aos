# RFC-0006 — Boot chain: sign & enforce

Phase 1 (firmware root) and phase 2 (lockdown overlay). The goal: the
firmware refuses to start anything not signed by our db key, and the running
kernel won't load unsigned code or be probed around lockdown.

## What must be signed

With sd-boot + UKI there are exactly **two** PE binaries the firmware/loader
executes, and signing the UKI transitively covers the kernel + initrd +
cmdline (they're PE sections inside it):

1. `systemd-bootx64.efi` (at both `EFI/BOOT/BOOTX64.EFI` and the canonical
   path) — verified by the firmware's `LoadImage`.
2. the UKI `EFI/Linux/aos-<ver>.efi` — sd-boot loads it via the firmware's
   `LoadImage`/`StartImage`, which verifies it against `db`.

No shim, no MOK, no separate kernel signing — the appeal of the UKI design
([`current-state.md`](current-state.md) closing note). One thing to be precise
about: the sd-stub does **not** itself verify the inner sections — coverage
comes entirely from the firmware's `LoadImage`/`StartImage` Authenticode check
over the *outer* UKI PE. So the chain is "firmware verifies the whole PE,"
not "the stub re-checks each section."

## Phase 1 — sign & enforce

### 1. SB-enable OVMF — `pkgs/boot/edk2.nix`

Add to the `build.py` invocation (`:141-146`):

```text
-D SECURE_BOOT_ENABLE=TRUE
-D SMM_REQUIRE=TRUE        # see open question — may defer
```

`SECURE_BOOT_ENABLE` compiles in the authenticated-variable + SB drivers the
current build lacks. A single SB-enabled OVMF serves **both** worlds: with no
PK enrolled it sits in Setup Mode and boots anything (so the existing
`checks.fleet.install-from-image` keeps **behaving** the same — Setup Mode
boots the unsigned dev image), and once keys are enrolled it enforces. Note
the OVMF *package* changes, so `pkgs.edk2`'s store path and every consumer's
closure rehash — "unchanged" is about test outcome, not build identity.
`SMM_REQUIRE` makes the variable store tamper-resistant (SB is only as strong
as the var store) but adds build/boot complexity **and changes the harness
needs** — QEMU then requires `-machine q35,smm=on` plus matching pflash, so
the existing argv only stays as-is for the SB-without-SMM build. The RFC ships
SB first and treats SMM as a fast follow (README open question).

This rebuild is the only change to the OVMF *package*; everything else is new
signing/enrollment glue.

### 2. Build the enrollment tool

The gap from [`current-state.md`](current-state.md): nothing in-tree can write
PK/KEK/db into an `OVMF_VARS.fd` or produce enrollment `.auth` blobs. Package
one of:

- **`virt-firmware`** (`virt-fw-vars`) — pure Python, injects certs into a
  vars file **without booting**. Best for CI: deterministic, hermetic, no VM
  round-trip. *Recommended.*
- **`efitools`** (`cert-to-efi-sig-list`, `sign-efi-sig-list`) to build the
  `PK.auth`/`KEK.auth`/`db.auth` siglists, paired with OVMF's
  `EnrollDefaultKeys.efi` for first-boot hardware enrollment. (Note:
  `EnrollDefaultKeys.efi` is a separate `OvmfPkg` application — confirm it is
  actually produced by the pinned `edk2-stable202602` `OvmfPkgX64.dsc`; it may
  need an additional build knob beyond `SECURE_BOOT_ENABLE`, or the
  `virt-fw-vars` offline path can replace it for hardware too.)

Lean: package `virt-firmware` for the CI/offline path and generate
efitools-style `.auth` for the hardware first-boot path. Both are small.

### 3. Generate keys

A `pkgs`/lib helper that mints a PK/KEK/db hierarchy (openssl, already
packaged). For CI: ephemeral, per-run, clearly test-named
([`key-custody.md`](key-custody.md)). For production: the helper takes key
*references*, not bytes, and the signing happens via the service abstraction.

### 4. Sign the artifacts

- **UKI** — `pkgs/boot/aos-uki.nix`: add **optional** `secureBootKey` /
  `secureBootCert` args; when present, pass
  `--secureboot-private-key`/`--secureboot-certificate` to `ukify build`
  (`:71-77`). Absent → today's reproducible unsigned UKI. Fix the docstring
  (`:3-4`) to stop claiming "signed" unconditionally.
- **sd-boot** — `modules/image/_builder.nix`: when a key is configured,
  `sbsign` `systemd-bootx64.efi` before the copies at `:117-118` (both ESP
  paths). sbsigntools is already packaged, just never invoked.

Keep signing **optional and overlay-driven** so the base stays reproducible
([`key-custody.md`](key-custody.md)). A new `aos.boot.secureBoot` module
option group carries the key references and flips signing on.

### 5. Enroll & wire the test

- CI: build an `OVMF_VARS.fd` with PK/KEK/db enrolled (via `virt-fw-vars`),
  hand it to the image-boot machine instead of the blank template (the fleet
  harness already supplies `firmware_vars` per machine —
  [`current-state.md`](current-state.md) test-harness section).
- The image-boot machine gains an opt-in `secureBoot = true` that selects the
  enrolled vars + the signed image.

See [`test-plan.md`](test-plan.md) for the positive/negative assertions.

## Phase 2 — lockdown overlay

SB stops the firmware loading unsigned code; **lockdown** stops the running
(signed) kernel from being turned into an unsigned-code loader (`/dev/mem`,
unsigned modules, kexec of an unsigned image, etc.). Without it, SB is a
front door with the back door open.

The base **cannot** carry this ([`current-state.md`](current-state.md) kernel
section; the reproducibility rationale at `security.config:27-31`). So
lockdown is a **deployment kernel overlay**:

- A deployment kernel config fragment sets `CONFIG_SECURITY_LOCKDOWN_LSM=y`,
  `…_EARLY=y`, `CONFIG_MODULE_SIG=y`, `MODULE_SIG_FORCE=y`,
  `CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y` (auto-lockdown when SB is on), and
  ideally `KEXEC_SIG=y` + `KEXEC_BZIMAGE_VERIFY_SIG=y` so the existing kexec
  path ([apm kernel hot-reload]) stays usable under lockdown.
- `CONFIG_SYSTEM_TRUSTED_KEYS` embeds the deployment's module-signing public
  key into the kernel; `MODULE_SIG_ALL=y` signs in-tree modules at build.
- Out-of-tree / extra modules are signed with the same deployment key as a
  post-build step (the module-signing key in [`key-custody.md`](key-custody.md)).
- Cmdline gains `lockdown=confidentiality` (or `integrity`) and
  `module.sig_enforce=1`, added via `aos.boot.kernelParams` from the secure
  boot module (cmdline assembly at `modules/image/_builder.nix:37`,
  base params `modules/base/boot.nix:107-129`).

Because lockdown auto-engages under SB
(`LOCK_DOWN_IN_EFI_SECURE_BOOT`), the overlay and the firmware enforcement
reinforce each other: an SB machine is locked down, a locked-down kernel
won't load the unsigned modules an attacker would need.

### IMA/EVM and dm-verity (adjacent, not required)

- IMA already measures to PCR 10 ([`current-state.md`](current-state.md)) but
  has no TPM to seal to and no `IMA_APPRAISE`. Once a TPM exists
  ([`measured-boot.md`](measured-boot.md)), IMA measurements become
  attestable; IMA *appraisal* (enforcing signed file hashes) is a heavier,
  optional follow-on.
- `modules/security/verity.nix` (dm-verity, default off) protects rootfs
  *block integrity* — complementary to SB's *boot-binary authenticity*. A
  fully locked appliance would enable verity on the read-only root with the
  root hash baked into the (signed) UKI cmdline, so the signature chain
  extends to every rootfs block. Called out as a natural phase-2+ addition,
  not required for SB enforcement.

## Enrollment hook on hardware

First-boot PK enrollment (Setup Mode → User Mode) is an ignition-ordered
oneshot, same pattern as the existing first-boot units (`aos-gpt-relocate`,
`aos-growfs` in `modules/services/ignition.nix`): after disks/mount, before
the system is declared ready, an `aos-sb-enroll` oneshot writes the deployment
PK/KEK/db (delivered the same way the registry trust anchor is —
`modules/base/apm-registries.nix`, baked or via the metadata channel) and, if
configured, reboots into enforcing mode. Idempotent: skip if already in User
Mode. Detail deferred to implementation; the ordering slot is the point.

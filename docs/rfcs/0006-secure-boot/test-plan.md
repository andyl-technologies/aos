# RFC-0006 — Test plan

Every phase is CI-gated. The tests extend the existing image-boot fleet
harness ([RFC-0003](../0003-install-from-image.md),
`checks.fleet.install-from-image`), which already boots the raw image under
OVMF with per-machine `firmware_code`/`firmware_vars` and a writable per-run
vars copy ([`current-state.md`](current-state.md) test-harness section). That
harness is most of the substrate; the new tests add enrolled keys, a vTPM,
and the assertions.

## Phase 1 — SB enforcement

New check `checks.fleet.secure-boot` (image-boot machine with `secureBoot =
true`):

- **Positive:** signed UKI + signed sd-boot, OVMF_VARS pre-enrolled with the
  CI PK/KEK/db (`virt-fw-vars`), SB-enabled OVMF. Assert the machine boots to
  `multi-user.target` **and** is actually enforcing:
  - `bootctl status` reports `Secure Boot: enabled (user)`,
  - `/sys/firmware/efi/efivars/SecureBoot-*` reads `1`,
  - `/sys/firmware/efi/efivars/SetupMode-*` reads `0`.
- **Negative (the load-bearing one):** take the *same* enrolled-vars OVMF, but
  feed it a **tampered or unsigned UKI**. The cleanest mechanism given the
  immutable image: the driver already makes a per-run *writable* disk copy
  (`qemu.py` copies + grows + `sgdisk -e`s the image — RFC-0003), so the test
  mutates the UKI on that copy's ESP before boot (mcopy a byte-flipped UKI
  over `EFI/Linux/aos-*.efi`), or simply selects the unsigned build artifact.
  Assert the machine **fails to boot** — the harness must distinguish
  "firmware rejected the image" from a generic boot hang (look for the OVMF
  "Security Violation" / access-denied signature on the serial log, and assert
  the agent never comes up within a bounded window).

The negative test is what proves SB is *enforcing* rather than merely
*enabled* — without it, a no-op "SB on but accepts everything" regression
passes silently.

A regression guard: `checks.fleet.install-from-image` (no `secureBoot`) keeps
passing on the SB-enabled OVMF in Setup Mode (no PK) — proving the OVMF
rebuild didn't break the unsigned/dev path.

## Phase 2 — lockdown overlay

Eval + VM checks on a deployment kernel built with the lockdown overlay:

- the kernel config fragment yields `lockdown=` in the cmdline and
  `CONFIG_MODULE_SIG_FORCE=y` (eval-time / config assertion),
- on a booted SB machine, `/sys/kernel/security/lockdown` shows the active
  mode is `[confidentiality]` (or `[integrity]`),
- loading an **unsigned** module fails (`modprobe` of a deliberately-unsigned
  test module returns the signature error),
- a module signed with the deployment key loads.

## Phase 3 — measured boot

New check `checks.fleet.measured-boot` (machine with `tpm = true`, which
starts swtpm + attaches `tpm-tis` — [`measured-boot.md`](measured-boot.md)):

- **TPM present:** `systemd-analyze pcrs` / `tpm2_pcrread` shows PCRs
  populated; PCR 11 non-zero (the PCR-phase extender ran).
- **Sealed `/var` unlocks unattended:** boot, confirm `/var` is a LUKS2
  device unlocked via the TPM2 token (`systemd-cryptsetup` / `cryptsetup
  luksDump` shows a `systemd-tpm2` token), with **no** passphrase prompt.
- **Survives upgrade:** run the RFC-0003 upgrade leg (`apm upgrade --system`
  → reboot into the new generation) and assert `/var` **still** unlocks — the
  new UKI changed PCR 11 but the *signed PCR policy* still unseals. This is
  the test that proves the policy-signing approach, not hash-pinning.
- **Tamper rejection:** a UKI not signed by the PCR-policy key (or an SB-state
  change) leaves `/var` sealed — unsealing fails, recovery passphrase is the
  only way in (assert the TPM unseal fails, recovery key works).

The vTPM toggle and swtpm wiring also need a unit-level smoke test in the
driver (`qemu.py`) so a swtpm-launch failure surfaces as a clear harness
error, not a mysterious boot hang.

## Phase 4 — registry catalog

Extends the two-node shape of `install-from-image` (registry peer + target):

- **Publish records facts:** after `apr publish --sysroot` of a signed image,
  assert the registry metadata carries `sb_signer_cert_sha256`, `sbat`, and
  `expected_pcr11` derived from the actual UKI (compare against `sbverify
  --list` / `.sbat` dump / `systemd-measure` run independently in the test).
- **Download-time accept:** `apm upgrade --system` to a component whose
  recorded signer is in the active set and SBAT ≥ floor → succeeds. If the
  predicted-PCR-11 method is settled (see
  [`registry-catalog.md`](registry-catalog.md) caveat), also assert the
  recorded `expected_pcr11` matches what the machine measures after reboot;
  until then this sub-assertion is gated on resolving the
  UKI-alone-vs-full-phase-sequence prediction gap.
- **Download-time refuse (the headline):** raise the registry's SBAT
  revocation floor above the published component (signed metadata change),
  `apm update`, then assert `apm upgrade --system` **refuses before reboot**
  with the revocation message — the machine never reboots into a doomed UKI.
- **Retired-cert refuse:** mark the signer cert retired; assert `apm` refuses
  a component signed by it.

Implemented as `checks.fleet.registry-sb-catalog`: publishes the signed
server-secureboot sysroot + its UKI, asserts the derived facts, and drives
`apm` through refuse-on-unknown-signer → refuse-on-SBAT-floor → accept. The
`expected_pcr11` prediction gap above is resolved by measuring the UKI's PE
*sections* (not the UKI-as-kernel); the test cross-checks the recorded value
against an independent `objcopy` + `systemd-measure` recompute rather than a
post-reboot machine reading (that equality remains attestation-side future
work — the recorded value is the `enter-initrd`-phase digest, where `/var`
unseals).

## Cost / sequencing notes

- The SB and measured-boot OVMF/vTPM tests add VM boots; budget like the
  existing fleet tests (~minutes) and gate them behind the same KVM
  requirement.
- swtpm/libtpms is the heaviest new build dependency for CI; phase 3 can't
  land its tests until that packaging is green.
- Each phase's tests are independent — phase 4's catalog refusal test does not
  need a vTPM (it's a download-time check), so it can land before or after
  phase 3 as long as phase 1's signing exists to produce a real signer cert.

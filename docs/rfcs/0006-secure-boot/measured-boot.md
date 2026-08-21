# RFC-0006 — Measured boot & sealed encryption

Phase 3. Secure Boot answers "is this allowed to run." Measured boot answers
"what *actually* ran," records it in a TPM, and lets secrets unseal only when
the measurement matches. This is what turns SB from a checkbox into a payoff:
**TPM-sealed disk encryption for `/var` that survives OTA upgrades.**

Without it, SB is load-time only and `/var` (every generation, apm state, the
/nix overlay upper, user data) sits in cleartext on disk
([`current-state.md`](current-state.md) disk-encryption section).

> **Implementation status: implemented and covered by the measured-boot fleet
> test.** The TPM
> stack is packaged, the kernel has TCG drivers, systemd is built
> `-Dtpm2=enabled`, the UKI carries a signed PCR policy, OVMF is built
> `TPM2_ENABLE`, the CI harness attaches a swtpm vTPM, and `aos-var-crypt`
> LUKS2-formats `/var` and enrolls a TPM2 token sealed to the signed policy
> (PCR 11) + pinned PCRs 7 and 12 plus a recovery key.
> `checks.fleet.measured-boot`
> verifies the **whole flow end to end**: Setup-mode first boot → enroll →
> enforcing seal (LUKS2 `systemd-tpm2` + `systemd-recovery` tokens) → reboot →
> **unattended TPM2 unlock of `/var`** (no passphrase), across three reboots.
>
> Getting the unlock green took unwinding several subtleties, recorded here so
> they aren't relearned:
>
> - **vTPM continuity.** swtpm exits when QEMU disconnects, and a relaunched
>   swtpm wedges the boot. The driver resets the VM **in place** for TPM
>   machines (no `-no-reboot`), keeping QEMU+swtpm alive so the emulated TPM's
>   NV/keys persist while PCRs reset via `TPM2_Startup` — real-hardware
>   semantics. The reboot is detected with `wait_down` then `wait_ready` (the
>   in-VM reset keeps the agent socket up, so a stale pre-reboot PONG must not
>   be read as the reboot completing).
> - **ignition must not own `/var`.** If ignition's `filesystems` config
>   formats `/var` (`format=ext4`, `wipeFilesystem=false`), `ignition-disks`
>   *fails* on the unlock boot — `/var` is then `crypto_LUKS`, not the ext4 it
>   expects — and the failure cascades (units that `Requires=ignition-disks`)
>   into a stuck initrd. `/var` is kept in `partitions` but out of
>   `filesystems`; `aos-var-crypt` owns its filesystem (plain ext4 in Setup
>   mode, LUKS2 once enforcing).
> - **device readiness.** For a `crypto_LUKS` partition udev surfaces
>   `/dev/disk/by-partlabel/var` late, so `aos-var-crypt` carries no
>   `ConditionPathExists` (which would skip it) and instead polls for the
>   device; it only orders after `ignition-disks` rather than requiring it.
> - **the token plugin (the crux).** systemd's
>   `libcryptsetup-token-systemd-tpm2.so` — needed to *read* the systemd-tpm2
>   LUKS2 token at unlock — ships in systemd's store path, but libcryptsetup
>   dlopens external token plugins by **absolute path** from cryptsetup's
>   compiled tokens dir (an `LD_LIBRARY_PATH` wrapper does not help). cryptsetup
>   is built `--with-luks2-external-tokens-path=/run/cryptsetup/tokens` and
>   `aos-var-crypt` symlinks systemd's plugin dir there before unlocking.
>   `systemd-cryptsetup … tpm2-device=auto,tpm2-signature=<sd-stub .pcrsig>,headless`
>   then unseals against the signed policy.
> - **slow stage-2.** The argon2 luksFormat (~1 GB, ~17 s) and stage-2 TPM
>   PCR ops mean the agent answers before `multi-user.target`; the test polls
>   with `wait_until_succeeds`.

## Historical starting point

Before RFC-0006 phase 3, AOS had no TPM packages, systemd was built without
TPM2 support, the initrd stripped the systemd measurement and enrollment
tools, the kernel omitted the TCG drivers, and the QEMU harness had no vTPM.
The implementation summarized above closed that bring-up gap; this paragraph
is retained only to explain why the phase was designed as a complete stack
rather than an incremental sealing tweak.

## The PCR-policy problem (why naive sealing breaks OTA)

The obvious approach — seal the `/var` key to the current PCR values — breaks
on the first upgrade: a new UKI changes PCR 11 (the UKI measurement), so the
seal no longer opens and the machine can't unlock `/var`. Every
`apm upgrade --system` would brick decryption.

systemd's answer, which this RFC adopts: **sign a PCR policy.** `ukify` (with
`--pcr-private-key`/`--pcr-public-key`) measures the UKI and signs a policy
into the UKI's `.pcrsig`/`.pcrpkey` sections. `systemd-cryptenroll
--tpm2-public-key` seals `/var`'s key to *"any PCR-11 state signed by the
policy key,"* not to a specific hash. So **any UKI signed by the PCR-policy
key — with SB state otherwise unchanged — unseals `/var`**: upgrades just
work, a tampered/unsigned UKI does not.

The "with SB state unchanged" qualifier is load-bearing and easy to miss.
PCR 11 (the UKI measurement) is the *policy-covered, signature-flexible* PCR —
that's what changes per UKI and what the policy signature blesses. If the seal
*also* binds PCR 7 (SB state) and PCR 12 (boot inputs), those PCRs are pinned
**by value**, not by the policy signature. So the OTA-survival guarantee
covers UKI changes only when the clean PCR-12 event stream remains compatible;
a firmware/KEK or appended-input change fails to unseal and falls back to the
recovery key. That is the intended security property, but it means firmware
and measured-input changes need an authorized migration runbook and the
recovery path is not optional.

This is why the PCR-policy key is a release-time, offline key
([`key-custody.md`](key-custody.md)), and why it rides *inside* the UKI
(transported by the registry as content, never signed by the registry —
[`registry-catalog.md`](registry-catalog.md)).

## Bring-up steps

### 1. Package the TPM stack

- `tpm2-tss` (the TSS libraries) — new `pkgs/security/tpm2-tss.nix`.
- `swtpm` + `libtpms` (software TPM) — needed to give QEMU a vTPM in CI; new
  packages. This is the larger packaging lift (libtpms, then swtpm on top).
- `tpm2-tools` optional (debugging/attestation tooling).

### 2. Kernel TPM drivers

A kernel config fragment adds `CONFIG_TCG_TPM=y`, `CONFIG_TCG_TIS=y`
(and `CONFIG_TCG_CRB=y` for cloud/CRB interfaces), `CONFIG_HW_RANDOM_TPM=y`.
These belong in the **base** (drivers, not keys — no reproducibility issue,
unlike lockdown/module-sig).

### 3. systemd with TPM2

Flip `pkgs/system/systemd.nix:237,293` to `-Dtpm=true`/`-Dtpm2=enabled`
(depends on tpm2-tss), and **stop stripping** the measured-boot tools from
the initrd (`modules/base/_initrd-builder.nix:632`) — the PCR-phase extender
(`systemd-pcrextend`, with its `systemd-pcrphase*.service` units; confirm the
exact binary/unit names in the pinned systemd, as this was renamed from the
older `systemd-pcrphase`), `systemd-cryptsetup` with the TPM2 token, and
`systemd-cryptenroll` must be present in the initrd for unlock-at-boot.
`systemd-measure` is needed at *build* time (predict PCR-11 for the catalog —
[`registry-catalog.md`](registry-catalog.md)).

### 4. Sign a PCR policy into the UKI

Extend `pkgs/boot/aos-uki.nix` (already gaining SB-signing args in
[`boot-chain.md`](boot-chain.md)) with optional `pcrPublicKey`/`pcrPrivateKey`
→ `ukify build --pcr-public-key --pcr-private-key`. ukify also emits the
predicted PCR-11 measurement, which `apr publish` records
([`registry-catalog.md`](registry-catalog.md)).

### 5. Seal `/var`

This is the invasive part — it reorders first-boot provisioning. Today
ignition creates `var` as a plain ext4 (`modules/services/ignition.nix`
disks/mount; `modules/base/filesystems.nix`). With sealing, first boot:

1. ignition disks creates the `var` partition (unchanged),
2. a new `aos-var-encrypt` oneshot (ordered after disks, before
   `mount-var`) LUKS-formats it and `systemd-cryptenroll --tpm2-device=auto
   --tpm2-public-key=<policy pub>` seals the key to the signed PCR policy,
   **and** `--recovery-key` generates a recovery passphrase. That passphrase
   must be **escrowed off the machine at provisioning** — it cannot live on
   the encrypted volume it unlocks. Where: reported back through the same
   instance-metadata channel the machine was provisioned from (so the
   fleet's provisioning system records it), or sealed to an operator-held
   public key and stored in fleet inventory. The escrow target is a
   deployment decision, but "escrowed somewhere recoverable, never on
   `/var`" is a hard requirement (open question in the README),
3. subsequent boots unlock via the TPM2 token automatically
   (`systemd-cryptsetup`), no passphrase.

The existing `cryptswap` (`filesystems.nix:272-327`) can fold into the same
mechanism, or stay random-keyed (swap needs no persistence). Encrypting
`/var` is the new, security-meaningful piece.

PCR selection: bind PCR 11 to the signed UKI phase policy, and pin PCR 7 for
Secure Boot state plus PCR 12 for boot inputs. Disabling Secure Boot,
enrolling a foreign key, or appending boot input changes a pinned measurement
and `/var` will not unseal.

### 6. vTPM in CI

The QEMU harness (`pkgs/tools/aos/aos-test-driver/.../qemu.py`) gains, for
measured-boot machines, a swtpm socket + `-chardev socket,id=chrtpm,…
-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0`. The
fleet machine schema (`lib/testing/fleet.nix`) gains a `tpm = true` toggle
that starts swtpm alongside the VM. See [`test-plan.md`](test-plan.md).

## Attestation (inputs only)

With a TPM measuring and `apr publish` recording the expected PCR-11
([`registry-catalog.md`](registry-catalog.md)), the pieces for remote
attestation exist: a machine can produce a TPM quote, and a verifier can
compare it against the registry's recorded known-good value. Building the
quote/verifier service is **out of scope** (README non-goals) — this RFC
produces the inputs, not the attestation server.

## Ordering note

Measured boot depends on SB being real: sealing to PCR 7 (SB state) and PCR 12
(boot inputs) is meaningless if SB is not enforcing, and the PCR-policy key shares the
release-time offline custody model that phase 1 establishes. Hence phase 3
follows phases 1–2.

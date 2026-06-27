# RFC-0012: Golden image installer — a self-expanding disk from a single ESP

- **Status:** Proposed — design + first-boot sequence here; the change plan
  lives in [`implementation.md`](implementation.md).
- **Date:** 2026-06-26
- **PR:** _TBD_
- **Audience:** anyone working on `modules/image/`, `lib/build/rootfs.nix`,
  `modules/services/ignition.nix`, `modules/base/{boot,filesystems}.nix`, the
  initrd builder, `tests/fleet/`, and the operator docs under `docs/boot/`.
- **Relates to:** [RFC-0003](../0003-install-from-image.md) (the image →
  Ignition first-boot install flow this evolves) and
  [RFC-0006](../0006-secure-boot/README.md) (UKI signing, measured boot,
  TPM-sealed `/var`). Supersedes the abandoned v1 sketch of this RFC
  (immutable recovery ESP + first-boot-minted XBOOTLDR holding a separate
  installer UKI).

## Summary

Ship the AOS disk image as a **single 512 MiB EFI System Partition** that
carries everything needed to install and boot the system:

- systemd-boot (`sd-boot`),
- the **install UKI** (`EFI/Linux/aos-<name>-<version>.efi`), carrying the
  normal boot profile and a signed **emergency/recovery profile**, and
- the compressed read-only root filesystem as a **file**, `rootfs.bin` (EROFS
  data + an appended dm-verity hash tree), sitting next to the UKI on the ESP.
  Its verity **root hash is baked into the signed UKI cmdline**, so the signed
  boot chain covers the root image.

There are **no other partitions in the shipped image**. On first boot, the
operator's own Ignition config partitions the rest of the disk however they
like; a new stage-1 service then `dd`s `rootfs.bin` from the ESP onto the
freshly-created `root-a` partition. The result is maximal operator control over
the on-disk layout, a tiny immutable shipped artifact, and an ESP that doubles
as a known-good recovery/re-pave medium.

```text
Shipped image (single partition, ≈514 MiB total)
┌─────────────────────────────────────────────────────────────────┐
│ GPT  │ Partition 1 — ESP (FAT32, 512 MiB, PARTLABEL=ESP)  │ GPT │
│ pri  │   EFI/BOOT/BOOTX64.EFI         (UEFI fallback)     │ bak │
│      │   EFI/systemd/systemd-bootx64.efi (sd-boot)        │     │
│      │   EFI/Linux/aos-<name>-<ver>.efi  (install UKI)    │     │
│      │   rootfs.bin                   (EROFS root image)  │     │
│      │   loader/loader.conf                               │     │
└─────────────────────────────────────────────────────────────────┘
                         │  dd image to a larger disk, boot
                         ▼
Typical on-disk layout after first boot (operator-defined)
┌──────┬───────────┬──────────┬──────────┬──────────┬──────────────────┐
│ ESP  │ XBOOTLDR  │  root-a  │  root-b  │   swap   │      /var        │
│512MiB│ ≥512 MiB  │  4 GiB   │  4 GiB   │  4 GiB   │  rest of disk    │
│(kept)│(apm UKIs, │ (EROFS,  │ (A/B,    │(cryptswap│ (mutable state,  │
│      │  future)  │  dd'd)   │  future) │ per boot)│  nix overlay)    │
└──────┴───────────┴──────────┴──────────┴──────────┴──────────────────┘
  1         2          3          4          5            6
```

## Problem

The current image (`modules/image/_builder.nix`) ships **two** partitions: a
sized-to-fit ESP holding sd-boot + the UKI, and a `root-a` partition holding
the EROFS root. Ignition then carves `root-b`/`swap`/`var` out of the trailing
free space ([RFC-0003](../0003-install-from-image.md)).

That works, but the root partition's **size and position are fixed at image
build time**. The operator can only *grow* `root-a` (`ignition … resize`); they
cannot:

- choose a different layout order (e.g. an XBOOTLDR partition *before* the
  root slots, which is the systemd-canonical place for per-generation UKIs),
- size the A/B root slots independently of what the image baked in, or
- avoid shipping the root partition inside the image at all (it makes the
  artifact as large as the root, and forces a root slot to exist before
  Ignition has run).

We want to give operators full control over everything after the ESP —
A/B root slots, swap, `/var`, an XBOOTLDR partition, extra data partitions —
through their Ignition config alone, while keeping a single small immutable
artifact that is identical regardless of the intended runtime layout.

## Goals / non-goals

**Goals**

- A single, tiny, byte-reproducible shipped artifact: one 512 MiB ESP.
- The entire post-ESP layout is the operator's Ignition config; AOS bakes in
  no storage config of its own.
- The shipped ESP is a self-contained install **and** recovery medium: a
  known-good UKI + `rootfs.bin` that can re-pave `root-a` at any time.
- A/B-ready and XBOOTLDR-ready on-disk shape, so the future `apm` UKI/erofs
  update flow has somewhere to write.
- Reuse the existing first-boot machinery (platform detect → Ignition stages →
  overlays → switch-root), inserting the root-install and verity-assembly
  stage-1 services.
- Extend the signed boot chain to the **root** via dm-verity with the root hash
  baked into the signed UKI cmdline, and ship a **signed emergency/recovery
  profile** on the same UKI for recovery-key-gated console access.

**Non-goals (deferred / out of scope here)**

- `apm` support for **updating** the install UKI or `rootfs.bin`, writing
  per-generation UKIs to XBOOTLDR, or A/B activation. Tracked as future work
  (§Future work). This RFC only delivers the image builder + stage-1 changes.
- A baked-in default disk layout. AOS ships **no** storage config; the
  operator must supply one (decision recorded in §Alternatives). The "typical
  layout" in this document is a recommended example, not a default.
- New encryption mechanisms. Swap and `/var` encryption keep using the
  existing `cryptswap.service` and RFC-0006 measured-boot paths; Ignition only
  creates the raw partitions. (dm-verity is root *integrity*, not encryption, and
  **is** in scope — see §Security and §Emergency and recovery access.)

## The shipped image

A single GPT disk with one partition:

| # | Label | Type GUID | FS | Size | Contents |
|---|-------|-----------|----|------|----------|
| 1 | `ESP` | `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` | FAT32 | 512 MiB (build-time constant) | sd-boot, install UKI, `rootfs.bin`, `loader.conf` |

`loader.conf` keeps the existing `default aos-*.efi` glob (sd-boot picks the
lexically-highest `aos-*.efi`), `timeout 3`, `console-mode max`, `editor no`.
Under Secure Boot the two sd-boot copies are db-signed and the UKI is signed by
`aos-uki` (unchanged from today, RFC-0006).

The image is sized to `ESP + GPT overhead` (≈ 514 MiB) and `dd`-ed onto any
target disk of at least that size. The trailing free space is where Ignition
builds the rest of the layout.

**ESP sizing.** 512 MiB is a build-time constant (`espSizeMiB`, default 512).
It must hold the UKI (dominated by the bundled kernel + initrd — tens of MiB,
estimated), sd-boot (~150 KiB, estimated), `rootfs.bin` (~160 MiB for the current
server closure, `lib/build/rootfs.nix:297`), `loader.conf`, and FAT overhead —
comfortably inside 512 MiB today. The **authoritative** guarantee is not these
estimates but the builder's fit assertion (`_builder.nix` §2a in
[implementation.md](implementation.md)): it sums the *actual* ESP contents and
fails the build with a clear message if `rootfs.bin` + UKI outgrow the ESP,
prompting the operator to raise `espSizeMiB`. (See §Security and §Future work for
why the root image can't simply spill out of the ESP.)

## The typical on-disk layout (recommended, operator-supplied)

The layout below is what the operator's Ignition config *typically* declares.
Sizes are illustrative — the operator owns them.

| # | Label | Type GUID | FS | Created by | Owned by |
|---|-------|-----------|----|-----------|----------|
| 1 | `ESP` | ESP | FAT32 | image | firmware / sd-boot (immutable) |
| 2 | `XBOOTLDR` | `BC13C2FF-59E6-4262-A352-B275FD6F7172` | FAT32 | Ignition | `apm` per-gen UKIs (future) |
| 3 | `root-a` | `0FC63DAF-8483-4772-8E79-3D69D8477DE4` (Linux data) | **EROFS (dd'd)** | Ignition (partition) + AOS (`dd`) | immutable root, generation A |
| 4 | `root-b` | Linux data | _(none yet)_ | Ignition | A/B slot B (future) |
| 5 | `swap` | `0657FD6D-A4AB-43C4-84E5-0933C84B4F4F` | per-boot dm-crypt | Ignition (partition) + `cryptswap.service` | encrypted swap |
| 6 | `var` | Linux data | ext4 | Ignition | persistent mutable state, nix overlay upper |

Partition **numbers are illustrative**: AOS never refers to these partitions by
number. The baked UKI cmdline uses `root=/dev/disk/by-partlabel/root-a`, and
every stage-1 service keys off `/dev/disk/by-partlabel/<label>`. The operator
may reorder or renumber freely as long as the **labels and type GUIDs** in the
contract below are honored.

## The AOS ⇄ Ignition contract

Because AOS ships no storage config, the operator's Ignition config is the sole
source of the layout. AOS depends on the following invariants; the operator's
config **must** honor them.

### Required

- **`root-a`** — a partition with `PARTLABEL=root-a` and the Linux-data type
  GUID, **left unformatted** (no `storage.filesystems` entry, or `format`
  unset). AOS writes the EROFS image onto it with `dd` at first boot; an
  Ignition-created filesystem here is overwritten by the install — its UUID
  mismatches `rootfs.bin`'s EROFS UUID, so the gate correctly re-`dd`s it
  (§First boot, step 6). It must be **at least as large as
  `rootfs.bin`** (the builder records the exact size in `image-info.json` and
  in `${rootfs}/rootfs-size-bytes`); 4 GiB is the recommended slot size for
  headroom and A/B symmetry.
- **`var`** — a partition with `PARTLABEL=var`, formatted `ext4` (or the
  operator's choice that matches `/etc/fstab`). Its **presence is AOS's
  "provisioning complete" sentinel**, keyed on `/dev/disk/by-partlabel/var`:
  `aos-gpt-relocate` skips once it exists, and `mount-var` activates when it exists.

### Optional (enables future capability / typical hardening)

- **`swap`** — `PARTLABEL=swap`, Linux-swap type GUID, **left unformatted**.
  `cryptswap.service` runs `mkswap` on a fresh random-keyed dm-crypt device
  every boot; an Ignition `format: swap` here is unnecessary and discarded.
- **`root-b`** — `PARTLABEL=root-b`, Linux-data type GUID. Reserved for the
  future A/B update flow; unused until `apm` learns to write it. (The
  `install-from-image` test formats it `ext4` so the partition is valid, but
  nothing mounts it; the typical-layout table above lists its FS as "none yet"
  because no AOS code consumes `root-b` today.)
- **XBOOTLDR** — a partition with the XBOOTLDR type GUID
  (`BC13C2FF-…`), formatted FAT32. sd-boot scans it on the same disk it booted
  from and merges its `EFI/Linux/*.efi` and `loader/entries/*.conf` into one
  menu with the ESP's. Reserved for `apm`'s per-generation UKIs (future);
  created but unused by this RFC.

### Global

- `storage.disks[].wipeTable` **must be `false`** because the operator's config
  does not re-declare the ESP, so a table wipe would delete the partition we
  booted from and brick the system. Ignition's own `refusing to wipe active
  disk` guard does **not** protect against this here — it only fires when
  `wipeTable` is `true` **and** a partition on the target disk is mounted or held
  (`internal/exec/stages/disks/partitions.go:452-456`, `blockDevInUse` `:391-427`),
  and at `ignition-disks` time the ESP is not yet mounted (the initrd ships an
  empty fstab; `aos-install-root` mounts the ESP only afterwards). New partitions
  are created in the trailing free space with `wipePartitionEntry` defaulting
  off.

A complete example config is kept in sync between `docs/boot/qemu-uefi.md` and
`checks.fleet.install-from-image`, which exercises it
([implementation.md](implementation.md) §7–8; the doc is updated to this contract
in §8). _(Today the doc still carries the pre-RFC config; §8 lands the update.)_

## First boot

The boot chain is the existing systemd-driven stage-1
(`modules/services/ignition.nix`) with **one new service** —
`aos-install-root.service` — inserted between `ignition-disks` and
`sysroot.mount`, and a reworked `aos-gpt-relocate`. UEFI loads sd-boot → the
install UKI → the kernel + initrd unpack, and PID 1 (systemd) runs:

1. **`aos-platform-detect`** — ISO `aos-metadata` label → DMI → `metal`
   fallback. Writes `/run/ignition/platform.env`; touches
   `/run/ignition/need-network` for cloud platforms. _(unchanged)_
2. **`aos-ignition-network`** — DHCP on cloud platforms only. _(unchanged)_
3. **`ignition-fetch`** — fetches the operator's config for the detected
   platform. _(unchanged)_
4. **`aos-gpt-relocate`** — moves the GPT backup header to the true end of the
   disk so Ignition can use the full device. **Reworked:** it now resolves the
   boot disk from `/dev/disk/by-partlabel/ESP` (the only partition that exists
   pre-provisioning), not from `root-a` (which no longer ships in the image).
   Still gated to the pre-provisioning boot via `var` absence.
5. **`ignition-disks`** — `ignition --stage=disks`. Creates the operator's
   partitions (XBOOTLDR, `root-a` **unformatted**, `root-b`, `swap`, `var`) and
   formats the ones with `storage.filesystems` entries (`var`, optionally
   `root-b`, XBOOTLDR). `root-a` and `swap` are left raw. _(config-driven)_
6. **`aos-install-root` (NEW)** — installs the root image onto `root-a`:
   - **Gate:** run only if `rootfs.bin` is present on the ESP **and** `root-a`
     does not already hold the shipped EROFS image (see idempotency below).
   - Mount the ESP (`/dev/disk/by-partlabel/ESP`) read-only at a scratch
     mountpoint, `dd if=<esp>/rootfs.bin of=/dev/disk/by-partlabel/root-a`,
     `sync`, then `fsck.erofs` the result to confirm a complete, valid image,
     and unmount the ESP.
   - Ordered `After=ignition-disks.service`/`systemd-udev-settle.service`;
     `Before=sysroot.mount`/`aos-growfs`. It **gates on the ESP and `root-a`
     partlabels via `ConditionPathExists` only** — it must *not* `Requires=`/`After=`
     their `.device` units, or a kernel-boot test disk (whose partition 1 is
     labeled `boot`, not `ESP`) would queue ~90 s on the missing device and fail
     the boot (implementation.md §3a; cf. the `cryptswap` swap-stub precedent,
     `lib/testing/vm.nix:53-57`).
7. **`sysroot.mount`** — synthesized from `root=/dev/disk/by-partlabel/root-a`;
   mounts the now-populated EROFS read-only at `/sysroot`. _(unchanged)_
8. **`aos-growfs`** — no-op for an EROFS root. _(unchanged)_
9. **`mount-var`**, **`nix-overlay-setup`**, **`aos-seed-profiles`** (writes
   gen-1 `state.json`, reading `/sysroot/aos-toplevel` from the just-installed
   EROFS), **`aos-machine-id`** — _(unchanged; they operate on `/sysroot`,
   which is now backed by the dd'd image, so the seed pointer and Nix DB seed
   resolve exactly as before)_.
10. **`ignition-mount`** / **`ignition-files`** (per-gen lower under
    `/run/etc/ignition-<gen>`), **`etc-overlay-setup`** (3-layer composefs
    `/etc`) — _(unchanged)_.
11. **`initrd-switch-root`** → pivot to stage-2.

The only conceptual change to the chain is the **`dd` step**: Ignition cannot
write an EROFS image or `dd` a raw blob (its filesystem stage only knows
`ext4`/`btrfs`/`xfs`/`vfat`/`swap`), so AOS owns the root-image install as a
custom oneshot — exactly the pattern already used for `aos-gpt-relocate`,
`aos-growfs`, and `cryptswap`.

### Idempotency (subsequent boots)

Every first-boot action is guarded so later boots are no-ops:

| Service | Gate | Subsequent boot |
|---------|------|-----------------|
| `aos-gpt-relocate` | `var` partition absent | skips (var present) |
| `ignition-disks` | Ignition's declarative diff + the `.ignition-result.json` stamp (`/var/etc/…`, written under `--root=/sysroot` in the initrd) | partitions already match → no change |
| `aos-install-root` | `root-a` not already the shipped EROFS | skips (root-a holds the image) |
| `mount-var` | `var` exists | mounts existing `/var` |
| `aos-seed-profiles` | `state.json` absent | skips (gen-1 already seeded) |
| `aos-machine-id` | `/var/etc/machine-id` absent | skips |

The `aos-install-root` gate is **self-describing and power-fail-safe**: it
compares `root-a`'s EROFS UUID to `rootfs.bin`'s UUID (both via `blkid`) and
runs `fsck.erofs` on `root-a`. The fixed UUID (`bdfb6fc9-…`) is the EROFS root's,
set on the production EROFS path only (`lib/build/rootfs.nix:317`; the ext4
dev-test root gets a random UUID). A complete, matching image → skip. A missing,
mismatched, or *partial* image (e.g. power lost mid-`dd`, leaving a truncated
EROFS that fails `fsck.erofs`) → re-`dd`. Because `root-a` is not yet in use
when this runs, a re-`dd` is always safe.

## Bootloader behavior

systemd-boot v259.1 (already vendored) scans, on the disk it booted from, both
the ESP and a same-disk XBOOTLDR partition, merging their Type #1 (`.conf`) and
Type #2 (UKI) entries into one sorted menu. This RFC relies only on the ESP
scan today:

- **Now:** one install UKI in the ESP's `EFI/Linux/`; the `default aos-*.efi`
  glob selects it. The install UKI's filename carries **no `+tries` boot
  counter** (the ESP is read-only at runtime; sd-boot must not try to rename it
  there).
- **Future (apm):** new generations install their UKI to the **XBOOTLDR**
  partition as `aos-<version>+<N>.efi`, where the `+N-M` suffix drives
  automatic boot assessment (`systemd-bless-boot good` on a healthy boot;
  exhausted entries sort last so the previous generation wins). The install UKI
  in the ESP remains the permanent recovery entry. This is why XBOOTLDR is in
  the typical layout even though nothing writes it yet.
- **Per-machine entropy:** a golden image clones identical ESP contents to every
  machine. The load-bearing invariant today is that the shipped ESP carries **no**
  `loader/random-seed` file — the builder writes only `loader.conf`
  (`modules/image/_builder.nix:178-183`) and `systemd-boot-random-seed.service` is
  masked (`modules/base/boot.nix:167-173`), so sd-boot's seed read is a silent no-op
  and no seed material is shared across clones. Minting a fresh `LoaderSystemToken`
  per machine (`bootctl random-seed`) is deferred defense-in-depth (it needs a
  transient ESP remount, since the ESP is read-only); wired with the apm work. A
  future builder that ever baked a `loader/random-seed` would silently share RNG seed
  across all clones — this absence is enforced today only by inspection of
  `_builder.nix:178-183`, so a regression test asserting the shipped ESP contains no
  `loader/random-seed` should land alongside the future apm ESP-write flow.

## Encryption

Per the scope decision, Ignition creates only **raw** partitions; encryption
stays with AOS's existing services:

- **Swap** — `cryptswap.service` (`modules/base/filesystems.nix`) opens the
  `swap` partition as a plain dm-crypt device keyed from `/dev/urandom` and
  runs `mkswap` every boot, so swap contents are unrecoverable across reboots.
  The operator's config must therefore leave `swap` unformatted.
- **`/var`** — under RFC-0006 measured boot, `aos-var-crypt` unseals a
  TPM-bound LUKS volume and exposes `/dev/mapper/var`, which `mount-var`
  prefers over the raw partition. Without measured boot, `var` is the raw ext4
  partition. Either way, Ignition just creates the partition.

## Recovery / re-pave

Because the ESP permanently carries a known-good UKI **and** `rootfs.bin`, the
shipped medium is also a recovery medium: re-running the `aos-install-root`
`dd` (e.g. by clearing `root-a` and rebooting, or via a future `apm` recovery
verb) restores the root image without a network or a rebuild. The ESP is never
written at runtime in this RFC (only firmware reads it and stage-1 mounts it
read-only), so it stays trustworthy as long as the medium is intact.

## Emergency and recovery access

The install UKI on the ESP doubles as the emergency/recovery entry. Because the
ESP is read-only, the root is immutable, and `/var` is TPM-sealed, console
access is structured so that it can neither persist a change nor expose sealed
state without the off-machine LUKS **recovery key** — the recovery key, not a
baked root password, is the authorization factor.

### A signed emergency profile, not a runtime karg

Secure Boot makes the obvious lever mostly a no-op: when the UKI carries a baked
`.cmdline`, sd-stub drops the **menu/LoadOptions** command line and uses the signed
one (systemd v259.1 `src/boot/stub.c:1184-1200`), and `editor no`
(`modules/image/_builder.nix:182`) blocks editing at the menu. So
`rd.systemd.unit=emergency.target` / `systemd.debug_shell` / `systemd.setenv=…`
*typed at the menu* never reach PID 1. (One gap remains: sd-stub still **appends**
unsigned SMBIOS/addon cmdline *after* the signed section — `stub.c:1273-1274`,
measured into PCR 12 (SMBIOS strings also into firmware PCR 1) — so a hostile hypervisor can inject kargs even under
Secure Boot. That vector is closed separately by the PCR-12 pin and the locked root
account, §"The root account"; it is *not* closed by the cmdline-drop alone.) The
emergency entry is therefore a second **signed** boot path:

- **Multi-profile UKI (preferred).** The install UKI carries a second `.profile`
  whose baked, signed `.cmdline` boots a dedicated `aos-recovery.target`
  (autologin — not `emergency.target`; see below). The `@N` profile
  selector is parsed out before the command line is dropped (`src/boot/stub.c:188`,
  `:1232-1245`) and selects the profile's signed section set (`stub.c:1148-1158`);
  sd-boot renders one menu entry per profile (`src/boot/boot.c:2177-2263`). One
  signed PE, no ESP write, compatible with `editor no`.
- **Second signed UKI (alternative).** A separate `EFI/Linux/aos-<ver>-rescue.efi`
  with the emergency cmdline baked and signed — simpler, but costs a second UKI
  against the `espSizeMiB` budget.

The @1 recovery shell runs in the **initrd**, via a dedicated
`rd.systemd.unit=aos-recovery.target` whose signed `.cmdline` boots an autologin
recovery shell — **not** `emergency.target`, whose `sulogin` would refuse under the
mandated locked root (§"The root account"). `aos-var-crypt` is itself an initrd
service wanted by `initrd-fs.target` (`modules/base/secure-boot.nix:311-314`);
`aos-recovery.target` runs `DefaultDependencies=no` and does not pull in
`initrd-fs.target`, so `initrd-fs.target`'s wants — `aos-var-crypt` among them — are
never started, and the recovery path never auto-unseals `/var`. Even a *manual*
unseal attempt fails on the dedicated **@1** emergency profile: it measures a PCR-11
the signed `.pcrsig` does not bless (precondition 2 below; mechanism in
implementation.md §10b), so the TPM policy rejects it. This holds for
the **@1** profile only — a *normal* **@0** boot that merely *falls* into
`emergency.target` (e.g. the fail-closed `aos-install-root` drop) carries the
**blessed** PCR-11 and *can* unseal `/var`; that path is fenced off by the locked
root account and the PCR-12 pin (§"The root account", precondition 3 below), not by
this isolation.

### Why a password-less shell is sound

This RFC delivers the three properties a password-less emergency shell depends
on. (Outside Secure Boot — the unsigned dev image — the emergency profile is
password-protected via `sulogin`, since none of them carries a guarantee
without the signature.)

1. **dm-verity on the root, root hash in the signed cmdline.** The signed cmdline
   pins the root *device* (the base `root=/dev/disk/by-partlabel/root-a` at
   `modules/base/boot.nix:165` is repointed to `/dev/mapper/root` by `aos-uki` when
   verity is active — implementation.md §9b, *not* by boot.nix) and, with this RFC,
   its *content*: `rootfs.bin` carries an appended verity hash tree and the root hash
   is baked into the signed UKI cmdline, so a root shell that `dd`s a tampered EROFS
   onto `root-a` fails verity (the mapper opens but reads return `EIO`) and the system
   fails closed instead of running the backdoor with Secure Boot intact. The root hash
   must be anchored to the *signed* `.cmdline`, not a greedy `/proc/cmdline` scan —
   sd-stub appends unsigned SMBIOS/addon cmdline afterwards, so stage-1 rejects a
   duplicate `roothash=` (implementation.md §9c). EROFS pairs naturally with dm-verity;
   the kernel pieces are builtin (`pkgs/kernel/config/storage.config:26-27`) and the
   wiring lands in `lib/build/rootfs.nix` / `pkgs/boot/aos-uki.nix` / stage-1
   (implementation.md §9). (`modules/security/verity.nix` provides an
   `aos.security.verity` option surface, but it assumes a *separate* hash device —
   `verity.data=`/`verity.hash=`, defaulting to `/dev/vda2`/`/dev/vda3` — so this RFC's
   appended-`--hash-offset` EROFS model extends or supersedes it.)
2. **The @1 emergency *profile* breaks the `/var` TPM auto-unseal.** The seal is
   signature-flexible on PCR 11 (the UKI/cmdline measurement) and pinned by value
   on PCR 7 (`modules/base/secure-boot.nix:208-228`;
   [measured-boot.md](../0006-secure-boot/measured-boot.md)). The @1 profile is built
   so its PCR-11 prediction is **excluded** from the signed `.pcrsig` set, so reaching
   *that* shell forces the recovery-key path; a CI assertion proves it cannot
   auto-unseal `/var` (implementation.md §10). This covers the @1 profile **only** —
   not a normal @0 boot that falls into `emergency.target` (precondition 3).
3. **A locked root account, and PCR 12 pinned into the seal, fence off the @0
   path.** Because a *normal* @0 boot carries the blessed PCR-11, the @1 exclusion
   does not protect it; two further controls do. (a) **Locked root:** the root account
   is locked (`!`/`*`), so `sulogin` on an @0 drop into `emergency.target` refuses a
   shell — closing the offline-corruption path that induces such a drop (the initrd
   root must change from empty to locked; stage-2 is already locked —
   implementation.md §10c). (b) **PCR-12 pin:** the seal also pins PCR 12, which
   measures the appended (override/SMBIOS) cmdline, so an injected
   `SYSTEMD_SULOGIN_FORCE=1` /
   `roothash=` / `rd.systemd.unit=` (via the unsigned SMBIOS append, the one karg
   vector left under Secure Boot) changes the measurement and the TPM refuses `/var`
   (implementation.md §10d). The security boundary is thus the **PCR binding**, not the
   shell mechanism — see §"The root account".

### The root account: locked, conditional on the boot posture

The password-less @1 recovery shell is sound only when no *other* path on the
blessed @0 profile offers an unauthenticated root with `/var` access. That reduces
to a single requirement: **under Secure Boot, the root account is locked** (no valid
password hash, not an empty one) in **both** stages.

- The **initrd** root is currently *empty* (`_initrd-builder.nix:526` =
  `root:::…`), which today already yields a passwordless `sulogin` on any emergency
  drop. Under Secure Boot it must become *locked* (`root:!*::…`); on the unsigned
  dev image it instead carries a password hash (the non-SB `sulogin`-protected
  posture), since one static shadow line cannot be both — so the line is gated on
  `aos.boot.secureBoot.enable` (implementation.md §10c).
- The **stage-2** root is **already** locked by default (`users.nix:31` emits
  `root:!*::…`; the inline comment at `:28` saying "empty password hash" is stale).
- The @1 recovery shell is granted by @1's *signed* cmdline (a baked
  `agetty --autologin` recovery target), **not** by `SYSTEMD_SULOGIN_FORCE` — that
  knob is readable straight from the cmdline, so the SMBIOS append could force it on
  @0. The robust @0/@1 boundary is the PCR binding (preconditions 2 + 3), never a
  cmdline token, because @0's cmdline is appendable.

This is a **conditional** guarantee, not a blanket mandate. It applies only when
`aos.profiles.debug.autologin` (and the debug security level) is off. A deployment
may legitimately choose root autologin — that is what `systems/server.nix:16` does
today — which force-unlocks root, adds autologin gettys, and masks the initrd
`sulogin` recovery units (`modules/profiles/debug.nix:86-89,:122-128`). That is an
informed opt-out of the sealed-`/var` guarantee, exactly parallel to running outside
Secure Boot, and is appropriate for VM testing and trusted-network use (the option
is already documented "NEVER enable this on a system exposed to an untrusted
network").

### Authorization model

With all three preconditions met, the recovery key is the only thing that changes
persistent state or exposes `/var`:

- **Reinstall** re-`dd`s `rootfs.bin` from the ESP onto `root-a`
  (§Recovery / re-pave); under verity an arbitrary substitute fails to boot, so
  this needs no password.
- **Unsealing `/var`** uses the LUKS recovery slot `aos-var-crypt` enrolls and
  never wipes (`modules/base/secure-boot.nix:447-449`, `:454`); only an operator
  holding the escrowed recovery passphrase can open it.

Lockdown (engaged via `modules/base/secure-boot.nix:280-283`, with unsigned-kexec
denial enforced by `CONFIG_KEXEC_SIG_FORCE` at `:49-52`, when enabled) already denies
a console root the usual escalation paths (unsigned modules, unsigned kexec,
`/dev/mem`); verity and the sealed `/var` deny persistence and exfiltration. Once the
root account is locked and PCR 12 is pinned (§"The root account"), the residual power
of console root is then **destructive only** (e.g. erasing the LUKS header or
corrupting `root-a`, forcing a re-pave) — acceptable where physical access already
implies denial of service. **Without** those two controls a console root reached on
the blessed @0 profile (an induced fail-closed drop, or an injected
`SYSTEMD_SULOGIN_FORCE=1`) can unseal `/var`, so they are load-bearing, not optional;
deployments that also want a credentialed shell keep a root password.

## Security considerations

- **The signed boot chain covers the root.** Under Secure Boot the install UKI
  (kernel + initrd + cmdline) is Authenticode-signed and measured, and this RFC
  extends that coverage to the root: `rootfs.bin` ships as EROFS data plus an
  appended dm-verity hash tree, and the verity **root hash is baked into the
  signed UKI cmdline** (`pkgs/boot/aos-uki.nix`), so a tampered `rootfs.bin` or
  `root-a` fails verity and the system fails closed instead of running a backdoor
  with Secure Boot intact. The anchor is the **signed `.cmdline` section**, not
  `/proc/cmdline` (sd-stub appends unsigned SMBIOS/addon cmdline afterwards), so
  stage-1 rejects a duplicate `roothash=` to defeat injection (implementation.md
  §9c). The kernel pieces are
  builtin — `CONFIG_DM_VERITY=y` and `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y`
  (`pkgs/kernel/config/storage.config:26-27`); the work is the rootfs builder
  emitting the hash tree + root hash, `aos-uki` baking the signed roothash, and a
  stage-1 step assembling the verity device before `sysroot.mount`
  (implementation.md §9). Outside Secure Boot the mechanism still runs, but the
  unsigned cmdline carries no guarantee — security comes from the signature, as
  everywhere in AOS. This is what makes the password-less emergency shell sound
  (§Emergency and recovery access).
- **ESP immutability.** The ESP is read-only at runtime (firmware reads it;
  stage-1 mounts it `ro`; `systemd-boot-update.service` and
  `systemd-boot-random-seed.service` are masked). The only planned writer is
  the future `apm` UKI-update flow, which must remount transiently and
  re-establish the signature posture.
- **`dd` is not atomic, and the install path is fail-closed.** A crash mid-install
  leaves a partial EROFS on `root-a`; the `fsck.erofs` gate detects it and
  re-installs on the next boot, and `root-a` is never live during install, so there
  is no torn-read window for a running system. Beyond ordering
  (`Before=sysroot.mount`), `sysroot.mount` carries a hard
  `Requires=aos-install-root.service` (`implementation.md` §3a), so a failed
  install+verify drops the boot to emergency rather than mounting a bad root —
  **fail-closed uniformly** across signed and unsigned images. Under Secure Boot
  this is reinforced by `root=` pointing at the verity mapper (`implementation.md`
  §9b): a partial or tampered image yields no `/dev/mapper/root` (or fails the
  roothash), so the mount cannot succeed. On the unsigned dev image (raw `root-a`,
  no verity) the `Requires=` is what prevents a partial-but-mountable EROFS from
  booting. `Requires=` (not `BindsTo=`) is used so a later inactive state of the
  `RemainAfterExit` oneshot cannot tear down a live root mount; the
  `ConditionPathExists`-skipped no-op on the kernel-boot test counts as success, so
  that test is unaffected.
- **Cmdline pinning.** Two distinct protections, often conflated: (1) at *runtime*,
  the UKI's baked `.cmdline` is signed and, under Secure Boot, a **menu/LoadOptions**
  command line is dropped by sd-stub (`src/boot/stub.c:1184-1200`), with `editor no`
  (`modules/image/_builder.nix:182`) as a second layer — so kargs cannot be *edited at
  the menu*; (2) at *build time*, an assertion (`modules/base/boot.nix:127-141`)
  rejects `ignition.config.url=` in `aos.boot.kernelParams`. Note the residual gap:
  sd-stub still **appends** unsigned SMBIOS/addon cmdline after the signed section
  (`stub.c:1273-1274`, measured into PCR 12; SMBIOS strings also into firmware PCR 1), so a hostile hypervisor can inject
  kargs even under SB — defeated not by the drop but by the verity duplicate-`roothash`
  guard (§9c) and the PCR-12 pin (§10d). Under verity the baked `root=` additionally
  points at the verified mapper (§Emergency and recovery access, precondition 1).
- **Emergency / recovery access.** The install UKI doubles as the recovery entry
  via the signed **@1** emergency profile, never a runtime karg. The off-machine LUKS
  recovery key — not a baked root password — authorizes any change to persistent
  state. A password-less shell is sound only once (1) the root is dm-verity-protected,
  (2) the @1 profile's PCR-11 is excluded from the seal, and (3) the root account is
  locked and PCR 12 is pinned so a *normal*-profile (@0) drop or an injected karg
  cannot reach an unauthenticated shell with `/var` unsealable. See §Emergency and
  recovery access (preconditions 1–3) and §"The root account".

## Alternatives considered

- **Keep the root as a baked image partition (current v2).** Simple, no `dd`
  step, but the artifact carries the root, the root slot must exist before
  Ignition runs, and the operator can only *grow* it — they cannot choose the
  post-ESP layout (XBOOTLDR-first, independent A/B sizes, extra partitions).
  Rejected: it does not meet the flexibility goal.
- **A baked default Ignition layout** that the operator overrides. Would make
  the image self-install on bare metal with zero config. **Rejected by
  decision** (2026-06-26): the operator always supplies the storage config; the
  typical layout is documentation, keeping a single behavior with no
  merge-semantics surprises.
- **Resize the ESP in place at first boot (`fatresize`).** Rejected in prior
  research: deprecated libparted FS-resize, a hard 256 MB FAT floor, non-atomic
  resize window, no test suite, and a new parted dependency chain. Moot here —
  the ESP is a fixed 512 MiB and is never resized.
- **`systemd-repart` for first-boot partitioning** instead of Ignition. AOS
  standardizes on Ignition for first-boot provisioning across all platforms
  (cloud user-data, ISO, fw_cfg); adding repart would be a second, parallel
  provisioning surface. Rejected for consistency.
- **Have Ignition write the root.** Ignition's filesystem stage supports only
  `ext4`/`btrfs`/`xfs`/`vfat`/`swap` and cannot `dd` a raw image, so an EROFS
  root cannot be produced declaratively. The custom `aos-install-root` service
  is required regardless.

## Open questions / future work

- **`apm` UKI + `rootfs.bin` updates.** The whole point of XBOOTLDR + `root-b`
  is the future update flow: `apm` writes a new UKI (with `+tries` boot
  counter) to XBOOTLDR and a new `rootfs.bin` to `root-b`, then flips A/B.
  Today `apm`'s sysroot path writes a single static
  `/boot/loader/entries/aos.conf` and is not XBOOTLDR/UKI-glob aware
  (`crates/aos-package/src/sysroot.rs`) — reconciling that with the image's
  UKI-glob model is the first task of the follow-up.
- **`/boot` vs `/efi` split.** The systemd convention is XBOOTLDR at `/boot`
  and the ESP at `/efi`. This RFC keeps the ESP at `/boot` (where the only UKI
  lives); the split lands with the apm work, once something writes XBOOTLDR.
- **Roothash signature in the kernel keyring** (`CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`)
  as a second anchor beyond the signed cmdline. Out of scope here; the signed
  cmdline is the primary anchor.
- **Per-machine `LoaderSystemToken`** minting at first boot (see §Bootloader).
- **Root-image size vs ESP size.** If a future closure grows `rootfs.bin` past
  the 512 MiB ESP budget, `espSizeMiB` must rise (or the root image must be
  split). The builder asserts the fit; revisit the constant when it trips.

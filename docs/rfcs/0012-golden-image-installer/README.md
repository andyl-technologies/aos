# RFC-0012: Golden image installer — a self-expanding disk from a single ESP

- **Status:** Proposed — design + first-boot sequence here; the change plan
  lives in [`implementation.md`](implementation.md).
- **Date:** 2026-06-26 (revised 2026-07-01 to build on RFC-0011's
  systemd-repart substrate)
- **PR:** _TBD_
- **Audience:** anyone working on `modules/image/`, `lib/build/rootfs.nix`,
  `modules/services/repart.nix`, `modules/services/boot-substrate.nix`,
  `pkgs/boot/aos-uki.nix`, `modules/base/{boot,filesystems,secure-boot}.nix`,
  the initrd builder, `tests/fleet/`, and the operator docs under `docs/boot/`.
- **Relates to:** [RFC-0011](../0011-on-host-config-eval/README.md) — this RFC
  builds directly on the systemd-repart provisioning substrate,
  the dm-verity + signed-roothash chain, and the on-host config-eval that
  RFC-0011 ships; [RFC-0003](../0003-install-from-image.md) (the image →
  first-boot install flow this evolves) and
  [RFC-0006](../0006-secure-boot/README.md) (UKI signing, measured boot,
  TPM-sealed `/var`). Supersedes the abandoned v1 sketch of this RFC
  (immutable recovery ESP + first-boot-minted XBOOTLDR holding a separate
  installer UKI).

> **Revision note (post-RFC-0011).** This RFC was first drafted against the
> Ignition first-boot machinery. RFC-0011 **removed Ignition** and replaced it
> with a systemd-native substrate: `systemd-repart` convention drop-ins carve
> and grow partitions in the initrd (`modules/services/repart.nix`), an
> `aos metadata` agent handles cloud user-data transport, and
> `aos-config-seed.service` seeds the per-generation `/etc` lower layer
> (`modules/base/boot-substrate.nix`). RFC-0011 also **already ships**
> dm-verity on the EROFS root with the root hash baked into the signed UKI
> cmdline (`pkgs/boot/aos-uki.nix`, `modules/security/verity.nix`). This
> revision re-expresses the golden-image installer on that substrate — the root
> image install becomes a `systemd-repart` `CopyBlocks=` drop-in rather than a
> custom `dd` service — so the design is now a **smaller** delta than it was
> against Ignition. It does **not** supersede RFC-0011; it extends it.

## Summary

Ship the AOS disk image as a **single 512 MiB EFI System Partition** that
carries everything needed to install and boot the system:

- systemd-boot (`sd-boot`),
- the **install UKI** (`EFI/Linux/aos-<name>-<version>.efi`), carrying the
  normal boot profile and a signed **emergency/recovery profile**, and
- the compressed read-only root filesystem as a **file**, `rootfs.bin` (EROFS
  data), plus its dm-verity hash tree as `root-a-hash.bin`, sitting next to the
  UKI on the ESP. The verity **root hash is baked into the signed UKI cmdline**
  (RFC-0011 already does this), so the signed boot chain covers the root.

There are **no other partitions in the shipped image**. On first boot,
`systemd-repart` — the same substrate RFC-0011 already uses to carve swap and
`/var` — additionally **creates `root-a` (and `root-a-hash`) and copies the
image blocks onto them** via `CopyBlocks=`, then grows `/var` into the rest of
the disk. The result is a tiny immutable shipped artifact, one provisioning
pass that both installs the root and carves the substrate, and an ESP that
doubles as a known-good recovery/re-pave medium.

```text
Shipped image (single partition, ≈514 MiB total)
┌─────────────────────────────────────────────────────────────────┐
│ GPT  │ Partition 1 — ESP (FAT32, 512 MiB, PARTLABEL=ESP)  │ GPT │
│ pri  │   EFI/BOOT/BOOTX64.EFI         (UEFI fallback)     │ bak │
│      │   EFI/systemd/systemd-bootx64.efi (sd-boot)        │     │
│      │   EFI/Linux/aos-<name>-<ver>.efi  (install UKI)    │     │
│      │   rootfs.bin                   (EROFS root data)   │     │
│      │   root-a-hash.bin              (dm-verity tree)    │     │
│      │   loader/loader.conf                               │     │
└─────────────────────────────────────────────────────────────────┘
                         │  dd image to a larger disk, boot
                         ▼
On-disk layout after first boot (systemd-repart, AOS-baked drop-ins)
┌──────┬──────────┬──────────────┬──────────┬──────────────────────┐
│ ESP  │  root-a  │  root-a-hash │   swap   │         /var         │
│512MiB│ (EROFS,  │ (verity tree │  2 GiB   │   rest of disk       │
│(kept)│ CopyBlk) │  CopyBlk)    │(cryptswap│ (mutable state,      │
│      │          │              │ per boot)│  nix overlay upper)  │
└──────┴──────────┴──────────────┴──────────┴──────────────────────┘
  1         2            3            4              5
```

## Problem

Today (RFC-0011, "caveat #3") the image (`modules/image/_builder.nix`) ships
**two or three** partitions: a sized-to-fit ESP holding sd-boot + the UKI, a
`root-a` partition holding the EROFS root, and — under Secure Boot — a
`root-a-hash` partition holding the dm-verity tree. `systemd-repart` then carves
`swap` and `/var` out of the trailing free space
(`modules/services/repart.nix`).

That works, and it was the fast path to a working ignition-free boot. But the
root partition's **size and position are fixed at image build time**, and the
artifact is as large as the root image itself. The operator cannot:

- avoid shipping the root partition inside the image (it makes the artifact as
  large as the root, and forces the root slots to exist before first boot has
  run), or
- reshape the post-ESP layout (independent A/B root sizing, an XBOOTLDR
  partition ahead of the root slots) without rebuilding the image.

We want a single small immutable artifact — one 512 MiB ESP — that is identical
regardless of the intended runtime layout, and let the **first-boot substrate**
lay down `root-a`, its verity tree, swap, and `/var` in one pass. RFC-0011
already put that substrate in place for swap and `/var`; this RFC extends the
same `systemd-repart` mechanism to install the root image itself.

## Goals / non-goals

**Goals**

- A single, tiny, byte-reproducible shipped artifact: one 512 MiB ESP.
- The entire post-ESP layout — `root-a`, `root-a-hash`, swap, `/var` — is
  created on first boot by `systemd-repart` from AOS-baked `repart.d` drop-ins,
  in one pass; the image bakes in no root/var/swap partitions.
- The shipped ESP is a self-contained install **and** recovery medium: a
  known-good UKI + `rootfs.bin` (+ hash) that can re-pave `root-a` at any time.
- A/B-ready and XBOOTLDR-ready on-disk shape, so the future `apm` UKI/erofs
  update flow has somewhere to write.
- Reuse RFC-0011's first-boot machinery (`aos-repart.service` →
  `mount-var` → `aos-config-seed` → `etc-overlay-setup` → switch-root),
  adding root-install `CopyBlocks=` drop-ins to the existing repart pass.
- Extend the signed boot chain to the **root** via dm-verity with the root hash
  baked into the signed UKI cmdline (RFC-0011 F1, already shipped), and ship a
  **signed emergency/recovery profile** on the same UKI for recovery-key-gated
  console access (**new in this RFC**).

**Non-goals (deferred / out of scope here)**

- `apm` support for **updating** the install UKI or `rootfs.bin`, writing
  per-generation UKIs to XBOOTLDR, or A/B activation. Tracked as future work
  (§Future work). This RFC only delivers the single-ESP image builder, the
  root-install repart drop-ins, and the emergency profile.
- Operator-supplied per-instance disk topology. RFC-0011's substrate is
  **image-baked convention drop-ins**, evaluated in the initrd before `host.nix`
  runs in stage-2; custom topologies are the documented two-boot flow
  (RFC-0011 `provisioning.md` §7), not a first-boot operator config. This RFC
  keeps that model.
- New encryption mechanisms. Swap and `/var` encryption keep using the existing
  `cryptswap.service` and RFC-0006 measured-boot paths; repart only creates the
  raw partitions. (dm-verity is root *integrity*, not encryption, and **is** in
  scope — see §Security and §Emergency and recovery access.)

## The shipped image

A single GPT disk with one partition:

| # | Label | Type GUID | FS | Size | Contents |
|---|-------|-----------|----|------|----------|
| 1 | `ESP` | `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` | FAT32 | 512 MiB (build-time constant) | sd-boot, install UKI, `rootfs.bin`, `root-a-hash.bin`, `loader.conf` |

`loader.conf` keeps the existing `default aos-*.efi` glob (sd-boot picks the
lexically-highest `aos-*.efi`), `timeout 3`, `console-mode max`, `editor no`.
Under Secure Boot the two sd-boot copies are db-signed and the UKI is signed by
`aos-uki` (unchanged from today, RFC-0006).

The image is sized to `ESP + GPT overhead` (≈ 514 MiB) and `dd`-ed onto any
target disk of at least that size. The trailing free space is where
`systemd-repart` builds the rest of the layout.

**ESP sizing.** 512 MiB is a build-time constant (`espSizeMiB`, default 512).
It must hold the UKI (dominated by the bundled kernel + initrd — tens of MiB),
sd-boot (~150 KiB), `rootfs.bin` (~160 MiB for the current server closure,
`lib/build/rootfs.nix`), `root-a-hash.bin` (a SHA-256 verity tree ≈ 0.8 % of the
data, a few MiB), `loader.conf`, and FAT overhead — comfortably inside 512 MiB
today. The **authoritative** guarantee is not these estimates but the builder's
fit assertion (`_builder.nix` §2a in [implementation.md](implementation.md)): it
sums the *actual* ESP contents and fails the build with a clear message if
`rootfs.bin` + hash + UKI outgrow the ESP, prompting the operator to raise
`espSizeMiB`.

## The on-disk layout after first boot (repart-created)

`systemd-repart` creates the following from AOS-baked `repart.d` drop-ins, in
filename order, in the free space after the ESP. AOS never refers to these
partitions by number; every consumer keys off `/dev/disk/by-partlabel/<label>`.

| # | Label | Type GUID | FS | Created by | Owned by |
|---|-------|-----------|----|-----------|----------|
| 1 | `ESP` | ESP | FAT32 | image | firmware / sd-boot (immutable) |
| 2 | `root-a` | `0FC63DAF-…` (Linux data) | **EROFS (`CopyBlocks=`)** | repart `10-root-a.conf` | immutable root, generation A |
| 3 | `root-a-hash` | `2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5` (root-verity, x86-64) | **verity tree (`CopyBlocks=`)** | repart `20-root-a-hash.conf` | dm-verity Merkle tree for `root-a` |
| 4 | `swap` | `0657FD6D-…` | per-boot dm-crypt | repart `50-swap.conf` (existing) | encrypted swap |
| 5 | `var` | `4D21B016-…` (var, DPS) | ext4 / LUKS | repart `60-var.conf` (existing) | persistent mutable state, nix overlay upper |

The `root-a-hash` partition uses the **root-verity DPS type GUID**
(`2C7357ED-…`, the same GUID `_builder.nix` already assigns when it bakes the
hash partition today), which is deliberately **distinct** from the Linux-data
GUID of `root-a`. This distinctness is load-bearing for `systemd-repart`:
because repart matches config partitions to existing ones by type GUID, a
same-typed slot would match `root-a` instead of being created — the same reason
RFC-0011 does **not** yet carve a reserved `root-b` (`repart.nix` note).

Partition **numbers are illustrative**: the baked UKI cmdline uses
`root=/dev/disk/by-partlabel/root-a` (repointed to `/dev/mapper/root` under
verity by `aos-uki`), and every unit keys off `/dev/disk/by-partlabel/<label>`.

## First boot

The boot chain is RFC-0011's systemd-driven stage-1
(`modules/services/repart.nix` + `modules/base/boot-substrate.nix`), with the
**root-install `CopyBlocks=` drop-ins added to the existing repart pass** and
`aos-repart.service` extended to mount the ESP as the copy source. UEFI loads
sd-boot → the install UKI → the kernel + initrd unpack, and PID 1 (systemd)
runs:

1. **`aos-repart.service`** — the single provisioning pass
   (`modules/services/repart.nix`), ordered before `mount-var.service` and
   `sysroot.mount`. Extended for this RFC to:
   - mount the ESP (`/dev/disk/by-partlabel/ESP`) read-only at a fixed scratch
     path (`/run/aos-esp`) so the `CopyBlocks=` sources resolve;
   - run `systemd-repart` over the baked `repart.d` directory, which now
     contains `10-root-a.conf` (`CopyBlocks=/run/aos-esp/rootfs.bin`),
     `20-root-a-hash.conf` (`CopyBlocks=/run/aos-esp/root-a-hash.bin`), and the
     existing `50-swap.conf` / `60-var.conf`. repart creates `root-a` and
     `root-a-hash`, copies the image blocks verbatim onto them, creates swap,
     and grows `/var` into the tail — **all in one invocation**;
   - rewrite the GPT backup header to the true end of the device (repart does
     this natively — this is why RFC-0011 could delete `aos-gpt-relocate`);
   - `veritysetup open` `/dev/mapper/root` from the **signed** root hash and the
     copied hash tree (see §9c in [implementation.md](implementation.md));
   - `udevadm settle` + poll for the `var`/`root-a` symlinks (RFC-0011's
     existing race guard).
2. **`sysroot.mount`** — synthesized by `systemd-fstab-generator` from the
   signed cmdline's `root=`; mounts the verity mapper (`/dev/mapper/root`, or
   the raw `root-a` EROFS on the unsigned dev image) read-only at `/sysroot`.
3. **`mount-var`**, **`nix-overlay-setup`**, **`aos-seed-profiles`** (writes
   gen-1 `state.json`, reading `/sysroot/aos-toplevel` from the just-installed
   EROFS), **`aos-machine-id`** — _(unchanged; they operate on `/sysroot`,
   which is now backed by the CopyBlock'd image exactly as it was backed by the
   baked `root-a` before)_.
4. **`aos-config-seed`** (per-gen lower under `/run/etc/…`),
   **`etc-overlay-setup`** (three-layer composefs `/etc`) — _(unchanged;
   RFC-0011)_.
5. **`initrd-switch-root`** → pivot to stage-2.

The only conceptual change to RFC-0011's chain is that the **root and its verity
tree are now `CopyBlocks=` targets on first boot** instead of partitions baked
into the shipped image. `systemd-repart`'s `CopyBlocks=` is purpose-built for
this "populate a golden partition from an image" step — it replaces the custom
`dd` service the Ignition-era draft of this RFC proposed.

### Idempotency (subsequent boots)

`systemd-repart` is **idempotent by construction**: it computes the delta
between the declared drop-ins and the observed partition table and only *adds*
missing partitions and *grows* growable ones. On the second boot `root-a`,
`root-a-hash`, `swap`, and `var` all already exist (matched by type GUID +
label), so repart makes no change and copies nothing. This is the same
idempotency RFC-0011 relies on for swap/var; it now also covers the root
install, with **no** hand-rolled UUID/`fsck` gate.

| Partition | First boot | Subsequent boot |
|-----------|-----------|-----------------|
| `root-a` | created + `CopyBlocks=rootfs.bin` | exists (label+type match) → untouched |
| `root-a-hash` | created + `CopyBlocks=root-a-hash.bin` | exists → untouched |
| `swap` | created (raw; `cryptswap` mkswaps per boot) | exists → untouched |
| `var` | created + grown to fill | exists → grown only if the disk grew |

**Power-fail caveat.** Because repart matches on the partition *entry* (type +
label), a crash **mid-`CopyBlocks`** leaves a `root-a` that repart considers
"present" and will **not** re-copy on the next boot. Under Secure Boot this is
harmless: the half-written EROFS fails dm-verity (`EIO` on a bad block, no
`/dev/mapper/root`), so the boot fails **closed** and the operator re-paves from
the ESP (§Recovery / re-pave). On the **unsigned** dev image there is no verity
backstop, so a partial copy could present a mountable-but-corrupt root; the
implementation adds an optional verify-and-`repart --factory-reset`-scoped gate
for that path only (implementation.md §3b). This is the one property the
Ignition-era `fsck.erofs` re-`dd` gate gave for free that pure repart does not —
called out honestly rather than hidden.

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
  partition as `aos-<version>+<N>.efi`, where the `+N-M` suffix drives automatic
  boot assessment. The install UKI in the ESP remains the permanent recovery
  entry. XBOOTLDR is created by a future repart drop-in when `apm` learns to
  write it.
- **Per-machine entropy:** a golden image clones identical ESP contents to every
  machine. The load-bearing invariant today is that the shipped ESP carries
  **no** `loader/random-seed` file — the builder writes only `loader.conf`
  (`modules/image/_builder.nix`) and `systemd-boot-random-seed.service` is masked
  (`modules/base/boot.nix`), so sd-boot's seed read is a silent no-op and no seed
  material is shared across clones. Minting a fresh `LoaderSystemToken` per
  machine (`bootctl random-seed`) is deferred defense-in-depth (it needs a
  transient ESP remount, since the ESP is read-only); wired with the apm work. A
  regression test asserting the shipped ESP contains no `loader/random-seed`
  should land alongside the future apm ESP-write flow.

## Encryption

Per the scope decision, `systemd-repart` creates only **raw** swap/var
partitions; encryption stays with AOS's existing services:

- **Swap** — `cryptswap.service` (`modules/base/filesystems.nix`) opens the
  `swap` partition as a plain dm-crypt device keyed from `/dev/urandom` and runs
  `mkswap` every boot, so swap contents are unrecoverable across reboots. The
  `50-swap.conf` drop-in therefore leaves swap unformatted.
- **`/var`** — under RFC-0006 measured boot, `aos-var-crypt` unseals a
  TPM-bound LUKS volume and exposes `/dev/mapper/var`, which `mount-var` prefers
  over the raw partition. RFC-0011's `60-var.conf` **omits `Format=` under
  measured boot** precisely so `aos-var-crypt` owns the LUKS seal; without
  measured boot repart formats `var` ext4 convergently.

## Recovery / re-pave

Because the ESP permanently carries a known-good UKI **and** `rootfs.bin` (+
hash), the shipped medium is also a recovery medium: clearing `root-a` (e.g.
wiping its partition entry) and rebooting makes `systemd-repart` re-create and
re-`CopyBlocks` it — restoring the root image without a network or a rebuild.
The ESP is never written at runtime in this RFC (only firmware reads it and
stage-1 mounts it read-only), so it stays trustworthy as long as the medium is
intact.

## Emergency and recovery access

The install UKI on the ESP doubles as the emergency/recovery entry. Because the
ESP is read-only, the root is immutable (dm-verity), and `/var` is TPM-sealed,
console access is structured so that it can neither persist a change nor expose
sealed state without the off-machine LUKS **recovery key** — the recovery key,
not a baked root password, is the authorization factor.

### A signed emergency profile, not a runtime karg

Secure Boot makes the obvious lever mostly a no-op: when the UKI carries a baked
`.cmdline`, sd-stub drops the **menu/LoadOptions** command line and uses the
signed one (systemd v259.1 `src/boot/stub.c:1184-1200`), and `editor no`
(`modules/image/_builder.nix`) blocks editing at the menu. So
`rd.systemd.unit=emergency.target` / `systemd.debug_shell` / `systemd.setenv=…`
*typed at the menu* never reach PID 1. (One gap remains: sd-stub still
**appends** unsigned SMBIOS/addon cmdline *after* the signed section —
`stub.c:1273-1274`, measured into PCR 12 (SMBIOS strings also into firmware
PCR 1) — so a hostile hypervisor can inject kargs even under Secure Boot. That
vector is closed separately by the PCR-12 pin and the locked root account,
§"The root account"; it is *not* closed by the cmdline-drop alone.) The
emergency entry is therefore a second **signed** boot path:

- **Multi-profile UKI (preferred).** The install UKI carries a second `.profile`
  whose baked, signed `.cmdline` boots a dedicated `aos-recovery.target`
  (autologin — not `emergency.target`; see below). The `@N` profile selector is
  parsed out before the command line is dropped (`src/boot/stub.c:188`,
  `:1232-1245`) and selects the profile's signed section set
  (`stub.c:1148-1158`); sd-boot renders one menu entry per profile
  (`src/boot/boot.c:2177-2263`). One signed PE, no ESP write, compatible with
  `editor no`.
- **Second signed UKI (alternative).** A separate
  `EFI/Linux/aos-<ver>-rescue.efi` with the emergency cmdline baked and signed —
  simpler, but costs a second UKI against the `espSizeMiB` budget.

The @1 recovery shell runs in the **initrd**, via a dedicated
`rd.systemd.unit=aos-recovery.target` whose signed `.cmdline` boots an autologin
recovery shell — **not** `emergency.target`, whose `sulogin` would refuse under
the mandated locked root (§"The root account"). `aos-var-crypt` is itself an
initrd service wanted by `initrd-fs.target` (`modules/base/secure-boot.nix`);
`aos-recovery.target` runs `DefaultDependencies=no` and does not pull in
`initrd-fs.target`, so `initrd-fs.target`'s wants — `aos-var-crypt` among them —
are never started, and the recovery path never auto-unseals `/var`. Even a
*manual* unseal attempt fails on the dedicated **@1** emergency profile: it
measures a PCR-11 the signed `.pcrsig` does not bless (precondition 2 below;
mechanism in implementation.md §10b), so the TPM policy rejects it. This holds
for the **@1** profile only — a *normal* **@0** boot that merely *falls* into
`emergency.target` carries the **blessed** PCR-11 and *can* unseal `/var`; that
path is fenced off by the locked root account and the PCR-12 pin (§"The root
account", precondition 3 below), not by this isolation.

### Why a password-less shell is sound

This RFC delivers the three properties a password-less emergency shell depends
on. (Outside Secure Boot — the unsigned dev image — the emergency profile is
password-protected via `sulogin`, since none of them carries a guarantee
without the signature.)

1. **dm-verity on the root, root hash in the signed cmdline.** The signed
   cmdline pins the root *device* (the base `root=/dev/disk/by-partlabel/root-a`
   at `modules/base/boot.nix:206` is repointed to `/dev/mapper/root` by
   `modules/security/verity.nix` / `aos-uki` when verity is active) and its
   *content*: the root hash is baked into the signed UKI cmdline
   (`pkgs/boot/aos-uki.nix` `rootHashFile` — **already shipped, RFC-0011 F1**),
   so a root shell that overwrites `root-a` with a tampered EROFS fails verity
   (the mapper opens but reads return `EIO`) and the system fails closed instead
   of running the backdoor with Secure Boot intact. The root hash must be
   anchored to the *signed* `.cmdline`, not a greedy `/proc/cmdline` scan —
   sd-stub appends unsigned SMBIOS/addon cmdline afterwards, so stage-1 rejects a
   duplicate `roothash=` (implementation.md §9c). The kernel pieces are builtin
   (`CONFIG_DM_VERITY=y`, `pkgs/kernel/config/storage.config`); the data + hash
   ship as ESP files and are `CopyBlocks`'d onto `root-a` / `root-a-hash` on
   first boot (implementation.md §9).
2. **The @1 emergency *profile* breaks the `/var` TPM auto-unseal.** The seal is
   signature-flexible on PCR 11 (the UKI/cmdline measurement) and pinned by
   value on PCR 7 (`modules/base/secure-boot.nix:438-439`;
   [measured-boot.md](../0006-secure-boot/measured-boot.md)). The @1 profile is
   built so its PCR-11 prediction is **excluded** from the signed `.pcrsig` set,
   so reaching *that* shell forces the recovery-key path; a CI assertion proves
   it cannot auto-unseal `/var` (implementation.md §10). This covers the @1
   profile **only** — not a normal @0 boot that falls into `emergency.target`
   (precondition 3).
3. **A locked root account, and PCR 12 pinned into the seal, fence off the @0
   path.** Because a *normal* @0 boot carries the blessed PCR-11, the @1
   exclusion does not protect it; two further controls do. (a) **Locked root:**
   the root account is locked (`!`/`*`), so `sulogin` on an @0 drop into
   `emergency.target` refuses a shell (the initrd root must change from empty to
   locked; stage-2 is already locked — implementation.md §10c). (b) **PCR-12
   pin:** the seal also pins PCR 12, which measures the appended (override/SMBIOS)
   cmdline, so an injected `SYSTEMD_SULOGIN_FORCE=1` / `roothash=` /
   `rd.systemd.unit=` changes the measurement and the TPM refuses `/var`
   (implementation.md §10d). The security boundary is thus the **PCR binding**,
   not the shell mechanism — see §"The root account".

### The root account: locked, conditional on the boot posture

The password-less @1 recovery shell is sound only when no *other* path on the
blessed @0 profile offers an unauthenticated root with `/var` access. That
reduces to a single requirement: **under Secure Boot, the root account is
locked** (no valid password hash, not an empty one) in **both** stages.

- The **initrd** root is currently *empty* (`_initrd-builder.nix:519` =
  `root:::0:99999:7:::`), which today already yields a passwordless `sulogin` on
  any emergency drop. Under Secure Boot it must become *locked*
  (`root:!*::…`); on the unsigned dev image it instead carries a password hash
  (the non-SB `sulogin`-protected posture), since one static shadow line cannot
  be both — so the line is gated on `aos.boot.secureBoot.enable`
  (implementation.md §10c).
- The **stage-2** root is **already** locked by default (`users.nix` emits
  `root:!*::…`).
- The @1 recovery shell is granted by @1's *signed* cmdline (a baked
  `agetty --autologin` recovery target), **not** by `SYSTEMD_SULOGIN_FORCE` —
  that knob is readable straight from the cmdline, so the SMBIOS append could
  force it on @0. The robust @0/@1 boundary is the PCR binding (preconditions 2 +
  3), never a cmdline token, because @0's cmdline is appendable.

This is a **conditional** guarantee, not a blanket mandate. It applies only when
`aos.profiles.debug.autologin` (and the debug security level) is off. A
deployment may legitimately choose root autologin — that is what
`systems/server.nix` does today — which force-unlocks root, adds autologin
gettys, and masks the initrd `sulogin` recovery units
(`modules/profiles/debug.nix`). That is an informed opt-out of the sealed-`/var`
guarantee, exactly parallel to running outside Secure Boot, and is appropriate
for VM testing and trusted-network use (the option is already documented "NEVER
enable this on a system exposed to an untrusted network").

### Authorization model

With all three preconditions met, the recovery key is the only thing that
changes persistent state or exposes `/var`:

- **Reinstall** re-`CopyBlocks` `rootfs.bin` from the ESP onto `root-a`
  (§Recovery / re-pave); under verity an arbitrary substitute fails to boot, so
  this needs no password.
- **Unsealing `/var`** uses the LUKS recovery slot `aos-var-crypt` enrolls and
  never wipes (`modules/base/secure-boot.nix`); only an operator holding the
  escrowed recovery passphrase can open it.

Lockdown (engaged via `modules/base/secure-boot.nix`, with unsigned-kexec denial
enforced by `CONFIG_KEXEC_SIG_FORCE`, when enabled) already denies a console
root the usual escalation paths (unsigned modules, unsigned kexec, `/dev/mem`);
verity and the sealed `/var` deny persistence and exfiltration. Once the root
account is locked and PCR 12 is pinned (§"The root account"), the residual power
of console root is then **destructive only** (e.g. erasing the LUKS header or
corrupting `root-a`, forcing a re-pave) — acceptable where physical access
already implies denial of service. **Without** those two controls a console root
reached on the blessed @0 profile can unseal `/var`, so they are load-bearing,
not optional; deployments that also want a credentialed shell keep a root
password.

## Security considerations

- **The signed boot chain covers the root.** Under Secure Boot the install UKI
  (kernel + initrd + cmdline) is Authenticode-signed and measured, and the root
  hash is baked into the signed UKI cmdline (`pkgs/boot/aos-uki.nix`
  `rootHashFile`, already shipped), so a tampered `rootfs.bin` or `root-a` fails
  verity and the system fails closed instead of running a backdoor with Secure
  Boot intact. The anchor is the **signed `.cmdline` section**, not
  `/proc/cmdline` (sd-stub appends unsigned SMBIOS/addon cmdline afterwards), so
  stage-1 rejects a duplicate `roothash=` to defeat injection (implementation.md
  §9c). Outside Secure Boot the mechanism still runs, but the unsigned cmdline
  carries no guarantee — security comes from the signature, as everywhere in AOS.
- **ESP immutability.** The ESP is read-only at runtime (firmware reads it;
  stage-1 mounts it `ro`; `systemd-boot-update.service` and
  `systemd-boot-random-seed.service` are masked). The only planned writer is the
  future `apm` UKI-update flow, which must remount transiently and re-establish
  the signature posture.
- **`CopyBlocks` is not atomic, and the install path is fail-closed under
  verity.** A crash mid-copy leaves a partial EROFS on `root-a`; because repart
  will not re-copy an existing partition entry, the next boot fails verity
  (`EIO`, no mapper → `sysroot.mount` fails → emergency) rather than mounting a
  bad root. On the unsigned dev image (raw `root-a`, no verity) an optional
  verify gate (implementation.md §3b) re-scopes repart to re-copy a corrupt root.
  `root-a` is never live during install, so there is no torn-read window for a
  running system.
- **Cmdline pinning.** Two distinct protections, often conflated: (1) at
  *runtime*, the UKI's baked `.cmdline` is signed and, under Secure Boot, a
  **menu/LoadOptions** command line is dropped by sd-stub
  (`src/boot/stub.c:1184-1200`), with `editor no` as a second layer; (2) at
  *build time*, an assertion (`modules/base/boot.nix:160-172`) rejects
  `ignition.config.url=` in `aos.boot.kernelParams` (retained from the Ignition
  era as a defense-in-depth guard). Residual gap: sd-stub still **appends**
  unsigned SMBIOS/addon cmdline after the signed section (`stub.c:1273-1274`,
  measured into PCR 12) — defeated not by the drop but by the verity
  duplicate-`roothash` guard (§9c) and the PCR-12 pin (§10d).
- **Emergency / recovery access.** The install UKI doubles as the recovery entry
  via the signed **@1** emergency profile, never a runtime karg. The off-machine
  LUKS recovery key — not a baked root password — authorizes any change to
  persistent state. A password-less shell is sound only once (1) the root is
  dm-verity-protected, (2) the @1 profile's PCR-11 is excluded from the seal, and
  (3) the root account is locked and PCR 12 is pinned. See §Emergency and
  recovery access (preconditions 1–3) and §"The root account".

## Alternatives considered

- **Keep the root as a baked image partition (RFC-0011 caveat #3, the current
  status quo).** Simple, no `CopyBlocks` step, and it was the fast path to an
  ignition-free boot. But the artifact carries the root, the root slots must
  exist before first boot, and the post-ESP layout is fixed at build time.
  Rejected as the *end state*: it does not meet the tiny-immutable-artifact goal.
  (This RFC is precisely the migration off it.)
- **Keep Ignition for first-boot partitioning.** The original draft of this RFC
  had the operator's Ignition config carve the disk and a custom
  `aos-install-root.service` `dd` the root. **Rejected / obsolete:** RFC-0011
  removed Ignition entirely in favor of the systemd-repart substrate. The
  root-install step folds into that substrate as a `CopyBlocks=` drop-in — one
  provisioning surface, not two.
- **Recompute the verity tree at first boot (`systemd-repart` `Verity=data` /
  `Verity=hash`).** `systemd-repart` can build a verity pair and compute a root
  hash itself. **Rejected:** the root hash is baked into the *signed UKI cmdline
  at build time*, so first boot must reproduce the exact build-time bytes and
  hash. The tree is therefore shipped precomputed and `CopyBlocks`'d verbatim,
  not recomputed.
- **Resize the ESP in place at first boot (`fatresize`).** Rejected in prior
  research: deprecated libparted FS-resize, a hard 256 MB FAT floor, non-atomic
  resize, no test suite. Moot here — the ESP is a fixed 512 MiB and never
  resized.
- **A baked default operator layout.** Would let the image self-install on bare
  metal with zero config, but RFC-0011's substrate is convention-based and
  image-baked by design; custom topology is the documented two-boot flow. No
  merge-semantics surprises.

## Open questions / future work

- **`apm` UKI + `rootfs.bin` updates.** The point of XBOOTLDR + a future
  `root-b` is the update flow: `apm` writes a new UKI (with `+tries`) to XBOOTLDR
  and a new `rootfs.bin`/hash to `root-b`, then flips A/B. `root-b` needs a
  **distinct** root-verity/DPS type from `root-a` so `systemd-repart` creates it
  rather than matching `root-a` (`modules/services/repart.nix` note). Today
  `apm`'s sysroot path writes a single static `/boot/loader/entries/aos.conf`
  and is not XBOOTLDR/UKI-glob aware (`crates/aos-package/src/sysroot.rs`) —
  reconciling that with the image's UKI-glob model is the first task of the
  follow-up.
- **`/boot` vs `/efi` split.** The systemd convention is XBOOTLDR at `/boot` and
  the ESP at `/efi`. This RFC keeps the ESP at `/boot` (where the only UKI
  lives); the split lands with the apm work, once something writes XBOOTLDR.
- **Power-fail re-copy on the unsigned path.** The optional verify gate
  (implementation.md §3b) covers the dev image; a cleaner mechanism would be a
  repart completion marker so a partial `CopyBlocks` is retried automatically on
  every posture. Deferred.
- **Roothash signature in the kernel keyring**
  (`CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`) as a second anchor beyond the signed
  cmdline. Out of scope here; the signed cmdline is the primary anchor.
- **Per-machine `LoaderSystemToken`** minting at first boot (see §Bootloader).
- **Root-image size vs ESP size.** If a future closure grows `rootfs.bin` past
  the 512 MiB ESP budget, `espSizeMiB` must rise (or the root image must be
  split). The builder asserts the fit; revisit the constant when it trips.

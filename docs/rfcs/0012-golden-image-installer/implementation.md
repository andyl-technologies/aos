# RFC-0012 implementation plan — image builder + stage-1 changes

This is the change plan for [RFC-0012](README.md). **Scope:** the image builder
and the stage-1 (initrd) services only — now including **dm-verity root
integrity** (the root hash baked into the signed UKI cmdline) and a **signed
emergency/recovery profile** on the install UKI. `apm` support for updating the
install UKI / `rootfs.bin`, writing per-generation UKIs to XBOOTLDR, and A/B
activation is **future work** and is not touched here.

The end state: the image is a single 512 MiB ESP carrying sd-boot + the install
UKI (normal + emergency profiles) + `rootfs.bin` (EROFS data + an appended
dm-verity hash tree). First boot runs the operator's Ignition layout,
`aos-install-root.service` `dd`s `rootfs.bin` onto `root-a` and assembles the
dm-verity device the signed cmdline's root hash anchors, then `sysroot.mount`
mounts the verified root. Under Secure Boot a tampered root fails closed, and the
UKI's emergency profile gives recovery-key-gated console access (RFC §Emergency
and recovery access).

## Component overview

| # | File | Change |
|---|------|--------|
| 1 | `lib/build/rootfs.nix` | **emit dm-verity**: append a verity hash tree to `root.img`, write the root hash + final size (change #9a) |
| 1b | `pkgs/boot/aos-uki.nix` | **bake** the signed verity root hash into the `.cmdline` (change #9b); **build** the emergency/recovery profile — a second `.profile`/`.cmdline`, PCR-11 excluded from `.pcrsig` (change #10) |
| 2 | `modules/image/_builder.nix` | **single-ESP image**: place `rootfs.bin` (with appended verity tree) in the ESP, fixed `espSizeMiB` (512) with a fit assertion, drop the `root-a` partition, rewrite `image-info.json`; pass `verityRootHashFile` to `aos-uki` under Secure Boot |
| 3 | `modules/services/ignition.nix` | **new** `aos-install-root.service` (dd **+ `veritysetup open`** from the signed root hash, change #9c); **drop-in** `Requires=aos-install-root` on `sysroot.mount` (fail-closed, §3a); **rework** `aos-gpt-relocate` to resolve the disk from the ESP partlabel |
| 4 | `modules/base/boot.nix` | **none required** — `vfat` is builtin (`CONFIG_VFAT_FS=y`); the manifest entry is optional documentation |
| 5 | `modules/base/_initrd-builder.nix` | add `erofs-utils` to the initrd closure (for `fsck.erofs`); `cryptsetup`/`veritysetup` is already present for the verity open + `/var` recovery slot |
| 6 | `modules/base/filesystems.nix` | make `rootDevice`/`espDevice` partlabel-based and point root at `/dev/mapper/root` when verity is active; keep `/boot` = ESP (note the future `/efi` split) |
| 7 | `tests/fleet/install-from-image.nix` | new Ignition config (XBOOTLDR + unformatted `root-a` + `root-b` + `swap` + `var`); assert the verity-mapped EROFS root and (under SB) that the emergency profile does not auto-unseal `/var` |
| 8 | `docs/boot/qemu-uefi.md` | update the example Ignition config to the new contract |

---

## 1. `lib/build/rootfs.nix` — EROFS unchanged, verity tree appended

The EROFS path already produces `$out/root.img` (the image that becomes
`rootfs.bin`) and `$out/rootfs-size-bytes`, with a fixed UUID
(`bdfb6fc9-0000-4000-8000-000000000001`) and the `/aos-toplevel` seed pointer
baked in. The EROFS payload itself is consumed the same way after it is `dd`'d to
`root-a` and mounted at `/sysroot`. **New:** a dm-verity hash tree is appended to
`root.img` and the root hash is emitted as `$out/root-hash` (change #9a); this is
what extends the signed boot chain to the root.

`rootfs-size-bytes` (now including the appended tree) is the **minimum `root-a`
size** the operator's Ignition config must declare; surface it in
`image-info.json` (change #2) and in `docs/boot/qemu-uefi.md` (change #8).
rootfs.nix also emits the EROFS-data size (`$out/rootfs-data-bytes`, the verity
hash-offset), which `aos-uki` bakes into the signed cmdline (change #9b) so stage-1
can `veritysetup open` from a signed source (change #9c).

---

## 2. `modules/image/_builder.nix` — single-ESP image

This is the load-bearing change. Today the builder writes an ESP **and** a
`root-a` partition (the EROFS). After this change it writes **only the ESP**,
with `rootfs.bin` as a file inside it.

### 2a. ESP size constant + parameter

Replace the "size to contents ×2" logic with a fixed `espSizeMiB` (default
512), and assert the contents fit:

```nix
# Fixed ESP size (MiB). The ESP must hold sd-boot, the install UKI, and the
# full EROFS rootfs.bin; 512 MiB fits the current server closure (~160 MiB
# rootfs.bin per lib/build/rootfs.nix:297, plus the UKI) with comfortable
# headroom. Raise this if the build-time fit assertion (below) trips.
espSizeMiB ? 512,
```

(thread it through `mkImage`/`_builder.nix`'s argument set the same way `name`
is.)

In the build script, drop the `esp_mib=$(( … *2 … ))` computation and instead:

```sh
# ── 3. Create vfat ESP image (fixed size, contents asserted to fit) ──
esp_content_kib=$(du -sk esp | cut -f1)
esp_mib=${toString espSizeMiB}
# Reserve ~32 MiB for FAT structures + slack; fail loudly if rootfs.bin + UKI
# outgrow the ESP rather than producing an image that overflows at mcopy time.
if [ $(( esp_content_kib + 32768 )) -gt $(( esp_mib * 1024 )) ]; then
  echo "ERROR: ESP contents ($(( esp_content_kib / 1024 )) MiB) + overhead" \
       "exceed espSizeMiB ($esp_mib MiB). Raise aos image espSizeMiB." >&2
  exit 1
fi
esp_bytes=$(( esp_mib * 1048576 ))
esp_sectors=$(( esp_bytes / 512 ))
```

### 2b. Put `rootfs.bin` in the ESP, not in a partition

In the "Populating ESP tree" step, after copying the UKI, add the root image:

```sh
# The EROFS root ships as a file on the ESP. aos-install-root.service dd's
# it onto the operator-created root-a partition on first boot (Ignition has
# no EROFS mkfs and cannot dd a raw image). rootfs.bin is the largest object
# on the ESP — this is what drives the espSizeMiB budget.
cp "$ROOT_IMG" esp/rootfs.bin
```

`$ROOT_IMG` is already wired (`ROOT_IMG = "${rootfs}/root.img";`). The existing
`mcopy -s` loop over `esp/*` picks `rootfs.bin` up unchanged.

Remove the now-unused top-level `cp "$ROOT_IMG" root.img` + `chmod u+w root.img`
(`_builder.nix:144-145`) and the root `dd` in step 4 (`:231`). **Keep** the
`root_bytes=$(cat "$ROOT_SIZE_FILE")` read (`:146`): it is still the `rootfs.bin`
size that the size record (§2c) and `image-info.json` (§2d) report as the `root-a`
minimum.

### 2c. Single-partition GPT table

Replace the two-line `sfdisk` table and the second `dd` with an ESP-only table:

```sh
# ── 4. Assemble final GPT image (ESP only) ──────────────────────────
# 1 MiB (2048 sectors) at the front for GPT header + alignment, 1 MiB at
# the end for the backup header. Everything after the ESP is unallocated
# free space that Ignition partitions on first boot per the operator's
# config (XBOOTLDR, root-a, root-b, swap, var). aos-gpt-relocate moves the
# backup header to the true end of the device when the image lands on a
# larger disk.
disk_sectors=$(( ${toString espStartSector} + esp_sectors + 2048 ))
disk_bytes=$(( disk_sectors * 512 ))
truncate -s "$disk_bytes" image.raw

sfdisk image.raw <<PTABLE
label: gpt
size=$esp_sectors, type=${espGuid}, name="ESP"
PTABLE

dd if=esp.img of=image.raw bs=512 seek=${toString espStartSector} \
   conv=notrunc status=none

# Hand-off files the metadata step (§2d) reads back. The current builder writes
# these at _builder.nix:233-234 and reads them at :245/:249 — keep them, or
# image-info.json's `cat root-size-bytes` / `cat esp-size-mib` break the build.
echo "$root_bytes" > root-size-bytes   # rootfs.bin size = root-a minimum
echo "$esp_mib"    > esp-size-mib
```

`linuxGuid` is no longer used by the builder (the operator's config assigns
type GUIDs to the partitions it creates); drop it.

### 2d. `image-info.json`

Rewrite the metadata to describe the single-partition artifact, surface the
`rootfs.bin` size as the `root-a` minimum, and document the expected first-boot
contract for downstream tooling:

```nix
cat > $out/image-info.json <<META
{
  "name": "${name}",
  "version": "${version}",
  "diskSizeMiB": $disk_size_mib,
  "espSizeMiB": $esp_size_mib,
  "rootfsBinBytes": $root_size_bytes,
  "rootfsBinUuid": "bdfb6fc9-0000-4000-8000-000000000001",
  "format": "raw",
  "partitionTable": "gpt",
  "partitions": [
    { "number": 1, "label": "ESP", "type": "esp", "filesystem": "vfat", "sizeMiB": $esp_size_mib }
  ],
  "esp": {
    "uki": "EFI/Linux/${ukiFilename}",
    "sdBoot": "EFI/systemd/systemd-bootx64.efi",
    "rootfsBin": "rootfs.bin"
  },
  "firstBoot": {
    "rootInstall": "aos-install-root.service dd's esp/rootfs.bin -> /dev/disk/by-partlabel/root-a",
    "requiredPartlabels": ["root-a", "var"],
    "rootAMinBytes": $root_size_bytes
  }
}
META
```

Update the header comment block (lines 1–22) to describe the new single-ESP
layout and the dd-on-first-boot model.

> The `imageDrv // {inherit uki;}` passthru (used by RFC-0006 phase 4
> `apr publish --image`) is unchanged.

---

## 3. `modules/services/ignition.nix` — install service + gpt-relocate rework

### 3a. New `aos-install-root.service`

Insert between `ignition-disks` and `sysroot.mount`. It mounts the ESP
read-only, `dd`s `rootfs.bin` onto `root-a`, verifies, and is idempotent +
power-fail-safe.

```nix
# Install the EROFS root image onto root-a on first boot. The image ships
# as a file (rootfs.bin) on the ESP because Ignition's disks stage can
# neither mkfs EROFS nor dd a raw blob — so AOS owns the root install as a
# custom oneshot, the same pattern as aos-gpt-relocate / aos-growfs /
# cryptswap. Runs after Ignition has created root-a (unformatted, per the
# operator's config) and before sysroot.mount consumes it.
"aos-install-root" = {
  description = "Install root filesystem image to root-a on first boot";
  wantedBy = ["initrd-root-fs.target"];
  before = [
    "sysroot.mount"
    "aos-growfs.service"
    "initrd-root-fs.target"
  ];
  requires = [
    "ignition-disks.service"
    "dev-disk-by\\x2dpartlabel-root\\x2da.device"
    "dev-disk-by\\x2dpartlabel-ESP.device"
  ];
  after = [
    "ignition-disks.service"
    "dev-disk-by\\x2dpartlabel-root\\x2da.device"
    "dev-disk-by\\x2dpartlabel-ESP.device"
    "systemd-udev-settle.service"
  ];
  unitConfig = {
    DefaultDependencies = "no";
    # Both endpoints must exist: the ESP we boot from (source of
    # rootfs.bin) and the operator-created root-a (the target). On a
    # kernel-boot VM test with no ESP/rootfs.bin this is a no-op.
    ConditionPathExists = [
      "/dev/disk/by-partlabel/ESP"
      "/dev/disk/by-partlabel/root-a"
    ];
  };
  environment.PATH = ignitionPath; # adds erofs-utils below (fsck.erofs)
  serviceConfig = {
    Type = "oneshot";
    RemainAfterExit = true;
    StandardOutput = "journal+console";
    StandardError = "journal+console";
  };
  script = ''
    set -euo pipefail
    esp=/dev/disk/by-partlabel/ESP
    root=/dev/disk/by-partlabel/root-a
    mnt=/run/aos-esp

    mkdir -p "$mnt"
    mount -t vfat -o ro,nodev,nosuid "$esp" "$mnt"
    trap 'umount "$mnt" 2>/dev/null || true' EXIT

    if [ ! -f "$mnt/rootfs.bin" ]; then
      echo "aos-install-root: no rootfs.bin on ESP; nothing to install"
      exit 0
    fi

    # Self-describing, power-fail-safe gate: skip only if root-a already
    # holds a COMPLETE EROFS whose UUID matches the shipped image. A
    # partial dd (power lost mid-install) fails fsck.erofs and is re-dd'd;
    # root-a is never live during install, so a re-dd is always safe.
    want_uuid=$(blkid -s UUID -o value "$mnt/rootfs.bin" || true)
    have_uuid=$(blkid -s UUID -o value "$root" 2>/dev/null || true)
    if [ -n "$want_uuid" ] && [ "$have_uuid" = "$want_uuid" ] \
       && fsck.erofs "$root" >/dev/null 2>&1; then
      echo "aos-install-root: root-a already holds rootfs.bin ($want_uuid); skipping"
      exit 0
    fi

    echo "aos-install-root: writing rootfs.bin -> $root"
    dd if="$mnt/rootfs.bin" of="$root" bs=4M conv=fsync status=progress
    sync
    fsck.erofs "$root" >/dev/null
    echo "aos-install-root: root-a installed and verified"
  '';
};
```

Notes:

- `mount -t vfat` uses the builtin VFAT (`CONFIG_VFAT_FS=y`); **no initrd
  module is needed** (see change #4). `fsck.erofs` requires `erofs-utils` in
  the initrd closure (change #5).
- `dd … conv=fsync` + an explicit `sync` flush the write before `fsck.erofs`
  reads it back.
- `ConditionPathExists` as a **list** ANDs the two conditions (both endpoints
  must exist); on a kernel-boot test disk (ext4 root, no ESP) the service is a
  clean no-op.
- **`sysroot.mount` gets a hard `Requires=aos-install-root.service`** (via a
  drop-in over the `systemd-fstab-generator` unit, the same `overrideStrategy =
  "asDropin"` pattern used elsewhere in this module). Ordering alone
  (`Before=sysroot.mount`) does not stop the mount if the install fails; the
  `Requires=` makes the boot **fail closed uniformly** — under Secure Boot the
  verity mapper is already the backstop (no `/dev/mapper/root` → no mount, §9c),
  but on the unsigned dev image (raw `root-a`, no verity) this is what prevents a
  partial-but-mountable EROFS from booting. Use `Requires=`, not `BindsTo=`: the
  `RemainAfterExit` oneshot stays active after success, and `BindsTo=` would risk
  tearing down a live root mount on any later inactive transition. The
  `ConditionPathExists`-skipped no-op (kernel-boot test) counts as success, so
  `Requires=` is satisfied and that test is unaffected.

### 3b. Rework `aos-gpt-relocate` to key off the ESP

Today this service requires/conditions on `/dev/disk/by-partlabel/root-a` and
resolves the boot disk from it. `root-a` no longer ships in the image, so it
must resolve the disk from the **ESP** (the only partition that exists
pre-provisioning). The "already provisioned → skip" gate on `var` is unchanged.

```nix
"aos-gpt-relocate" = {
  description = "Relocate GPT backup header to end of boot disk";
  wantedBy = ["initrd-root-fs.target"];
  before = [
    "ignition-disks.service"
    "initrd-root-fs.target"
  ];
  requires = ["dev-disk-by\\x2dpartlabel-ESP.device"];
  after = ["dev-disk-by\\x2dpartlabel-ESP.device"];
  unitConfig = {
    DefaultDependencies = "no";
    ConditionPathExists = "/dev/disk/by-partlabel/ESP";
  };
  environment.PATH = ignitionPath;
  serviceConfig = {
    Type = "oneshot";
    RemainAfterExit = true;
    StandardOutput = "journal+console";
    StandardError = "journal+console";
  };
  script = ''
    set -euo pipefail

    # var is created by Ignition, never by the image. Its presence means
    # the disk is already provisioned and the GPT spans the full device.
    if [ -e /dev/disk/by-partlabel/var ]; then
      echo "aos-gpt-relocate: disk already provisioned (var present); skipping"
      exit 0
    fi

    part=$(readlink -f /dev/disk/by-partlabel/ESP)
    disk=$(lsblk -ndo PKNAME "$part" 2>/dev/null || true)
    if [ -z "$disk" ]; then
      echo "aos-gpt-relocate: cannot resolve parent disk of $part; skipping" >&2
      exit 0
    fi
    disk="/dev/$disk"

    echo "aos-gpt-relocate: relocating GPT backup header to end of $disk"
    sgdisk -e "$disk"
    sgdisk -v "$disk" || true
  '';
};
```

### 3c. `aos-growfs` ordering (minor)

`aos-growfs` is already a no-op for an EROFS root and conditions on `root-a`.
Leave it; just confirm it stays ordered `After=ignition-disks` and now also
`After=aos-install-root` (it runs before `sysroot.mount`, after the root image
exists). Add `aos-install-root.service` to its `after` list for clarity:

```nix
after = [ "ignition-disks.service" "aos-install-root.service" ];
```

`mount-var`, `nix-overlay-setup`, `aos-seed-profiles`, `aos-machine-id`,
`ignition-mount`, `ignition-files`, `etc-overlay-setup` are **unchanged** —
they operate on `/sysroot`, which is now backed by the dd'd EROFS exactly as it
was backed by the baked `root-a` before.

### 3d. `ignitionTools` gains `erofs-utils`

Add `pkgs.erofs-utils` to the `ignitionTools` list so `fsck.erofs` is on the
stage-1 PATH (the closure is pulled into the initrd by change #5):

```nix
ignitionTools = [
  pkgs.kmod
  pkgs.util-linux
  pkgs.e2fsprogs
  pkgs.dosfstools
  pkgs.gptfdisk
  pkgs.cryptsetup
  pkgs.erofs-utils   # fsck.erofs for the aos-install-root gate
  pkgs.systemd
  pkgs.coreutils
  pkgs.bash
  pkgs.jq
];
```

---

## 4. `modules/base/boot.nix` — no change required (VFAT is builtin)

Stage-1 mounts the ESP (FAT32) to read `rootfs.bin`, but **no initrd module
work is needed**: VFAT and its FAT default codepage/charset are compiled into
the kernel, not built as modules.

Verified against `pkgs/kernel/config/storage.config`:

- `CONFIG_VFAT_FS=y` (line 66) — VFAT builtin.
- `CONFIG_FAT_DEFAULT_UTF8=y` (line 67) — default iocharset is utf8.
- The kernel is configured from `make defconfig` + these fragments
  (`pkgs/kernel/linux.nix:98`), so the FAT default codepage/charset NLS
  (`NLS_CODEPAGE_437`, `NLS_UTF8`) come from defconfig and are builtin.

This is already exercised at runtime: the current image mounts the ESP at
`/boot` as `vfat` via `/etc/fstab` (`modules/base/filesystems.nix:51`, a hard
mount), and `checks.fleet.install-from-image` is green with an
`assert not failed` units check — so the ESP vfat mount, with these exact NLS
defaults, demonstrably works. Stage-1 runs the **same** kernel (the UKI bundles
one kernel for both stages), and EROFS — also `=y` builtin (`storage.config:55`)
— is already mounted in stage-1 (`sysroot.mount`) with **no** entry in
`boot.initrd.modules`. VFAT behaves identically.

**Optional, documentation-only:** AOS already lists some builtin filesystems in
the manifest (`ext4`) as a record of "filesystems the image supports", so you
*may* add `"vfat"` to `aos.boot.initrd.modules` for parity. It is not
load-bearing (`modprobe` of a builtin is a no-op success), and EROFS is not
listed despite being the root, so leaving it out is equally consistent. Either
way, no `nls_*` entries are needed.

---

## 5. `modules/base/_initrd-builder.nix` — `erofs-utils` in the initrd

The initrd closure is the fixed `initrdPackages` list **plus** the rendered-unit
closure (`exportReferencesGraph` over `initrdUnits`, `_initrd-builder.nix:389-394`);
the rendered units embed `environment.PATH = ignitionPath`, so adding
`erofs-utils` to `ignitionTools` (change #3d) **already** pulls it into the initrd
via the unit references — the same path by which `jq` and `dosfstools` reach the
initrd today without being in `initrdPackages`. This step is therefore not strictly
required to make `fsck.erofs` present. Add `pkgs.erofs-utils` to the base
`initrdPackages` list anyway for explicitness (alongside `e2fsprogs`, `gptfdisk`,
`cryptsetup`, …), and add a short `/bin/fsck.erofs` symlink if the builder
maintains short-name symlinks for the tools Ignition/initrd scripts call.

`dd`, `sync`, `blkid`, `mount`, `umount`, `mountpoint` are already present
(`coreutils` + `util-linux`). The `vfat` **kernel** module comes from change #4
(the builder copies the active kernel's module tree); no userspace FAT tool is
needed for a read-only mount.

Cost: `erofs-utils` adds a few MiB to the initrd — acceptable, and it is
already a build dependency of `lib/build/rootfs.nix`.

---

## 6. `modules/base/filesystems.nix` — partlabel-based devices

`root-a` is no longer image partition 2 — the operator may place it at any
number. Make the root and ESP fstab devices partlabel-based so they are
partition-number independent (the UKI cmdline already uses
`root=/dev/disk/by-partlabel/root-a`):

```nix
rootDevice = lib.mkOption {
  type = lib.types.str;
  default = "/dev/disk/by-partlabel/root-a";
  description = "Block device for the root filesystem.";
};

espDevice = lib.mkOption {
  type = lib.types.str;
  default = "/dev/disk/by-partlabel/ESP";
  description = "Block device for the EFI System Partition.";
};
```

Verify the production system profiles (`systems/server*.nix`) don't pin these
to `/dev/vdaN`; if they do, drop the override so the partlabel defaults apply.

The fstab `/boot` mount stays on the ESP (`espDevice → /boot vfat ro,…`) for
now — that is where the only UKI lives. The systemd-canonical XBOOTLDR-at-`/boot`
+ ESP-at-`/efi` split lands with the `apm` follow-up, once something writes
XBOOTLDR. The `var` and swap entries are unchanged (`cryptswap.service` and the
`/dev/disk/by-partlabel/var` fstab line already key off partlabels).

---

## 7. `tests/fleet/install-from-image.nix` — exercise the new flow

`checks.fleet.install-from-image` is the canonical runtime test; update its
Ignition config to the new contract and assert the dd'd root.

### Ignition config (target machine `instanceMetadata.config`)

```nix
storage = {
  disks = [
    {
      device = "/dev/vda";
      wipeTable = false;
      partitions = [
        # XBOOTLDR — reserved for apm per-gen UKIs (created, not yet used).
        {
          number = 2;
          label = "xbootldr";
          sizeMiB = 512;
          typeGuid = "BC13C2FF-59E6-4262-A352-B275FD6F7172";
        }
        # root-a — UNFORMATTED; aos-install-root dd's rootfs.bin onto it.
        {
          number = 3;
          label = "root-a";
          sizeMiB = rootSizeMiB;
          typeGuid = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
        }
        {
          number = 4;
          label = "root-b";
          sizeMiB = rootSizeMiB;
          typeGuid = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
        }
        # swap — UNFORMATTED; cryptswap.service mkswaps it per boot.
        {
          number = 5;
          label = "swap";
          sizeMiB = swapSizeMiB;
          typeGuid = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F";
        }
        {
          number = 6;
          label = "var";
          sizeMiB = 0; # rest of the disk
        }
      ];
    }
  ];
  filesystems = [
    # NOTE: no entry for root-a (dd'd EROFS) or swap (cryptswap per boot).
    {
      device = "/dev/disk/by-partlabel/xbootldr";
      format = "vfat";
      label = "AOS-XBOOT";
      wipeFilesystem = false;
    }
    {
      device = "/dev/disk/by-partlabel/root-b";
      format = "ext4";
      label = "aos-root-b";
      wipeFilesystem = false;
    }
    {
      device = "/dev/disk/by-partlabel/var";
      format = "ext4";
      label = "aos-var";
      wipeFilesystem = false;
    }
  ];
};
```

Key differences from today's config: a leading XBOOTLDR partition, `root-a`
moved to number 3 and **no longer resized or formatted** (it is created fresh
and `dd`'d), and `swap`/`root-a` deliberately absent from `filesystems`.

### Assertion changes

The existing assertions mostly hold (root is read-only EROFS, smaller than its
partition; `/var` filled the disk; gen-1 seeded). Adjust and add:

```python
# The declared install layout exists (now includes xbootldr).
for label in ("xbootldr", "root-a", "root-b", "swap", "var"):
    target.succeed(f"test -e /dev/disk/by-partlabel/{label}")

# root-a was created at exactly rootSizeMiB (fresh partition, not grown).
sectors = int(target.succeed("cat /sys/class/block/vda3/size").strip())
assert sectors == ${toString rootSizeMiB} * 2048

# aos-install-root dd'd the shipped EROFS: root-a's UUID matches the image's.
root_uuid = target.succeed(
    "blkid -s UUID -o value /dev/disk/by-partlabel/root-a"
).strip()
assert root_uuid == "bdfb6fc9-0000-4000-8000-000000000001", root_uuid

# The install service ran and verified the image.
target.succeed("systemctl is-active aos-install-root.service")
```

(`vda2` was `root-a` before; it is now `vda3`. The `stat -f` EROFS-size and
`/var` assertions key off mount points, not partition numbers, so they are
unaffected.)

The reboot leg is unchanged and now also proves the `aos-install-root` gate is
idempotent: on the post-reboot boot the service must skip (root-a already holds
the image) and the system must come back on the upgraded generation with no
failed units.

---

## 8. `docs/boot/qemu-uefi.md` — operator example

Update the by-hand walkthrough's Ignition config to match change #7 (XBOOTLDR +
unformatted `root-a` + `root-b` + `swap` + `var`) and note that the image is now
a single 512 MiB ESP `dd`'d onto an oversized disk. Keep it one-for-one with the
test config (RFC-0003's "doc and test cannot drift" principle).

---

## 9. dm-verity root — `rootfs.nix` + `aos-uki` + stage-1

The signed UKI cmdline pins `root=/dev/disk/by-partlabel/root-a`
(`modules/base/boot.nix:165`) but not the root *content*. dm-verity closes that:
the EROFS image gets a Merkle hash tree, the root hash is baked into the signed
cmdline, and stage-1 assembles a verity device the kernel checks on every read.
Kernel support is builtin (`CONFIG_DM_VERITY=y`,
`CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y` — `pkgs/kernel/config/storage.config:26-27`),
and the option surface already exists (`modules/security/verity.nix`).

### 9a. Emit the hash tree + root hash (`lib/build/rootfs.nix`)

After `root.img` (EROFS) is built, append a verity hash tree to the same file and
capture the printed root hash. A pinned `--salt=` keeps the tree and hash
byte-reproducible:

```sh
data_bytes=$(stat -c %s root.img)
veritysetup format --salt=<fixed-hex> --hash-offset=$data_bytes root.img root.img \
  | sed -n 's/^Root hash:[[:space:]]*//p' > $out/root-hash
```

Emit `$out/root-hash` (hex) and grow `rootfs-size-bytes` to include the tree.
`veritysetup` ships in the AOS `cryptsetup` build at `${cryptsetup}/sbin/veritysetup`
— asserted by `lib/testing/systemd-verity.nix:28` — and `cryptsetup` is already a
build dep of this file. The repo already formats verity images in
`lib/build/package-root-image.nix:154` (for apm package roots), but with a
**separate** `root.verity` file; this RFC appends the tree into the same `root.img`
via `--hash-offset` instead, because `rootfs.bin` must be a single `dd`-able blob
(one file on the ESP, one partition on `root-a`). Note the cryptsetup build carries
`cryptsetup-patches/0001-fail-closed-on-signed-verity-activation.patch`.

### 9b. Bake the signed root hash + hash-offset into the cmdline (`pkgs/boot/aos-uki.nix`)

`aos-uki` materializes the cmdline to a file before signing (`aos-uki.nix:103`).
Add optional `verityRootHashFile` / `verityDataBytesFile` args (paths into the
rootfs derivation) and, when set, (a) append the root hash + hash-offset and
(b) **repoint `root=` at the verity mapper**, so all of it lands inside the signed
`.cmdline` and stage-1 reads it from a signed source:

```sh
if [ -n "${verityRootHashFile}" ]; then
  # The initrd's sysroot.mount is synthesized by systemd-fstab-generator from the
  # signed cmdline's root= (modules/base/boot.nix:159-165 — there is deliberately
  # no /etc/fstab entry in the initrd). So root= MUST point at the verity mapper,
  # not the raw partition; otherwise sysroot.mount mounts root-a directly (the
  # EROFS data sits at offset 0) and silently BYPASSES verity. Repoint it here, in
  # the same signed cmdline that carries the roothash.
  sed -i 's#root=/dev/disk/by-partlabel/root-a#root=/dev/mapper/root#' cmdline
  printf ' roothash=%s aos.verity.hash_offset=%s' \
    "$(cat ${verityRootHashFile})" "$(cat ${verityDataBytesFile})" >> cmdline
fi
```

`_builder.nix` passes `verityRootHashFile = "${rootfs}/root-hash"` and
`verityDataBytesFile = "${rootfs}/rootfs-data-bytes"` when Secure Boot is enabled.
Both are computed in a derivation, so they are read from the rootfs output at build
time (no import-from-derivation). Because the `root=` rewrite lives in `aos-uki`,
the base `root=/dev/disk/by-partlabel/root-a` in `modules/base/boot.nix:165` stays
unchanged (component table row #4 remains "none required"), and the unsigned dev
image (no `verityRootHashFile`) keeps `root=root-a` and mounts the raw partition.

### 9c. Assemble the verity device in stage-1 (`modules/services/ignition.nix`)

Extend `aos-install-root.service`: after the `dd` + `fsck.erofs`, open the verity
device from the **signed** root hash (read from `/proc/cmdline`, never from disk)
and the appended tree, then let the root mount consume the mapper:

```sh
# Both the root hash and the hash-offset (where the appended verity tree begins)
# come from the SIGNED cmdline — never read off the disk.
roothash=$(sed -n 's/.*\broothash=\([0-9a-f]\+\).*/\1/p' /proc/cmdline)
offset=$(sed -n 's/.*\baos\.verity\.hash_offset=\([0-9]\+\).*/\1/p' /proc/cmdline)
veritysetup open /dev/disk/by-partlabel/root-a root \
  /dev/disk/by-partlabel/root-a "$roothash" --hash-offset=$offset
```

`sysroot.mount` then mounts `/dev/mapper/root` — which it does because §9b
repointed the signed cmdline's `root=` at the mapper, and this service creates that
mapper before `sysroot.mount` runs (`Before=sysroot.mount`). If the `veritysetup
open` fails (or the image was a partial/tampered `dd`), `/dev/mapper/root` never
appears, so `sysroot.mount` fails and the boot drops to emergency rather than
mounting an unverified root — the install path is **fail-closed** under verity.
Drive the open from the cmdline's `roothash=` only, so the anchor is the signature,
not the medium. When the cmdline carries no `roothash=` (the unsigned dev image),
skip the open; `root=` is still `root-a` and the raw partition mounts as today.

### 9d. Point the root device at the mapper (`modules/base/filesystems.nix`)

`rootDevice` becomes `/dev/mapper/root` when verity is active (gate on the
secure-boot / verity option), falling back to `/dev/disk/by-partlabel/root-a` for
the unsigned dev image. This governs the **stage-2** `/etc/fstab` entry for `/`;
the **initrd** `sysroot.mount` is driven by the signed cmdline `root=` (repointed
in §9b) and is moved across switch-root, so the two must agree. fstab `passno`
stays `0` (read-only, verity-checked).

### 9e. ESP sizing

The appended tree is ~1% of the EROFS image (a few MiB for a ~160 MiB root); the
`espSizeMiB` fit assertion (change #2a) already sums ESP contents, so the larger
`rootfs.bin` is accounted for automatically.

## 10. Emergency / recovery profile — `pkgs/boot/aos-uki.nix`

The install UKI gains a second **profile** whose baked, signed `.cmdline` boots
the initrd emergency target — recovery-key-gated console access under Secure Boot
(RFC §Emergency and recovery access). A runtime karg cannot do this: sd-stub drops
it under SB (systemd v259.1 `src/boot/stub.c:1184-1200`).

### 10a. Build the profile (`aos-uki`)

Assemble a multi-profile UKI with `ukify` (v259.1): profile 0 = the normal cmdline
(+ `roothash=` from §9b); profile 1 = the same plus `rd.systemd.unit=emergency.target`.
sd-boot renders one menu entry per profile (`src/boot/boot.c:2177-2263`) and the
`@N` selector survives the SB cmdline-drop (`stub.c:188`, `:1232-1245`); `editor no`
(`_builder.nix:182`) stays on. The v259.1 mechanism (confirmed against the
`~/src/c/systemd` clone) is a two-step build: first
`ukify build --profile='ID=emergency\n…' --cmdline='… rd.systemd.unit=emergency.target' --output=profile-emergency.efi`,
then the main `ukify build … --profile='ID=main\n…' --join-profile=profile-emergency.efi …`.
`--profile`/`--join-profile` landed in v257 and `--sign-profile` in v258
(`man/ukify.xml:255,269,280`); the join is implemented at `ukify.py:1483-1512`.

### 10b. Exclude the emergency profile from the signed PCR policy

The `/var` seal is signature-flexible on PCR 11 (`secure-boot.nix:208-228,:438-439`).
The emergency profile's PCR-11 prediction **must not** be blessed by the signed
`.pcrsig`, or the TPM auto-unseals `/var` for whoever selects it. v259.1 `ukify`
does exactly this via `--sign-profile=main`: it signs the PCR-11 policy only for
profiles whose `.profile` env-file `ID=` matches (`ukify.py:1515-1520`), so the
emergency profile (`ID=emergency`) gets **no** signed prediction. At boot the stub
overrides `sections[]` with the selected profile's `.cmdline`/`.profile`
(`stub.c:1148-1158`) and measures them into PCR 11 (`stub.c:751-791`,
`tpm2-pcr.h:28`), so selecting the emergency profile yields a PCR-11 value with no
matching signature in `.pcrsig` → the `--tpm2-public-key-pcrs=11` unseal
(`secure-boot.nix:382-396`) fails closed and the recovery key is required. PCR 7 is
unchanged (firmware-measured SB state). **Build constraint:** the emergency
profile's `--profile='ID=…'` MUST use an ID distinct from any `--sign-profile=`
value, or the exclusion does not happen (`ukify.py:1518` gates by ID string). A CI
assertion (change #7) proves the emergency profile reaches the shell and leaves
`/var` sealed.

### 10c. Recovery tooling + authentication

The initrd already carries `cryptsetup`/`veritysetup`, `dd`, `blkid`, and (change
#5) `erofs-utils` — enough to re-pave `root-a` and `cryptsetup open` the `/var`
recovery slot (`secure-boot.nix:447-449`). The emergency target runs `sulogin`:
bake an emergency root-password hash for the **non-SB** image (or the constrained
recovery program from the RFC). Under SB the shell is password-less by design —
verity (§9) denies persistence, the excluded PCR (§10b) denies `/var` exposure,
and lockdown (`secure-boot.nix:280-283`, when enabled) denies the usual root
escalations.

---

## Work-item checklist (suggested order)

1. **`rootfs.nix`** — append the verity hash tree + emit the root hash (change #9a).
2. **`_builder.nix`** — single-ESP image + `rootfs.bin`, `espSizeMiB` + fit
   assertion (incl. the verity tree), `image-info.json` (change #2); pass
   `verityRootHashFile` to `aos-uki`. Build `nix-build -A
   <system>.config.system.build.image` and inspect with `sfdisk -d` / `mdir`.
3. **`aos-uki.nix`** — bake the signed `roothash=` (change #9b) + the emergency
   profile (change #10).
4. **`boot.nix`** — none required (VFAT builtin); optional documentation-only
   `"vfat"` manifest entry (change #4).
5. **`_initrd-builder.nix`** — `erofs-utils` in the initrd (change #5).
6. **`ignition.nix`** — `aos-install-root.service` (dd + `veritysetup open`) +
   `aos-gpt-relocate` rework + `ignitionTools` (changes #3, #9c).
7. **`filesystems.nix`** — partlabel devices + verity mapper root (changes #6, #9d).
8. **`install-from-image.nix`** — new config + assertions incl. verity root +
   emergency-profile no-unseal (change #7).
9. **`qemu-uefi.md`** — operator example (change #8).

## Testing / validation

- `nix-build -A checks.eval` — module eval (option defaults, the new unit,
  the boot.nix assertion still passes).
- `nix-build -A checks.vm.boot` — a kernel-boot VM test must still pass: the
  ext4-root path has no ESP/`rootfs.bin`, so `aos-install-root` is a no-op via
  its `ConditionPathExists` AND of the two endpoints. Confirm it logs the
  no-op and does not fail the boot.
- **`checks.fleet.install-from-image`** — the real end-to-end proof: UEFI →
  sd-boot → install UKI → Ignition partitions the disk → `aos-install-root`
  `dd`s `rootfs.bin` → boot on EROFS `root-a` → `apm upgrade --system` → reboot
  → idempotent install gate skips, system healthy. This is the gate for the
  change.
- **`checks.fleet.secure-boot` / `checks.fleet.measured-boot`** — extend to prove
  (a) the verity-mapped root mounts and a corrupted `root-a` fails the boot closed
  (verity catches it), and (b) selecting the emergency profile reaches the initrd
  emergency shell and does **not** auto-unseal `/var` (the recovery key is
  required).
- Inspect the built image (`mdir -i esp.img ::`) to confirm `rootfs.bin` (with its
  appended verity tree) is present and the partition table has exactly one
  partition.

## Risks & migration

- **Breaking image-format change.** The shipped image no longer carries
  `root-a`; there is no in-place migration from a v2 image — re-deploy from the
  new artifact. AOS is pre-release, so no fielded installs depend on the old
  layout.
- **ESP budget caps root growth.** `rootfs.bin` must stay within `espSizeMiB`
  minus the UKI and FAT overhead. The build-time assertion turns an overflow
  into a clear build failure (raise `espSizeMiB`) rather than a corrupt image.
- **`vfat` availability.** Resolved: `CONFIG_VFAT_FS=y` is builtin
  (`pkgs/kernel/config/storage.config:66`) and the ESP vfat mount is already
  proven by the current `/boot` mount + green `install-from-image`. No risk.
- **Initrd size.** `erofs-utils` adds a few MiB; acceptable for the
  power-fail-safe `fsck.erofs` gate. If size becomes a concern, the gate can
  fall back to UUID-match-only (dropping `fsck.erofs`), at the cost of not
  detecting a partial `dd` — not recommended.
- **`dd` throughput.** Writing ~160 MiB on first boot adds a couple of seconds;
  negligible next to Ignition's partitioning + mkfs and well inside the test
  timeout. The `veritysetup open` is near-instant (it builds no tree, only reads
  the appended one).
- **Verity reproducibility.** `veritysetup format` must use a pinned `--salt=` so
  the hash tree and root hash are byte-reproducible across builds (an unpinned salt
  randomizes both). The root hash is computed at build time, so `aos-uki` reads it
  from the rootfs derivation rather than from a Nix-eval value (no
  import-from-derivation).
- **`ukify` multi-profile + PCR policy.** Confirmed against the systemd v259.1
  clone: multi-profile UKIs build via `--profile`/`--join-profile` (v257) and the
  signed PCR policy is scoped per profile via `--sign-profile` (v258), so the
  emergency profile's PCR-11 prediction is excluded from `.pcrsig` and it cannot
  auto-unseal `/var` (changes #10a, #10b). The one build constraint is that the
  emergency profile must carry a distinct `.profile` `ID=` (not passed to
  `--sign-profile`); CI (change #7) asserts the property end-to-end.

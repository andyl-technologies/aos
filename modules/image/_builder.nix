##! modules/image/_builder.nix — AOS disk image builder (sandbox-compatible)
##!
##! Produces a bootable GPT disk image from an evaluated AOS system
##! configuration. The image contains:
##!
##!   Partition 1 (Boot) — ext4, kernel + initrd + boot config
##!   Partition 2 (Root) — ext4, Nix store closure + system symlinks
##!   Remaining space    — unpartitioned (reserved for ZFS data pool at runtime)
##!
##! Boot method: BIOS boot via syslinux/extlinux (installed on the boot
##! partition). EFI boot can be added later when systemd-boot EFI stub
##! is available.
##!
##! Build strategy (no losetup/mount — fully sandbox-compatible):
##!   1. Populate root directory tree on disk
##!   2. mkfs.ext4 -d root/ → creates ext4 image from directory
##!   3. Populate boot directory tree on disk
##!   4. mkfs.ext4 -d boot/ → creates ext4 boot image from directory
##!   5. sfdisk + dd → assembles partitions into final GPT image
##!
##! Arguments:
##!   pkgs     — AOS package set
##!   lib      — AOS library
##!   system   — evaluated system configuration (from evalModules)
##!   name     — image name slug (used in derivation name and boot entry)
##!   diskSize — total raw image size (e.g. "16G")
##!   bootSize — boot partition size (e.g. "512M")
##!   rootSize — root partition size (e.g. "8G")
##!
##! Output: $out/aos-${name}.img + $out/image-info.json
{
  pkgs,
  lib,
  system,
  name,
  diskSize ? "16G",
  bootSize ? "512M",
  rootSize ? "8G",
  # Legacy compat — espSize maps to bootSize
  espSize ? bootSize,
}:
let
  # Kernel command line parameters from the evaluated config.
  kernelParams = lib.concatStringsSep " " system.config.aos.boot.kernelParams;

  version = system.config.aos.system.version;

  # Parse sizes to bytes for dd offsets.
  parseSize =
    s:
    let
      mG = builtins.match "([0-9]+)G" s;
      mM = builtins.match "([0-9]+)M" s;
    in
    if mG != null then
      (builtins.fromJSON (builtins.head mG)) * 1024 * 1024 * 1024
    else if mM != null then
      (builtins.fromJSON (builtins.head mM)) * 1024 * 1024
    else
      throw "Cannot parse size: ${s}";

  bootBytes = parseSize bootSize;
  rootBytes = parseSize rootSize;

  # Partition geometry (512-byte sectors)
  bootStartSector = 2048; # 1 MiB alignment
  bootSectors = bootBytes / 512;
  rootStartSector = bootStartSector + bootSectors;
  rootSectors = rootBytes / 512;
in
pkgs.mkDerivation {
  name = "aos-image-${name}";

  # No source — this is a pure assembly step.
  src = null;

  buildDeps = [
    pkgs.util-linux # sfdisk
    pkgs.e2fsprogs # mkfs.ext4 -d
    pkgs.dosfstools # mkfs.vfat
    pkgs.mtools # mcopy to populate the vfat boot partition sandbox-free
    pkgs.coreutils # truncate, cp, mkdir, ln, cat, dd
    pkgs.grep # grep store paths from closure graph
  ];

  # exportReferencesGraph computes the store closure at eval time and
  # writes it as a file into the build directory — no nix-store needed.
  exportReferencesGraph = [
    "closure-toplevel"
    system.config.system.build.toplevel
  ];

  phases = [
    {
      name = "build-image";
      script = ''
        echo "==> Building sandbox-compatible disk image for AOS ${name}"

        # ── 0. Extract store paths from closure graph ──────────────────────
        grep '^/nix/store/' closure-toplevel | sort -u > store-paths
        echo "    $(wc -l < store-paths) store paths in closure"

        # ── 1. Build root filesystem directory tree ────────────────────────
        echo "==> Populating root filesystem tree"
        mkdir -p rootfs/nix/store
        mkdir -p rootfs/{etc,var,run,tmp,proc,sys,dev,sbin,boot}
        mkdir -p rootfs/var/{log,lib,tmp}
        mkdir -p rootfs/run/current-system

        # Copy Nix store closure
        total=$(wc -l < store-paths)
        count=0
        while IFS= read -r storePath; do
          count=$((count + 1))
          if [ $((count % 50)) -eq 0 ] || [ "$count" -eq "$total" ]; then
            printf '\r    [%d/%d]' "$count" "$total"
          fi
          cp -a "$storePath" rootfs"$storePath"
        done < store-paths
        echo ""

        # Symlink the active system profile
        ln -sfn ${system.config.system.build.toplevel} \
          rootfs/run/current-system

        # /sbin/init → systemd
        ln -sfn ${pkgs.systemd}/lib/systemd/systemd rootfs/sbin/init

        # Runtime compatibility symlinks.
        #
        # /bin/bash and /bin/sh match CLAUDE.md's explicit allowance
        # for "Shebangs inside VM rootfs init scripts" — the rootfs
        # builder is allowed to create a /bin/sh pointing at AOS bash.
        mkdir -p rootfs/bin
        ln -sfn ${pkgs.bash}/bin/bash rootfs/bin/bash
        ln -sfn ${pkgs.bash}/bin/sh rootfs/bin/sh

        # /usr is populated with exactly one file: /usr/bin/env. That
        # is the one widely-used shebang target (`#!/usr/bin/env python`
        # etc.) and it is also what keeps systemd 259's
        # `dir_is_empty("/usr")` check in src/core/main.c happy so
        # stage-2 starts. Every other /usr/* path (e.g. /usr/sbin/sshd,
        # /usr/sbin/agetty) must be replaced by an absolute Nix store
        # path in the referring unit — we do NOT blanket /usr/* with
        # compatibility symlinks.
        mkdir -p rootfs/usr/bin
        ln -sfn ${pkgs.coreutils}/bin/env rootfs/usr/bin/env

        # Empty machine-id signals systemd to generate one on first boot
        touch rootfs/etc/machine-id

        # Install /etc from the toplevel derivation.
        # The toplevel's /etc contains config files (passwd, fstab,
        # os-release, systemd units, etc.) that systemd needs at boot.
        # --no-clobber preserves the empty machine-id created above.
        echo "    Installing /etc from toplevel"
        toplevel=${system.config.system.build.toplevel}
        if [ -d "$toplevel/etc" ]; then
          cp -a --no-clobber "$toplevel/etc/." rootfs/etc/
        fi

        # ── 2. Create ext4 root partition image ────────────────────────────
        echo "==> Creating ext4 root image (${rootSize})"
        truncate -s ${toString rootBytes} root.img
        mkfs.ext4 -L aos-root -O ^has_journal -d rootfs -q root.img

        # ── 3. Build boot directory tree ───────────────────────────────────
        echo "==> Populating boot tree"
        mkdir -p bootfs

        # Kernel and initrd
        cp ${system.config.system.build.kernel}/boot/vmlinuz-* bootfs/vmlinuz
        cp ${system.config.system.build.initrd}/initrd.img bootfs/initrd.img

        # Boot configuration (syslinux/extlinux format — works with
        # QEMU -kernel too, and most cloud platforms can parse this)
        cat > bootfs/syslinux.cfg <<SYSLINUX
DEFAULT aos
PROMPT 0
TIMEOUT 30

LABEL aos
  MENU LABEL AOS ${name} ${version}
  LINUX /vmlinuz
  INITRD /initrd.img
  APPEND ${kernelParams}
SYSLINUX

        # GRUB-compatible entry for cloud platforms that look for grub.cfg
        mkdir -p bootfs/grub
        cat > bootfs/grub/grub.cfg <<GRUB
set default=0
set timeout=3

menuentry "AOS ${name} ${version}" {
  linux /vmlinuz ${kernelParams}
  initrd /initrd.img
}
GRUB

        # ── 4. Create vfat boot partition image ───────────────────────────
        # FAT32 is what UEFI reads. mkfs.vfat has no -d flag, so we
        # create an empty image, then use mtools' mcopy -s to populate
        # it from the bootfs directory tree — sandbox-compatible, no
        # loopback mount needed. MTOOLS_SKIP_CHECK=1 is required because
        # mcopy otherwise refuses to write to a plain file that has no
        # ~/.mtoolsrc entry.
        echo "==> Creating vfat boot image (${bootSize})"
        truncate -s ${toString bootBytes} boot.img
        mkfs.vfat -F 32 -n AOSBOOT boot.img
        export MTOOLS_SKIP_CHECK=1
        for entry in bootfs/*; do
          mcopy -s -i boot.img "$entry" "::"
        done

        # ── 5. Assemble final GPT image ───────────────────────────────────
        echo "==> Assembling ${diskSize} GPT image"
        truncate -s ${diskSize} image.raw

        # Write GPT partition table
        # Partition 1 has BIOS boot flag for legacy boot compatibility
        sfdisk image.raw <<PTABLE
label: gpt
size=${toString bootSectors}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="Boot", attrs="LegacyBIOSBootable"
size=${toString rootSectors}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="Root"
PTABLE

        # dd partition images into the correct offsets
        echo "    Writing boot partition at sector ${toString bootStartSector}"
        dd if=boot.img of=image.raw bs=512 seek=${toString bootStartSector} conv=notrunc status=none

        echo "    Writing root partition at sector ${toString rootStartSector}"
        dd if=root.img of=image.raw bs=512 seek=${toString rootStartSector} conv=notrunc status=none

        echo "==> Image assembly complete"
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
        mv image.raw $out/aos-${name}.img

        # Also provide kernel and initrd separately for direct-kernel-boot
        # workflows (QEMU -kernel, cloud platform import, PXE, etc.)
        ln -s ${system.config.system.build.kernel}/boot/vmlinuz-* $out/vmlinuz
        ln -s ${system.config.system.build.initrd}/initrd.img $out/initrd.img

        # Write image metadata for downstream tooling.
        cat > $out/image-info.json <<META
{
  "name": "${name}",
  "version": "${version}",
  "diskSize": "${diskSize}",
  "bootSize": "${bootSize}",
  "rootSize": "${rootSize}",
  "format": "raw",
  "partitionTable": "gpt",
  "kernelParams": "${kernelParams}",
  "partitions": [
    { "number": 1, "label": "Boot", "type": "linux", "filesystem": "ext4", "size": "${bootSize}" },
    { "number": 2, "label": "Root", "type": "linux", "filesystem": "ext4", "size": "${rootSize}" }
  ]
}
META
      '';
    }
  ];
}

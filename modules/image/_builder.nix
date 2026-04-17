##! modules/image/_builder.nix — AOS disk image builder (sandbox-compatible)
##!
##! Produces a bootable GPT disk image from an evaluated AOS system
##! configuration. The image contains:
##!
##!   Partition 1 (boot) — vfat, kernel + initrd + boot config
##!   Partition 2 (root) — ext4, Nix store closure + system symlinks
##!                         (sized to fit the root filesystem tree)
##!
##! Ignition adds swap + /var partitions at first boot in the
##! unallocated space after the root partition.
##!
##! Build strategy (no losetup/mount — fully sandbox-compatible):
##!   1. Populate root directory tree on disk
##!   2. mkfs.ext4 -d root/ → creates ext4 image from directory
##!   3. resize2fs -M → shrink to minimum, then grow by headroom
##!   4. Populate boot directory tree on disk
##!   5. mkfs.vfat + mcopy → creates FAT32 boot image
##!   6. sfdisk + dd → assembles partitions into final GPT image
##!
##! Arguments:
##!   pkgs     — AOS package set
##!   lib      — AOS library
##!   system   — evaluated system configuration (from evalModules)
##!   name     — image name slug (used in derivation name and boot entry)
##!   bootSize — boot partition size (e.g. "1G")
##!
##! Output: $out/aos-${name}.img + $out/image-info.json
{
  pkgs,
  lib,
  system,
  name,
  bootSize ? "1G",
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

  # Partition geometry (512-byte sectors).
  # Root partition size is computed at build time after measuring the
  # rootfs tree — only boot geometry is known at eval time.
  bootStartSector = 2048; # 1 MiB alignment
  bootSectors = bootBytes / 512;
  rootStartSector = bootStartSector + bootSectors;
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
  # The kernel is included alongside the toplevel because the rootfs
  # carries a /lib/modules symlink into ${kernel}/lib/modules; without
  # the kernel's closure in /nix/store that symlink is dangling on the
  # running system and modprobe reports "Module <name> not found".
  exportReferencesGraph = [
    "closure-toplevel"
    system.config.system.build.toplevel
    "closure-kernel"
    system.config.system.build.kernel
  ];

  phases = [
    {
      name = "build-image";
      script = ''
        echo "==> Building sandbox-compatible disk image for AOS ${name}"

        # ── 0. Extract store paths from closure graph ──────────────────────
        # Merge toplevel + kernel closures, dedupe. Both need to land
        # in /nix/store on the root partition (toplevel for stage-2,
        # kernel's /lib/modules for modprobe lookups).
        grep -h '^/nix/store/' closure-toplevel closure-kernel | sort -u > store-paths
        echo "    $(wc -l < store-paths) store paths in closure"

        # ── 1. Build root filesystem directory tree ────────────────────────
        echo "==> Populating root filesystem tree"
        mkdir -p rootfs/nix/store
        mkdir -p rootfs/{etc,var,run,tmp,proc,sys,dev,sbin,boot}
        mkdir -m 0700 -p rootfs/root
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

        # /lib/modules → kernel's modules tree. kmod (modprobe/insmod)
        # defaults to /lib/modules/$(uname -r) for module lookup;
        # without this symlink services like k8s-modules-load fail
        # with "Module <name> not found in directory /lib/modules/..."
        # even though the .ko ships in the kernel's store path.
        mkdir -p rootfs/lib
        ln -sfn ${system.config.system.build.kernel}/lib/modules \
          rootfs/lib/modules

        # /var/run → /run. Standard modern-Linux convention: /run is
        # a tmpfs and /var/run is a back-compat symlink. Many daemons
        # (dbus-daemon's system.conf, various PID files) still use
        # /var/run/... paths.
        ln -sfn /run rootfs/var/run

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

        # Build a debugfs chown script for later (see the post-mkfs
        # step below). Nix sandbox builds run as nixbld (uid 1000),
        # which `cp -a` preserves into rootfs/etc — several daemons
        # then refuse to start (auditd: `/etc/audit/auditd.conf isn't
        # owned by root`). chown(2) from within the sandbox can't
        # target uid 0 (unprivileged user-ns only maps nixbld→0 at the
        # VFS layer, not on-disk), so we instead patch the on-disk
        # inodes via debugfs after mkfs.ext4 writes the image.
        #
        # /nix/store paths must NOT be touched (shared between
        # derivations at the Nix level). /bin, /sbin, /usr are
        # symlinks (no uid the kernel enforces on access). Only
        # /etc needs a post-pass. `sif <path> uid=0 gid=0` on every
        # inode under /etc does the job in one debugfs invocation.
        echo "    Generating /etc ownership reset script"
        {
          echo "sif /etc uid 0"
          echo "sif /etc gid 0"
          find rootfs/etc -mindepth 1 -printf '/etc/%P\n' | while IFS= read -r p; do
            echo "sif \"$p\" uid 0"
            echo "sif \"$p\" gid 0"
          done
        } > etc-chown.debugfs

        # ── 2. Create ext4 root partition image (sized to fit) ─────────────
        echo "==> Measuring rootfs tree"
        rootfs_bytes=$(du -sb rootfs | cut -f1)
        # 2x data for initial mkfs headroom (resized down afterwards).
        initial_bytes=$(( rootfs_bytes * 2 + 256 * 1024 * 1024 ))
        echo "    rootfs data: $(( rootfs_bytes / 1048576 )) MiB"

        echo "==> Creating ext4 root image"
        truncate -s "$initial_bytes" root.img
        mkfs.ext4 -L aos-root -O ^has_journal -d rootfs -q root.img

        # Apply the /etc ownership reset prepared above. debugfs's
        # `sif` command sets inode fields on the live image; one
        # invocation executes the whole script.
        echo "    Resetting /etc ownership to root:root via debugfs"
        debugfs -w -f etc-chown.debugfs root.img >/dev/null

        # Shrink root.img to its minimum size + 64 MiB headroom.
        echo "    Shrinking root image to fit"
        e2fsck -f -y root.img >/dev/null
        resize2fs -M root.img >/dev/null 2>&1
        # Read the minimum block count, then grow by 64 MiB.
        blk_size=$(dumpe2fs -h root.img 2>/dev/null | awk '/Block size:/{print $3}')
        min_blocks=$(dumpe2fs -h root.img 2>/dev/null | awk '/Block count:/{print $3}')
        headroom_blocks=$(( 64 * 1024 * 1024 / blk_size ))
        final_blocks=$(( min_blocks + headroom_blocks ))
        resize2fs root.img "$final_blocks" >/dev/null 2>&1
        # Compute final byte size, round up to 1 MiB alignment.
        root_bytes=$(( final_blocks * blk_size ))
        root_bytes=$(( ((root_bytes + 1048575) / 1048576) * 1048576 ))
        truncate -s "$root_bytes" root.img
        echo "    root image: $(( root_bytes / 1048576 )) MiB"

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
        root_sectors=$(( root_bytes / 512 ))
        # 1 MiB (2048 sectors) at the start for GPT header + alignment,
        # plus 1 MiB at the end for the backup GPT header.
        disk_sectors=$(( ${toString rootStartSector} + root_sectors + 2048 ))
        disk_bytes=$(( disk_sectors * 512 ))
        echo "==> Assembling $(( disk_bytes / 1048576 )) MiB GPT image"
        truncate -s "$disk_bytes" image.raw

        # Write GPT partition table.
        sfdisk image.raw <<PTABLE
label: gpt
size=${toString bootSectors}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="boot", attrs="LegacyBIOSBootable"
size=$root_sectors, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="root"
PTABLE

        # dd partition images into the correct offsets.
        echo "    Writing boot partition at sector ${toString bootStartSector}"
        dd if=boot.img of=image.raw bs=512 seek=${toString bootStartSector} conv=notrunc status=none

        echo "    Writing root partition at sector ${toString rootStartSector}"
        dd if=root.img of=image.raw bs=512 seek=${toString rootStartSector} conv=notrunc status=none

        # Save root size for the install phase.
        echo "$root_bytes" > root-size-bytes

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
        root_size_bytes=$(cat root-size-bytes)
        root_size_mib=$(( root_size_bytes / 1048576 ))
        disk_size_bytes=$(stat -c %s "$out/aos-${name}.img")
        disk_size_mib=$(( disk_size_bytes / 1048576 ))
        cat > $out/image-info.json <<META
{
  "name": "${name}",
  "version": "${version}",
  "diskSizeMiB": $disk_size_mib,
  "bootSize": "${bootSize}",
  "rootSizeMiB": $root_size_mib,
  "format": "raw",
  "partitionTable": "gpt",
  "kernelParams": "${kernelParams}",
  "partitions": [
    { "number": 1, "label": "boot", "type": "linux", "filesystem": "vfat", "size": "${bootSize}" },
    { "number": 2, "label": "root", "type": "linux", "filesystem": "ext4", "sizeMiB": $root_size_mib }
  ]
}
META
      '';
    }
  ];
}

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
##!   1. lib/build/rootfs.nix builds root.img (ext4, root-owned)
##!   2. Populate boot directory tree on disk
##!   3. mkfs.vfat + mcopy → creates FAT32 boot image
##!   4. sfdisk + dd → assembles partitions into final GPT image
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
}: let
  # Kernel command line parameters from the evaluated config.
  kernelParams = lib.concatStringsSep " " system.config.aos.boot.kernelParams;

  version = system.config.aos.system.version;

  # Parse sizes to bytes for dd offsets.
  parseSize = s: let
    mG = builtins.match "([0-9]+)G" s;
    mM = builtins.match "([0-9]+)M" s;
  in
    if mG != null
    then (builtins.fromJSON (builtins.head mG)) * 1024 * 1024 * 1024
    else if mM != null
    then (builtins.fromJSON (builtins.head mM)) * 1024 * 1024
    else throw "Cannot parse size: ${s}";

  bootBytes = parseSize bootSize;

  # Partition geometry (512-byte sectors).
  # Root partition size is computed at build time after measuring the
  # rootfs tree — only boot geometry is known at eval time.
  bootStartSector = 2048; # 1 MiB alignment
  bootSectors = bootBytes / 512;
  rootStartSector = bootStartSector + bootSectors;

  mkRootfs = import ../../lib/build/rootfs.nix;
  rootfs = mkRootfs {
    inherit pkgs lib system;
    pname = "aos-image-${name}-rootfs";
    label = "aos-root";
    etcTarget = "etc";
    shrinkToFit = true;
    headroomMiB = 64;
  };
in
  pkgs.mkDerivation {
    name = "aos-image-${name}";
    src = null;

    buildDeps = [
      pkgs.util-linux # sfdisk
      pkgs.e2fsprogs
      pkgs.dosfstools # mkfs.vfat
      pkgs.mtools # mcopy to populate the vfat boot partition sandbox-free
      pkgs.coreutils
    ];

    ROOT_IMG = "${rootfs}/root.img";
    ROOT_SIZE_FILE = "${rootfs}/rootfs-size-bytes";

    phases = [
      {
        name = "build-image";
        script = ''
                  set -eu
                  echo "==> Building sandbox-compatible disk image for AOS ${name}"

                  # ── 1. Pick up the prebuilt root image from lib/build/rootfs.nix ──
                  cp "$ROOT_IMG" root.img
                  chmod u+w root.img
                  root_bytes=$(cat "$ROOT_SIZE_FILE")
                  echo "    root image: $(( root_bytes / 1048576 )) MiB"

                  # ── 2. Build boot directory tree ───────────────────────────────────
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

                  # ── 3. Create vfat boot partition image ───────────────────────────
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

                  # ── 4. Assemble final GPT image ───────────────────────────────────
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

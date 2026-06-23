##! modules/image/_builder.nix — AOS disk image builder (sandbox-compatible)
##!
##! Produces a UEFI-bootable GPT disk image from an evaluated AOS system
##! configuration. The image contains:
##!
##!   Partition 1 (ESP)    — vfat, sized to its contents x2 (A/B headroom)
##!                          EFI/BOOT/BOOTX64.EFI              (UEFI fallback)
##!                          EFI/systemd/systemd-bootx64.efi   (sd-boot canonical)
##!                          EFI/Linux/aos-<toplevel-hash>.efi (UKI)
##!                          loader/loader.conf                (sd-boot config)
##!   Partition 2 (root-a) — rootFsType (erofs/ext4), sized to the rootfs image
##!
##! Ignition creates root-b, swap, and /var partitions on first boot
##! in the unallocated space after root-a.
##!
##! Build strategy (no losetup/mount — fully sandbox-compatible):
##!   1. lib/build/rootfs.nix builds root.img (erofs or ext4, root-owned)
##!   2. Populate ESP tree (sd-boot + UKI + loader.conf)
##!   3. mkfs.vfat + mcopy → creates FAT32 ESP image
##!   4. sfdisk + dd → assembles partitions into final GPT image
##!
##! Arguments:
##!   pkgs   — AOS package set
##!   lib    — AOS library
##!   system — evaluated system configuration (from evalModules)
##!   name   — image name slug
##!
##! Output: $out/aos-${name}.img + $out/image-info.json
{
  pkgs,
  lib,
  system,
  name,
}: let
  toplevel = system.config.system.build.toplevel;
  toplevelStorePath = toString toplevel;
  toplevelStoreHash = builtins.substring 0 32 (baseNameOf toplevelStorePath);
  # The ESP UKI entry name is derived from the toplevel store hash. apm uses
  # the same convention when reconciling retained generations at runtime.
  ukiFilename = "aos-${toplevelStoreHash}.efi";
  ukiOutputFilename = "aos-${system.config.aos.system.name}-${version}.efi";
  # Kernel command line baked into system.build.uki.
  kernelParams = lib.concatStringsSep " " (
    system.config.aos.boot.kernelParams
    ++ ["aos.toplevel=${toplevel}"]
  );

  version = system.config.aos.system.version;

  # The ESP is sized at build time to its actual contents (the UKI + sd-boot)
  # times two — headroom for a sysupdate A/B flow that stages a second UKI
  # during upgrades — plus FAT overhead, floored at 128 MiB. See the build
  # script's "Create vfat ESP" step. Only the start sector is fixed here.
  espStartSector = 2048; # 1 MiB GPT + alignment

  # UEFI ESP partition GUID.
  espGuid = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
  # Standard Linux filesystem partition GUID.
  linuxGuid = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

  mkRootfs = import ../../lib/build/rootfs.nix;
  # The image's root filesystem matches the system's declared root fstype, so
  # the fstab/mount and the on-disk image agree. Production systems set this to
  # "erofs" (compressed, read-only) for a much smaller bootable image.
  rootFsType = system.config.aos.filesystems.rootFsType;
  rootfs = mkRootfs {
    inherit pkgs lib system;
    pname = "aos-image-${name}-rootfs";
    label = "aos-root";
    fsType = rootFsType;
    shrinkToFit = true;
    headroomMiB = 64;
    extraClosures = [system.config.system.build.uki];
  };

  # Secure Boot signing. system.build.uki is already signed by aos-uki when
  # enabled; the image builder signs only sd-boot itself.
  sb = system.config.aos.boot.secureBoot;

  imageDrv = pkgs.mkDerivation {
    name = "aos-image-${name}";
    src = null;

    buildDeps =
      [
        pkgs.util-linux # sfdisk
        pkgs.e2fsprogs
        pkgs.dosfstools # mkfs.vfat
        pkgs.mtools # mcopy
        pkgs.coreutils
      ]
      ++ lib.optional sb.enable pkgs.sbsigntools; # sbsign for sd-boot

    ROOT_IMG = "${rootfs}/root.img";
    ROOT_SIZE_FILE = "${rootfs}/rootfs-size-bytes";
    UKI_PATH = "${system.config.system.build.uki}/${ukiOutputFilename}";
    SDBOOT_DIR = "${pkgs.systemd}/lib/systemd/boot/efi";

    # Secure Boot signing inputs (empty unless enabled). The UKI is
    # already signed by aos-uki; sd-boot is signed here, in place.
    SB_ENABLE =
      if sb.enable
      then "1"
      else "";
    SB_KEY =
      if sb.enable
      then sb.dbKey
      else "";
    SB_CERT =
      if sb.enable
      then sb.dbCert
      else "";

    phases = [
      {
        name = "build-image";
        script = ''
          set -eu
          echo "==> Building UEFI-bootable disk image for AOS ${name}"

          # ── 1. Root image from the shared rootfs helper ─────────────
          cp "$ROOT_IMG" root.img
          chmod u+w root.img
          root_bytes=$(cat "$ROOT_SIZE_FILE")
          echo "    root image: $(( root_bytes / 1048576 )) MiB"

          # ── 2. ESP tree ─────────────────────────────────────────────
          echo "==> Populating ESP tree"
          mkdir -p esp/EFI/BOOT
          mkdir -p esp/EFI/systemd
          mkdir -p esp/EFI/Linux
          mkdir -p esp/loader

          # sd-boot at both canonical and UEFI fallback paths. Firmware
          # that isn't told about a specific EFI application falls back
          # to /EFI/BOOT/BOOTX64.EFI (removable-media convention); the
          # canonical path is /EFI/systemd/systemd-bootx64.efi. Under
          # Secure Boot both copies are db-signed (RFC-0006); the UKI is
          # already signed by aos-uki.
          if [ -n "$SB_ENABLE" ]; then
            echo "==> Signing sd-boot for Secure Boot"
            sbsign --key "$SB_KEY" --cert "$SB_CERT" \
              --output esp/EFI/BOOT/BOOTX64.EFI "$SDBOOT_DIR/systemd-bootx64.efi"
            cp esp/EFI/BOOT/BOOTX64.EFI esp/EFI/systemd/systemd-bootx64.efi
          else
            cp "$SDBOOT_DIR/systemd-bootx64.efi" esp/EFI/BOOT/BOOTX64.EFI
            cp "$SDBOOT_DIR/systemd-bootx64.efi" esp/EFI/systemd/systemd-bootx64.efi
          fi

          # UKI auto-discovered by sd-boot from /EFI/Linux/.
          cp "$UKI_PATH" esp/EFI/Linux/${ukiFilename}

          # sd-boot configuration. The default points at the image's
          # initial toplevel-hash UKI; apm rewrites this on generation
          # changes after first boot.
          cat > esp/loader/loader.conf <<LOADER
          default ${ukiFilename}
          timeout 3
          console-mode max
          editor no
          LOADER

          # ── 3. Create vfat ESP image ────────────────────────────────
          # FAT32 is what UEFI reads. mkfs.vfat has no -d flag, so we
          # create an empty image, then use mtools mcopy -s to populate
          # it from the esp/ directory — sandbox-compatible, no loopback
          # mount needed. MTOOLS_SKIP_CHECK=1 is required because mcopy
          # otherwise refuses to write to a plain file with no
          # ~/.mtoolsrc entry.
          # Size the ESP to its contents (UKI + sd-boot) x2 — headroom for an
          # A/B sysupdate staging a second UKI — plus 32 MiB FAT overhead,
          # rounded up to MiB and floored at 128 MiB (FAT32 minimum comfort).
          esp_content_kib=$(du -sk esp | cut -f1)
          esp_mib=$(( (esp_content_kib * 2 + 32768) / 1024 + 1 ))
          if [ "$esp_mib" -lt 128 ]; then esp_mib=128; fi
          esp_bytes=$(( esp_mib * 1048576 ))
          esp_sectors=$(( esp_bytes / 512 ))
          root_start_sector=$(( ${toString espStartSector} + esp_sectors ))

          echo "==> Creating vfat ESP image ($esp_mib MiB)"
          truncate -s "$esp_bytes" esp.img
          mkfs.vfat -F 32 -n ESP esp.img
          export MTOOLS_SKIP_CHECK=1
          for entry in esp/*; do
            mcopy -s -i esp.img "$entry" "::"
          done

          # ── 4. Assemble final GPT image ─────────────────────────────
          root_sectors=$(( root_bytes / 512 ))
          # 1 MiB (2048 sectors) at the start for GPT header + alignment,
          # plus 1 MiB at the end for the backup GPT header.
          disk_sectors=$(( root_start_sector + root_sectors + 2048 ))
          disk_bytes=$(( disk_sectors * 512 ))
          echo "==> Assembling $(( disk_bytes / 1048576 )) MiB GPT image"
          truncate -s "$disk_bytes" image.raw

          # Partition 1 is the ESP (type GUID C12A7328-…); partition 2
          # is the root A slot. Root B, swap, and /var are carved out of
          # the trailing unallocated space by ignition on first boot.
          sfdisk image.raw <<PTABLE
          label: gpt
          size=$esp_sectors, type=${espGuid}, name="ESP"
          size=$root_sectors, type=${linuxGuid}, name="root-a"
          PTABLE

          echo "    Writing ESP at sector ${toString espStartSector}"
          dd if=esp.img of=image.raw bs=512 seek=${toString espStartSector} conv=notrunc status=none
          echo "    Writing root at sector $root_start_sector"
          dd if=root.img of=image.raw bs=512 seek=$root_start_sector conv=notrunc status=none

          echo "$root_bytes" > root-size-bytes
          echo "$esp_mib" > esp-size-mib
          echo "==> Image assembly complete"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out
          mv image.raw $out/aos-${name}.img

          # Image metadata for downstream tooling (sysupdate later).
          root_size_bytes=$(cat root-size-bytes)
          root_size_mib=$(( root_size_bytes / 1048576 ))
          disk_size_bytes=$(stat -c %s "$out/aos-${name}.img")
          disk_size_mib=$(( disk_size_bytes / 1048576 ))
          esp_size_mib=$(cat esp-size-mib)
          cat > $out/image-info.json <<META
          {
            "name": "${name}",
            "version": "${version}",
            "diskSizeMiB": $disk_size_mib,
            "espSizeMiB": $esp_size_mib,
            "rootSizeMiB": $root_size_mib,
            "format": "raw",
            "partitionTable": "gpt",
            "kernelParams": "${kernelParams}",
            "partitions": [
              { "number": 1, "label": "ESP", "type": "esp", "filesystem": "vfat", "sizeMiB": $esp_size_mib },
              { "number": 2, "label": "root-a", "type": "linux", "filesystem": "${rootFsType}", "sizeMiB": $root_size_mib }
            ],
            "esp": {
              "uki": "EFI/Linux/${ukiFilename}",
              "sdBoot": "EFI/systemd/systemd-bootx64.efi"
            }
          }
          META
        '';
      }
    ];
  };
in
  imageDrv

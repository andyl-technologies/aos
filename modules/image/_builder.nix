##! modules/image/_builder.nix — AOS disk image builder (sandbox-compatible)
##!
##! Produces a UEFI-bootable GPT disk image from an evaluated AOS system
##! configuration. The image contains:
##!
##!   Partition 1 (ESP)    — vfat, sized to its contents x2 (A/B headroom)
##!                          EFI/BOOT/BOOTX64.EFI              (UEFI fallback)
##!                          EFI/systemd/systemd-bootx64.efi   (sd-boot canonical)
##!                          EFI/Linux/aos-<version>.efi       (UKI)
##!                          loader/loader.conf                (sd-boot config)
##!   Partition 2 (root-a) — rootFsType (erofs/ext4), sized to the rootfs image
##!
##! systemd-repart creates swap and /var partitions on first boot
##! in the unallocated space after root-a.
##!
##! Build strategy (no losetup/mount — fully sandbox-compatible):
##!   1. lib/build/rootfs.nix builds root.img (erofs or ext4, root-owned)
##!   2. aos-uki assembles vmlinuz + initrd + cmdline + os-release into a UKI
##!   3. Populate ESP tree (sd-boot + UKI + loader.conf)
##!   4. mkfs.vfat + mcopy → creates FAT32 ESP image
##!   5. sfdisk + dd → assembles partitions into final GPT image
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
  # Kernel command line parameters from the evaluated config.
  kernelParams = lib.concatStringsSep " " system.config.aos.boot.kernelParams;

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
  # Discoverable Partitions Spec root-verity GUID (x86-64). The root-a-hash
  # partition is discovered by partlabel either way, so the type GUID is
  # cosmetic; using the DPS verity type keeps the table self-describing.
  verityGuid = "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5";

  mkRootfs = import ../../lib/build/rootfs.nix;
  # The image's root filesystem matches the system's declared root fstype, so
  # the fstab/mount and the on-disk image agree. Production systems set this to
  # "erofs" (compressed, read-only) for a much smaller bootable image.
  rootFsType = system.config.aos.filesystems.rootFsType;

  # Secure Boot signing (RFC-0006). When enabled, the UKI and sd-boot
  # are Authenticode-signed with the deployment db key; otherwise the
  # image is the byte-reproducible unsigned artifact.
  sb = system.config.aos.boot.secureBoot;

  # dm-verity root anchoring, enabled by aos.security.verity.enable.
  # (modules/security/verity.nix, auto-loaded so the option always exists; false
  # for every ext4/VM-test system). When false, every verity branch below is
  # gated off and the image build is unchanged.
  verityEnabled = system.config.aos.security.verity.enable;

  rootfs = mkRootfs ({
      inherit pkgs lib system;
      pname = "aos-image-${name}-rootfs";
      label = "aos-root";
      fsType = rootFsType;
      shrinkToFit = true;
      headroomMiB = 64;
    }
    // lib.optionalAttrs verityEnabled {
      verity = true;
      # Sign the ASCII-hex roothash with the SB db key when SB is enabled (for
      # the optional in-kernel roothash-signature enforcement path). The
      # roothash-on-cmdline anchoring itself is key-independent.
      secureBootKey =
        if sb.enable
        then sb.dbKey
        else null;
      secureBootCert =
        if sb.enable
        then sb.dbCert
        else null;
    });

  uki = pkgs.aos-uki {
    inherit name version;
    kernel = system.config.system.build.kernel;
    initrd = system.config.system.build.initrd;
    cmdline = kernelParams;
    # The toplevel now ships a top-level `os-release` symlink (named-
    # output layout from spec v12 §1); the previous `etc/os-release`
    # path is gone along with the rest of `${toplevel}/etc/`.
    osRelease = "${system.config.system.build.toplevel}/os-release";
    secureBootKey =
      if sb.enable
      then sb.dbKey
      else null;
    secureBootCert =
      if sb.enable
      then sb.dbCert
      else null;
    # PCR-policy signing (RFC-0006 phase 3): when measured boot is on, the
    # UKI carries a signed PCR policy so TPM-sealed /var unseals across OTA.
    pcrPrivateKey =
      if sb.measuredBoot.enable
      then sb.measuredBoot.pcrPrivateKey
      else null;
    pcrPublicKey =
      if sb.measuredBoot.enable
      then sb.measuredBoot.pcrPublicKey
      else null;
    # Bake `roothash=<hex>` (a build output) into the measured
    # .cmdline. `null` when verity is off, so non-verity UKIs are unchanged.
    rootHashFile =
      if verityEnabled
      then "${rootfs}/root.roothash"
      else null;
  };

  ukiFilename = "aos-${name}-${version}.efi";

  # sd-boot boot-counting tries suffix for durable image
  # rollback. When `aos.boot.bootCountingTries` is set, the UKI staged into the
  # ESP is named `aos-<name>-<version>+<tries>.efi`; sd-boot decrements the
  # counter on each boot attempt and auto-demotes a UKI that fails to boot, so a
  # bad new image falls back to the other A/B slot without operator action.
  # Durable rollback to an older slot is `bootctl set-default` (apm, runtime),
  # NOT the lexically-highest `default aos-*.efi` glob, which stays only the
  # first-install fallback. The file inside the `uki` derivation keeps its
  # un-suffixed name; only the ESP copy carries the suffix.
  bootCountingTries = system.config.aos.boot.bootCountingTries;
  espUkiFilename =
    if bootCountingTries == null
    then ukiFilename
    else "aos-${name}-${version}+${toString bootCountingTries}.efi";

  imageDrv = pkgs.mkDerivation ({
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
      UKI_PATH = "${uki}/${ukiFilename}";
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

            # UKI auto-discovered by sd-boot from /EFI/Linux/. The ESP filename
            # carries the boot-counting tries suffix when enabled.
            cp "$UKI_PATH" esp/EFI/Linux/${espUkiFilename}

            # sd-boot configuration. The `default aos-*.efi` glob is the
            # FIRST-INSTALL FALLBACK only: it picks the lexically-highest match.
            # For A/B rollout, name UKIs with a boot-counting
            # tries-suffix (auto-demoting a bad new image) and pins durable
            # rollback via `bootctl set-default` at runtime, which overrides the
            # glob's lexical preference.
            cat > esp/loader/loader.conf <<LOADER
            default aos-*.efi
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
            # The dm-verity hash tree rides in a `root-a-hash`
            # partition immediately after root-a, sized from the build-time
            # root-verity-size-bytes and rounded up to a 1 MiB (2048-sector)
            # boundary. hash_sectors stays 0 (and the whole block is gated off)
            # on the non-verity path.
            hash_start_sector=$(( root_start_sector + root_sectors ))
            hash_sectors=0
            ${lib.optionalString verityEnabled ''
              verity_bytes=$(cat "$VERITY_SIZE_FILE")
              hash_sectors=$(( (verity_bytes + 511) / 512 ))
              hash_sectors=$(( (hash_sectors + 2047) / 2048 * 2048 ))
              echo "    root-a-hash: $(( hash_sectors / 2048 )) MiB verity tree"
            ''}
            # 1 MiB (2048 sectors) at the start for GPT header + alignment,
            # plus 1 MiB at the end for the backup GPT header.
            disk_sectors=$(( root_start_sector + root_sectors + hash_sectors + 2048 ))
            disk_bytes=$(( disk_sectors * 512 ))
            echo "==> Assembling $(( disk_bytes / 1048576 )) MiB GPT image"
            truncate -s "$disk_bytes" image.raw

            # Partition 1 is the ESP (type GUID C12A7328-…); partition 2
            # is the root A slot; partition 3 (verity only) is its dm-verity
            # hash tree. Root B, swap, and /var are carved out of the trailing
            # unallocated space by systemd-repart on first boot.
            sfdisk image.raw <<PTABLE
            label: gpt
            size=$esp_sectors, type=${espGuid}, name="ESP"
            size=$root_sectors, type=${linuxGuid}, name="root-a"${lib.optionalString verityEnabled ''

              size=$hash_sectors, type=${verityGuid}, name="root-a-hash"''}
            PTABLE

            echo "    Writing ESP at sector ${toString espStartSector}"
            dd if=esp.img of=image.raw bs=512 seek=${toString espStartSector} conv=notrunc status=none
            echo "    Writing root at sector $root_start_sector"
            dd if=root.img of=image.raw bs=512 seek=$root_start_sector conv=notrunc status=none
            ${lib.optionalString verityEnabled ''
              echo "    Writing root-a-hash at sector $hash_start_sector"
              dd if="$VERITY_IMG" of=image.raw bs=512 seek=$hash_start_sector conv=notrunc status=none
              echo "$(( hash_sectors / 2048 ))" > hash-size-mib
            ''}

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
            ${lib.optionalString verityEnabled ''hash_size_mib=$(cat hash-size-mib)''}
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
                { "number": 2, "label": "root-a", "type": "linux", "filesystem": "${rootFsType}", "sizeMiB": $root_size_mib }${lib.optionalString verityEnabled ''                ,
                              { "number": 3, "label": "root-a-hash", "type": "verity", "filesystem": "dm-verity", "sizeMiB": $hash_size_mib }''}
              ],
              "esp": {
                "uki": "EFI/Linux/${espUkiFilename}",
                "sdBoot": "EFI/systemd/systemd-bootx64.efi"
              }
            }
            META
          '';
        }
      ];
    }
    // lib.optionalAttrs verityEnabled {
      # Verity inputs are present only when verity is on, so the
      # non-verity image derivation's environment — and hash — is unchanged.
      VERITY_IMG = "${rootfs}/root.verity";
      VERITY_SIZE_FILE = "${rootfs}/root-verity-size-bytes";
    });
in
  # Expose the assembled UKI (the exact `.efi` written to the ESP) as a
  # passthru attribute so callers can publish or measure it directly
  # (RFC-0006 phase 4: `apr publish --image <uki>` derives Secure Boot
  # facts from this signed binary).
  imageDrv // {inherit uki;}

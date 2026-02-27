##! images/builder.nix — AOS disk image builder
##!
##! Produces a bootable GPT disk image from an evaluated AOS system
##! configuration. The image contains:
##!
##!   Partition 1 (ESP)  — FAT32, systemd-boot + kernel + initrd + boot entries
##!   Partition 2 (Root) — ext4, Nix store closure + system symlinks
##!   Remaining space    — unpartitioned (reserved for ZFS data pool at runtime)
##!
##! Arguments:
##!   pkgs     — AOS package set (provides util-linux, dosfstools, etc.)
##!   lib      — AOS library
##!   system   — evaluated system configuration (from evalModules)
##!   name     — image name slug (used in derivation name and boot entry)
##!   diskSize — total raw image size (e.g. "16G")
##!   espSize  — ESP partition size (e.g. "1G")
##!   rootSize — root partition size (e.g. "8G")
##!
##! Output: a single raw disk image file at $out
##!
##! NOTE: This derivation requires KVM for loop device access during the
##! build. It will not evaluate in a pure Nix sandbox without
##! requiredSystemFeatures = ["kvm"].
{
  pkgs,
  lib,
  system,
  name,
  diskSize ? "16G",
  espSize ? "1G",
  rootSize ? "8G",
}:
let
  # Compute the Nix store closure of the system toplevel. Every store
  # path reachable from the toplevel must be copied into the root
  # filesystem so the system can boot without a Nix daemon.
  closureInfo = pkgs.mkDerivation {
    name = "${name}-closure-info";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];

    phases = [
      {
        name = "compute-closure";
        script = ''
          mkdir -p $out

          # Enumerate every store path in the transitive closure.
          ${pkgs.coreutils}/bin/env nix-store \
            --query --requisites \
            ${system.config.system.build.toplevel} \
            > $out/store-paths

          # Record each path's on-disk size for progress reporting.
          while IFS= read -r p; do
            size=$(${pkgs.coreutils}/bin/du -sb "$p" | cut -f1)
            printf '%s\t%s\n' "$size" "$p"
          done < $out/store-paths > $out/store-info
        '';
      }
    ];
  };

  # Kernel command line parameters from the evaluated config.
  kernelParams = lib.concatStringsSep " " system.config.aos.boot.kernelParams;

  # systemd-boot EFI binary paths.
  systemdBootEfi = "${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi";

  version = system.config.aos.system.version;
in
pkgs.mkDerivation {
  name = "aos-image-${name}";

  # No source — this is a pure assembly step.
  src = null;

  buildDeps = [
    pkgs.util-linux # losetup, sgdisk (via sfdisk), partx
    pkgs.dosfstools # mkfs.fat
    pkgs.e2fsprogs # mkfs.ext4
    pkgs.coreutils # truncate, cp, mkdir, ln, cat
    pkgs.gzip # boot payload compression
  ];

  phases = [
    {
      name = "build-image";
      script = ''
        echo "==> Creating ${diskSize} raw disk image for AOS ${name}"

        # ── 1. Create empty raw image ──────────────────────────────────────
        truncate -s ${diskSize} image.raw

        # ── 2. Create GPT partition table ──────────────────────────────────
        # Partition 1: EFI System Partition (ESP)
        # Partition 2: Linux root filesystem
        # Remaining space is left unpartitioned for ZFS.
        sfdisk image.raw <<PTABLE
        label: gpt
        size=${espSize}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="ESP"
        size=${rootSize}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="Root"
        PTABLE

        # ── 3. Attach loop device with partition scanning ──────────────────
        LOOP=$(losetup --find --show --partscan image.raw)
        cleanup() {
          set +e
          umount /mnt/aos-esp  2>/dev/null
          umount /mnt/aos-root 2>/dev/null
          losetup -d "$LOOP"   2>/dev/null
        }
        trap cleanup EXIT

        # Wait for partition device nodes to appear.
        partprobe "$LOOP" 2>/dev/null || true
        udevadm settle 2>/dev/null || sleep 1

        # ── 4. Format partitions ───────────────────────────────────────────
        echo "==> Formatting ESP (FAT32)"
        mkfs.fat -F 32 -n ESP "''${LOOP}p1"

        echo "==> Formatting root (ext4, no journal for image build)"
        mkfs.ext4 -L aos-root -O ^has_journal -q "''${LOOP}p2"

        # ── 5. Mount filesystems ───────────────────────────────────────────
        mkdir -p /mnt/aos-root /mnt/aos-esp
        mount "''${LOOP}p2" /mnt/aos-root
        mount "''${LOOP}p1" /mnt/aos-esp

        # ── 6. Populate root from Nix store closure ────────────────────────
        echo "==> Copying Nix store closure to root filesystem"
        mkdir -p /mnt/aos-root/nix/store

        total=$(wc -l < ${closureInfo}/store-paths)
        count=0
        while IFS= read -r storePath; do
          count=$((count + 1))
          printf '\r    [%d/%d] %s' "$count" "$total" "$(basename "$storePath")"
          cp -a "$storePath" /mnt/aos-root"$storePath"
        done < ${closureInfo}/store-paths
        echo ""

        # ── 7. Create system directory structure ───────────────────────────
        echo "==> Setting up system directories"
        mkdir -p /mnt/aos-root/{etc,var,run,tmp,proc,sys,dev}
        mkdir -p /mnt/aos-root/var/{log,lib,tmp}
        mkdir -p /mnt/aos-root/run/current-system

        # Symlink the active system profile.
        ln -sfn ${system.config.system.build.toplevel} \
          /mnt/aos-root/run/current-system

        # Create /sbin/init symlink for PID 1 discovery.
        mkdir -p /mnt/aos-root/sbin
        ln -sfn ${pkgs.systemd}/lib/systemd/systemd /mnt/aos-root/sbin/init

        # ── 8. Install systemd-boot on ESP ─────────────────────────────────
        echo "==> Installing systemd-boot"
        mkdir -p /mnt/aos-esp/EFI/systemd
        mkdir -p /mnt/aos-esp/EFI/BOOT
        mkdir -p /mnt/aos-esp/loader/entries

        cp ${systemdBootEfi} /mnt/aos-esp/EFI/systemd/systemd-bootx64.efi
        cp ${systemdBootEfi} /mnt/aos-esp/EFI/BOOT/BOOTX64.EFI

        # Loader configuration: auto-select the single entry, 3s timeout.
        cat > /mnt/aos-esp/loader/loader.conf <<LOADER
        timeout 3
        default aos.conf
        editor no
        LOADER

        # ── 9. Write boot entry ────────────────────────────────────────────
        echo "==> Writing boot entry for AOS ${name} ${version}"
        cat > /mnt/aos-esp/loader/entries/aos.conf <<ENTRY
        title   AOS ${name} ${version}
        linux   /vmlinuz
        initrd  /initrd.img
        options ${kernelParams}
        ENTRY

        # ── 10. Copy kernel and initrd to ESP ──────────────────────────────
        echo "==> Copying kernel and initrd"
        cp ${system.config.system.build.kernel}/bzImage /mnt/aos-esp/vmlinuz
        cp ${system.config.system.build.initrd}/initrd.img /mnt/aos-esp/initrd.img

        # ── 11. Write machine-id placeholder ───────────────────────────────
        # Empty file signals systemd to generate a unique ID on first boot.
        touch /mnt/aos-root/etc/machine-id

        # ── 12. Unmount ────────────────────────────────────────────────────
        echo "==> Unmounting filesystems"
        umount /mnt/aos-esp
        umount /mnt/aos-root
        losetup -d "$LOOP"
        trap - EXIT

        echo "==> Image build complete"
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
        mv image.raw $out/aos-${name}.img

        # Write image metadata for downstream tooling.
        cat > $out/image-info.json <<META
        {
          "name": "${name}",
          "version": "${version}",
          "diskSize": "${diskSize}",
          "espSize": "${espSize}",
          "rootSize": "${rootSize}",
          "format": "raw",
          "partitionTable": "gpt",
          "partitions": [
            { "number": 1, "label": "ESP",  "type": "esp",  "filesystem": "fat32", "size": "${espSize}" },
            { "number": 2, "label": "Root", "type": "linux", "filesystem": "ext4",  "size": "${rootSize}" }
          ]
        }
        META
      '';
    }
  ];

  # Requires KVM for loop device access in the build sandbox.
  requiredSystemFeatures = [ "kvm" ];
}

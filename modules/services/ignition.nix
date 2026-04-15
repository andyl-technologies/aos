##! modules/services/ignition.nix — First-boot provisioning via Ignition
##!
##! Configures the Ignition first-boot provisioning tool. Ignition runs
##! inside the systemd-based initrd (`boot.initrd.systemd.services`)
##! before the real root is mounted at `/sysroot`. On a QEMU platform
##! Ignition reads its JSON config from the firmware-config device
##! (`/sys/firmware/qemu_fw_cfg/by_name/opt/com.coreos/config/raw`,
##! delivered via QEMU's `-fw_cfg name=opt/com.coreos/config,file=...`).
##!
##! A marker file at `/sysroot/boot/ignition.complete` guards against
##! re-execution: Ignition only runs when the marker is absent.
##!
##! Paired with:
##!   - `growfs-root.service`       — resize2fs after Ignition extends
##!                                    the root partition
##!   - `etc-overlay-setup.service` — /etc overlay + persistent
##!                                    machine-id/hostname/ssh links
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.services.ignition;

  # Ignition shells out to external tools at each stage: `modprobe`
  # to load qemu_fw_cfg, `mount`/`umount`, `sgdisk`/`blkid`/`wipefs`,
  # `mkfs.ext4`, etc. It looks them up via $PATH, so every service
  # needs the common sysutil dirs on PATH. Most of these tools ship
  # in sbin rather than bin (kmod, util-linux admin tools, e2fsprogs,
  # cryptsetup), so we concatenate bin + sbin across the relevant
  # packages via lib.makeBinPath / lib.makeSearchPath.
  # Ignition's per-stage commands come from internal/distro/distro.go
  # in the upstream repo: sgdisk (gptfdisk), partx/wipefs/mount/umount
  # (util-linux), modprobe (kmod), udevadm (systemd), mkfs.ext4
  # (e2fsprogs), mkfs.fat (dosfstools), cryptsetup, and a handful of
  # coreutils/bash staples.
  ignitionTools = [
    pkgs.kmod
    pkgs.util-linux
    pkgs.e2fsprogs
    pkgs.dosfstools
    pkgs.gptfdisk
    pkgs.cryptsetup
    pkgs.systemd
    pkgs.coreutils
    pkgs.bash
  ];
  ignitionPath = lib.concatStringsSep ":" [
    (lib.makeBinPath ignitionTools)
    (lib.makeSearchPath "sbin" ignitionTools)
  ];
in {
  options.aos.services.ignition = {
    ## Enable Ignition first-boot provisioning.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable Ignition first-boot provisioning. Ignition reads a JSON
        configuration from its platform source and applies it atomically
        during the initrd phase (partitioning, filesystem creation,
        file writes). If Ignition fails the system does not boot — no
        partially-configured machines.
      '';
    };

    ## Ignition platform name.
    platform = lib.mkOption {
      # Valid platform names come from the ignition binary itself —
      # `ignition --help` prints the full list under `-platform value`.
      # The enum is kept verbatim from ignition 2.25.1 so misspelling
      # a platform fails at eval time instead of at initrd boot.
      type = lib.types.enum [
        "akamai" "aliyun" "applehv" "aws" "azure" "azurestack"
        "brightbox" "cloudstack" "digitalocean" "exoscale" "file"
        "gcp" "hetzner" "hyperv" "ibmcloud" "kubevirt" "metal"
        "nutanix" "nvidiabluefield" "openstack" "oraclecloud"
        "packet" "powervs" "proxmoxve" "qemu" "scaleway" "upcloud"
        "virtualbox" "vmware" "vultr" "zvm"
      ];
      default = "qemu";
      description = ''
        Ignition platform passed as `--platform=<name>`. Determines how
        Ignition locates its config:
          - "qemu"      — QEMU fw_cfg device (used for VM testing)
          - "aws"/"gcp" — cloud instance metadata services
          - "metal"     — baremetal (systemd credentials or kargs)
        See https://coreos.github.io/ignition/supported-platforms/ for
        the full list.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Ignition ships the binary in every stage-2 installation too so
    # operators can re-run or inspect state after first boot.
    environment.systemPackages = [pkgs.ignition];

    # Initrd services. The cpio assembler in modules/base/initrd-builder.nix
    # picks these up via `system.build.systemdInitrdUnits`.
    #
    # Ignition runs as a sequence of stages (fetch → disks → mount →
    # files → umount). Upstream's dracut module splits each stage
    # into its own unit so they can be ordered around `sysroot.mount`
    # — disks happens before, mount/files after. Mirror that here.
    # See ignition/dracut/30ignition/*.service in the ignition repo.
    boot.initrd.systemd.services = {
      "ignition-fetch" = {
        description = "Ignition (fetch)";
        wantedBy = ["initrd-root-fs.target"];
        before = [
          "ignition-disks.service"
          "initrd-root-fs.target"
          "sysroot.mount"
        ];
        requires = [
          "systemd-modules-load.service"
          "systemd-udevd.service"
        ];
        after = [
          "systemd-modules-load.service"
          "systemd-udevd.service"
        ];
        # Ignition shells out to modprobe / mount / blkid etc. at each
        # stage; it expects to find them on PATH, not at absolute paths.
        # PATH is inherited in its entirety across services below.
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.ignition}/bin/ignition --platform=${cfg.platform} --root=/sysroot --stage=fetch --log-to-stdout";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };

      "ignition-disks" = {
        description = "Ignition (disks)";
        wantedBy = ["initrd-root-fs.target"];
        before = [
          "initrd-root-device.target"
          "initrd-root-fs.target"
          "sysroot.mount"
        ];
        requires = ["systemd-udevd.service"];
        after = [
          "ignition-fetch.service"
          "systemd-udevd.service"
        ];
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.ignition}/bin/ignition --platform=${cfg.platform} --root=/sysroot --stage=disks --log-to-stdout";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };

      "ignition-mount" = {
        description = "Ignition (mount)";
        wantedBy = ["initrd-fs.target"];
        before = [
          "ignition-files.service"
          "initrd-switch-root.target"
          "initrd-fs.target"
        ];
        requires = ["initrd-root-fs.target"];
        after = [
          "ignition-disks.service"
          "sysroot.mount"
          "initrd-root-fs.target"
        ];
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.ignition}/bin/ignition --platform=${cfg.platform} --root=/sysroot --stage=mount --log-to-stdout";
          # Run umount on service stop (i.e. during initrd-cleanup)
          # so filesystems ignition mounted are torn down cleanly
          # before switch_root. Matches upstream's ignition-mount.service.
          ExecStop = "${pkgs.ignition}/bin/ignition --platform=${cfg.platform} --root=/sysroot --stage=umount --log-to-stdout";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };

      "ignition-files" = {
        description = "Ignition (files)";
        wantedBy = ["initrd-fs.target"];
        before = [
          "initrd-parse-etc.service"
          "initrd-switch-root.target"
          "initrd-fs.target"
        ];
        after = ["ignition-mount.service"];
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          # Ignition writes its own stamp to /var/etc/.ignition-result.json
          # (compiled-in override of resultFilePath; see
          # pkgs/boot/ignition.nix). That stamp lives on the persistent
          # ext4 root, and on subsequent boots ignition detects it and
          # runs idempotently. No external marker file needed.
          ExecStart = "${pkgs.ignition}/bin/ignition --platform=${cfg.platform} --root=/sysroot --stage=files --log-to-stdout";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };

      # Ignition resizes the GPT partition entry for the root partition
      # (via `resize: true` in the storage.disks config) but does NOT
      # run resize2fs on the ext4 filesystem when `wipeFilesystem: false`.
      # Verified against internal/exec/stages/disks/filesystems.go:122-137
      # in the ignition source: with an existing matching filesystem,
      # ignition skips mkfs and leaves the filesystem at its original
      # size. So we grow the ext4 ourselves after ignition finishes.
      "growfs-root" = {
        description = "Grow Root Filesystem to Fill Partition";
        wantedBy = ["initrd-root-fs.target"];
        before = [
          "initrd-root-fs.target"
          "sysroot.mount"
        ];
        requires = [
          "ignition-disks.service"
          "systemd-udev-settle.service"
        ];
        after = [
          "ignition-disks.service"
          "systemd-udev-settle.service"
        ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.e2fsprogs}/sbin/resize2fs /dev/disk/by-partlabel/root";
        };
      };

      # /etc overlay: moves the image's /etc → /etc.lower on first boot,
      # mounts an overlayfs at /etc, and creates persistent symlinks for
      # state that must survive reboots (machine-id, hostname, SSH
      # host keys + authorized_keys). On subsequent boots /etc.lower
      # already exists and the mv is skipped.
      "etc-overlay-setup" = {
        description = "Set Up /etc Overlay Filesystem";
        wantedBy = ["initrd-fs.target"];
        before = [
          "initrd-fs.target"
          "initrd-switch-root.target"
        ];
        requires = [
          "sysroot.mount"
          "growfs-root.service"
        ];
        after = [
          "sysroot.mount"
          "growfs-root.service"
          "initrd-root-fs.target"
        ];
        # The script below shells out to coreutils (mv, mkdir, ln) and
        # util-linux (mount) without absolute paths, so PATH has to
        # include both. Without this, systemd gives the service its
        # default PATH (/usr/bin:/bin:/usr/sbin:/sbin) which doesn't
        # find any AOS-built binary and each lookup returns 127.
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          sysroot=/sysroot

          # 1. Move the image's /etc aside on first boot.
          if [ ! -d "$sysroot/etc.lower" ]; then
            mv "$sysroot/etc" "$sysroot/etc.lower"
            mkdir -p "$sysroot/etc"
          fi

          # 2. Tmpfs upper-layer directories (inside the future /run).
          mkdir -p "$sysroot/run/etc-upper/upper"
          mkdir -p "$sysroot/run/etc-upper/work"

          # 3. Persistent storage skeleton on the root partition.
          mkdir -p "$sysroot/var/etc/ssh/authorized_keys"

          # 4. Mount the overlay — /etc becomes a union of the immutable
          #    image /etc.lower and the volatile /run/etc-upper/upper.
          ${pkgs.util-linux}/bin/mount -t overlay overlay \
            -o lowerdir="$sysroot/etc.lower",upperdir="$sysroot/run/etc-upper/upper",workdir="$sysroot/run/etc-upper/work" \
            "$sysroot/etc"

          # 5. Persistent symlinks. Ignition writes the files directly
          #    to /sysroot/var/etc/* (the JSON config uses /var/etc
          #    paths), so all we do here is point the canonical /etc
          #    names at them. Every file is one symlink target in
          #    /var/etc/, which is persistent ext4 on the root part.
          for f in machine-id hostname; do
            ln -sfn "/var/etc/$f" "$sysroot/etc/$f"
          done

          # SSH host keys: sshd-keygen writes these directly to
          # /var/etc/ssh/ on first boot. Pointing /etc/ssh/ssh_host_*
          # at /var/etc/ssh/ keeps them persistent. sshd_config itself
          # stays in the immutable lower layer, so we symlink per-leaf
          # rather than the whole /etc/ssh. Only ed25519 is used; RSA
          # and ECDSA are disabled at the sshd_config level.
          for name in ssh_host_ed25519_key ssh_host_ed25519_key.pub; do
            ln -sfn "/var/etc/ssh/$name" "$sysroot/etc/ssh/$name"
          done

          # authorized_keys: Ignition writes /var/etc/ssh/authorized_keys/root
          # so sshd's `AuthorizedKeysFile /etc/ssh/authorized_keys/%u` resolves
          # to the persistent copy via this directory-level symlink.
          ln -sfn "/var/etc/ssh/authorized_keys" "$sysroot/etc/ssh/authorized_keys"
        '';
      };
    };
  };
}

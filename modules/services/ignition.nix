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
##!   - `mount-var.service`         — mounts /var partition (created by
##!                                    Ignition) before ignition-files so
##!                                    writes to /var/etc/* succeed; the
##!                                    mount persists through switch-root
##!   - `etc-overlay-setup.service` — /etc overlay with /var/etc as an
##!                                    additional lower layer
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

      # Mount the /var partition created by ignition-disks so that
      # ignition-files can write to /sysroot/var/etc/* and the mount
      # persists through switch-root into stage-2 (no ExecStop).
      # Stage-2 systemd sees the existing mount and considers its
      # fstab-generated var.mount unit already active.
      "mount-var" = {
        description = "Mount /var Partition";
        wantedBy = ["initrd-fs.target"];
        before = [
          "ignition-files.service"
          "etc-overlay-setup.service"
          "initrd-fs.target"
        ];
        requires = [
          "sysroot.mount"
          "ignition-disks.service"
        ];
        after = [
          "sysroot.mount"
          "ignition-disks.service"
          "systemd-udev-settle.service"
        ];
        unitConfig = {
          ConditionPathExists = "/dev/disk/by-partlabel/var";
        };
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          if ! mountpoint -q /sysroot/var; then
            mkdir -p /sysroot/var
            mount /dev/disk/by-partlabel/var /sysroot/var
          fi
          # Standard /var subdirectories expected by systemd and daemons.
          mkdir -p /sysroot/var/{log,lib,tmp}
          # /var/run → /run is the modern-Linux convention; many daemons
          # (dbus, various PID files) still reference /var/run paths.
          ln -sfn /run /sysroot/var/run
        '';
      };

      # /etc overlay: moves the image's /etc → /etc.lower on first boot,
      # then mounts an overlayfs at /etc with two lower layers:
      #   1. /var/etc   — persistent state written by ignition (shadows)
      #   2. /etc.lower — immutable image /etc
      # The upper layer is a tmpfs under /run so runtime writes to /etc
      # are not persisted across reboots.
      "etc-overlay-setup" = {
        description = "Set Up /etc Overlay Filesystem";
        wantedBy = ["initrd-fs.target"];
        before = [
          "initrd-fs.target"
          "initrd-switch-root.target"
        ];
        requires = [
          "sysroot.mount"
          "mount-var.service"
          "ignition-files.service"
        ];
        after = [
          "sysroot.mount"
          "mount-var.service"
          "ignition-files.service"
          "initrd-root-fs.target"
        ];
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          sysroot=/sysroot

          # 1. First-boot setup: move /etc aside and create the
          #    /run/etc-upper mountpoint. Root is read-only so we
          #    remount rw briefly for these on-disk changes.
          needs_rw=false
          if [ ! -d "$sysroot/etc.lower" ]; then needs_rw=true; fi
          if [ ! -d "$sysroot/run/etc-upper" ]; then needs_rw=true; fi

          if [ "$needs_rw" = true ]; then
            mount -o remount,rw "$sysroot"
            if [ ! -d "$sysroot/etc.lower" ]; then
              mv "$sysroot/etc" "$sysroot/etc.lower"
              mkdir -p "$sysroot/etc"
            fi
            mkdir -p "$sysroot/run/etc-upper"
            mount -o remount,ro "$sysroot"
          fi

          # 2. Tmpfs for the overlay upper/work dirs. The mountpoint
          #    on the root ext4 means this appears as a sibling of /run
          #    in findmnt rather than nested — cosmetic only, the overlay
          #    functions correctly either way.
          if ! mountpoint -q "$sysroot/run/etc-upper"; then
            mount -t tmpfs -o nosuid,nodev,mode=755 tmpfs "$sysroot/run/etc-upper"
          fi
          mkdir -p "$sysroot/run/etc-upper/upper"
          mkdir -p "$sysroot/run/etc-upper/work"

          # 3. Ensure /var/etc exists on the persistent /var partition.
          mkdir -p "$sysroot/var/etc/ssh/authorized_keys"

          # 4. Mount the overlay. /var/etc is listed first so its files
          #    shadow /etc.lower; the tmpfs upper captures runtime writes.
          ${pkgs.util-linux}/bin/mount -t overlay overlay \
            -o nosuid,nodev,lowerdir="$sysroot/var/etc:$sysroot/etc.lower",upperdir="$sysroot/run/etc-upper/upper",workdir="$sysroot/run/etc-upper/work" \
            "$sysroot/etc"
        '';
      };
    };
  };
}

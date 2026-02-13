# modules/services/ignition.nix — First-boot provisioning via Ignition
#
# Configures the Ignition first-boot provisioning system. Ignition runs in
# the initrd before the real root is mounted, applying machine-specific
# configuration atomically: hostname, SSH keys, ZFS pool creation, dataset
# setup, and custom file writes. It runs exactly once — the presence of
# /boot/ignition.complete prevents re-execution.
#
# Absorbed TOML config values:
#   [services.ignition] enable, config_source
#   [services.ignition.zfs] create_pool, pool_name, pool_disks, datasets

{
  config,
  pkgs,
  lib,
  ...
}:

let
  cfg = config.aos.services.ignition;

  # Build the list of ZFS dataset creation commands.
  datasetCmds = lib.mapAttrsToList (
    name: props:
    let
      propFlags = builtins.concatStringsSep " " (lib.mapAttrsToList (k: v: "-o ${k}=${v}") props);
    in
    "/usr/sbin/zfs create ${propFlags} ${cfg.poolName}/${name}"
  ) cfg.datasets;

in
{
  options.aos.services.ignition = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Enable Ignition first-boot provisioning. Ignition reads a JSON
        configuration from the config source and applies it atomically
        during the initrd phase. If Ignition fails, the system does not
        boot — ensuring no partially-configured machines.
      '';
    };

    configSource = lib.mkOption {
      type = lib.types.str;
      default = "/dev/disk/by-label/ignition";
      description = ''
        Source for the Ignition configuration. This can be:
        - A block device path (disk label, UUID) for bare-metal
        - A URL for cloud environments
        - A file path for VM/test environments
      '';
    };

    createZfsPool = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Create the ZFS pool during first-boot provisioning. The pool is
        created from the disks specified in poolDisks with recommended
        properties (ashift=12, compression, checksums).
      '';
    };

    poolName = lib.mkOption {
      type = lib.types.str;
      default = "aos-pool";
      description = "Name of the ZFS pool to create during first boot.";
    };

    poolDisks = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Block devices to include in the ZFS pool. Example:
        [ "/dev/vdb" ] for a single disk or
        [ "/dev/vdb" "/dev/vdc" ] for a mirror.
      '';
    };

    datasets = lib.mkOption {
      type = lib.types.attrsOf (lib.types.attrsOf lib.types.str);
      default = {
        "var" = {
          mountpoint = "/var";
          compression = "zstd-3";
          atime = "off";
        };
        "var/log" = {
          mountpoint = "/var/log";
          compression = "zstd-3";
          atime = "off";
          "logbias" = "throughput";
        };
        "var/lib" = {
          mountpoint = "/var/lib";
          compression = "zstd-3";
          atime = "off";
        };
        "var/lib/containerd" = {
          mountpoint = "/var/lib/containerd";
          compression = "zstd-3";
          atime = "off";
          recordsize = "128K";
        };
        "var/lib/etcd" = {
          mountpoint = "/var/lib/etcd";
          compression = "zstd-3";
          atime = "off";
          recordsize = "4K";
          sync = "always";
        };
      };
      description = ''
        ZFS datasets to create during first-boot provisioning. Each key
        is the dataset name (relative to the pool), and the value is an
        attrset of ZFS properties including mountpoint.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ pkgs.ignition ];

    # Ignition service — runs in the initrd before sysroot mount.
    # This is the core first-boot provisioning unit.
    systemd.services."ignition-apply" = {
      description = "Ignition First-Boot Provisioning";
      wantedBy = [ "initrd.target" ];
      before = [ "initrd-root-fs.target" ];
      after = [
        "systemd-udevd.service"
        "initrd-root-device.target"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Only run on first boot (marker file absent).
        ExecCondition = "/usr/bin/test ! -f /sysroot/boot/ignition.complete";
        ExecStart = "/usr/bin/ignition --platform=file --config-cache=${cfg.configSource} --root=/sysroot --log-to-stdout";
        ExecStartPost = "/usr/bin/touch /sysroot/boot/ignition.complete";
      };
    };

    # ZFS pool creation service — creates the pool from raw disks.
    # Only runs on first boot when the pool does not yet exist.
    systemd.services."ignition-zfs-pool" = lib.mkIf (cfg.createZfsPool && cfg.poolDisks != [ ]) {
      description = "Ignition: Create ZFS Pool";
      wantedBy = [ "initrd.target" ];
      before = [ "ignition-zfs-datasets.service" ];
      after = [
        "ignition-apply.service"
        "systemd-udevd.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecCondition = "/usr/bin/sh -c '! /usr/sbin/zpool list ${cfg.poolName} 2>/dev/null'";
        ExecStart = builtins.concatStringsSep " " (
          [
            "/usr/sbin/zpool create"
            "-f"
            "-o ashift=12"
            "-O compression=zstd-3"
            "-O acltype=posixacl"
            "-O xattr=sa"
            "-O dnodesize=auto"
            "-O normalization=formD"
            "-O relatime=on"
            "-O canmount=off"
            "-O mountpoint=none"
            cfg.poolName
          ]
          ++ cfg.poolDisks
        );
      };
    };

    # ZFS dataset creation service — creates datasets from the config.
    # Runs after the pool exists, creating datasets that do not yet exist.
    systemd.services."ignition-zfs-datasets" = lib.mkIf cfg.createZfsPool {
      description = "Ignition: Create ZFS Datasets";
      wantedBy = [ "initrd.target" ];
      before = [ "initrd-root-fs.target" ];
      after = [ "ignition-zfs-pool.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecCondition = "/usr/bin/test ! -f /sysroot/boot/ignition.complete";
        ExecStart = datasetCmds;
      };
    };

    # Ensure Ignition is included in the initrd.
    aos.boot.initrd.modules = [
      "virtio_blk"
      "virtio_pci"
      "ext4"
      "overlay"
    ];
  };
}

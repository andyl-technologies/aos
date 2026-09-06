##! modules/services/zfs-auto-snapshot.nix — Retained ZFS snapshots
##!
##! Schedules zfstools snapshot and expiry runs for named retention intervals.
##! Datasets can be selected here or through the compatible
##! `com.sun:auto-snapshot` ZFS property managed by another tool.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.zfsAutoSnapshot;
  intervalNames = builtins.attrNames cfg.intervals;
  enabledIntervals = builtins.filter (name: cfg.intervals.${name}.enable) intervalNames;
  nonnegativeInt = lib.types.addCheck lib.types.int (value: value >= 0);
  unitName = name: "zfs-auto-snapshot-${name}";
  mkService = name: {
    name = unitName name;
    value = {
      description = "Create and expire ${name} ZFS snapshots";
      after = ["zfs-mount.service"];
      wants = ["zfs-mount.service"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart =
          "${pkgs.zfstools}/bin/zfs-auto-snapshot"
          + lib.optionalString cfg.utc " --utc"
          + lib.optionalString cfg.parallel " --parallel-snapshots"
          + " ${lib.escapeShellArg name} ${toString cfg.intervals.${name}.keep}";
        Nice = 10;
        IOSchedulingClass = "idle";
        LockPersonality = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
      };
    };
  };
  mkTimer = name: {
    name = unitName name;
    value = {
      description = "Schedule ${name} ZFS snapshots";
      wantedBy = ["timers.target"];
      timerConfig = {
        OnCalendar = cfg.intervals.${name}.calendar;
        Persistent = true;
        RandomizedDelaySec = cfg.randomizedDelaySec;
        Unit = "${unitName name}.service";
      };
    };
  };
  intervalType = lib.types.submodule {
    options = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Schedule this snapshot interval.";
      };
      calendar = lib.mkOption {
        type = lib.types.str;
        description = "systemd calendar expression for this interval.";
      };
      keep = lib.mkOption {
        type = nonnegativeInt;
        description = "Number of snapshots retained for this interval.";
      };
    };
  };
in {
  options.aos.services.zfsAutoSnapshot = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Create and expire retained ZFS snapshots on a schedule.";
    };

    datasets = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "ZFS datasets marked for automatic snapshots.";
    };

    intervals = lib.mkOption {
      type = lib.types.attrsOf intervalType;
      default = {
        frequent = {
          calendar = "*:0/15";
          keep = 4;
        };
        hourly = {
          calendar = "hourly";
          keep = 24;
        };
        daily = {
          calendar = "daily";
          keep = 7;
        };
        weekly = {
          calendar = "weekly";
          keep = 4;
        };
        monthly = {
          calendar = "monthly";
          keep = 12;
        };
      };
      description = "Named snapshot schedules and retention counts.";
    };

    utc = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Use UTC in generated snapshot names.";
    };

    parallel = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Create independent dataset snapshots concurrently.";
    };

    randomizedDelaySec = lib.mkOption {
      type = lib.types.str;
      default = "5m";
      description = "Maximum randomized delay applied to timer runs.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions =
      [
        {
          assertion = config.aos.filesystems.zfs.enable;
          message = "aos.services.zfsAutoSnapshot requires aos.filesystems.zfs.enable";
        }
        {
          assertion = enabledIntervals != [];
          message = "aos.services.zfsAutoSnapshot requires at least one enabled interval";
        }
      ]
      ++ map (name: {
        assertion = builtins.match "[A-Za-z0-9_-]+" name != null;
        message = "ZFS snapshot interval names may contain only letters, digits, '_' and '-'";
      })
      intervalNames;

    environment.systemPackages = [pkgs.zfstools];

    systemd.services =
      builtins.listToAttrs (map mkService enabledIntervals)
      // lib.optionalAttrs (cfg.datasets != []) {
        zfs-auto-snapshot-prepare = {
          description = "Select datasets for automatic ZFS snapshots";
          wantedBy = ["multi-user.target"];
          after = ["zfs-mount.service"];
          requires = ["zfs-mount.service"];
          before = map (name: "${unitName name}.service") enabledIntervals;
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script =
            lib.concatMapStringsSep "\n" (dataset: ''
              ${config.aos.filesystems.zfs.package}/sbin/zfs set \
                com.sun:auto-snapshot=true ${lib.escapeShellArg dataset}
            '')
            cfg.datasets;
        };
      };

    systemd.timers = builtins.listToAttrs (map mkTimer enabledIntervals);
  };
}

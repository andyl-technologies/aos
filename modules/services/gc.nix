##! modules/services/gc.nix — Store garbage collection module
##!
##! Periodically removes old OS generations and unused store paths to reclaim
##! disk space. Runs on a systemd timer and keeps a configurable number of
##! generations for rollback safety.
##!
##! Absorbed TOML config values:
##!   [gc] enable, schedule, keep_generations, older_than

{
  config,
  pkgs,
  lib,
  ...
}:

let
  cfg = config.aos.gc;
in
{
  options.aos.gc = {
    ## Enable periodic garbage collection of old OS generations.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable periodic garbage collection of old OS generations.";
    };

    ## systemd calendar expression for when garbage collection runs.
    schedule = lib.mkOption {
      type = lib.types.str;
      default = "weekly";
      description = ''
        systemd calendar expression for when garbage collection runs.
        Examples: "weekly", "daily", "Mon *-*-* 03:00:00".
      '';
    };

    ## Number of recent OS generations to keep for rollback.
    keepGenerations = lib.mkOption {
      type = lib.types.int;
      default = 5;
      description = ''
        Number of recent OS generations to keep. At least this many
        generations will always be available for rollback, regardless
        of the olderThan setting.
      '';
    };

    ## Minimum age for a generation to be eligible for garbage collection.
    olderThan = lib.mkOption {
      type = lib.types.str;
      default = "7d";
      description = ''
        Minimum age for a generation to be eligible for garbage collection.
        Format: number followed by unit (d=days, h=hours, m=minutes).
        Generations newer than this are never collected, even if they
        exceed keepGenerations.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # gc.timer — periodic garbage collection trigger.
    systemd.timers."aos-gc" = {
      description = "AOS Store Garbage Collection Timer";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.schedule;
        RandomizedDelaySec = "1h";
        Persistent = true;
      };
    };

    # gc.service — performs the actual garbage collection.
    systemd.services."aos-gc" = {
      description = "AOS Store Garbage Collection";
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "oneshot";
        # Remove generations older than the threshold, keeping at least
        # keepGenerations for rollback. Then collect unreferenced store paths.
        ExecStart = builtins.concatStringsSep " " [
          "${pkgs.aos-gc}/bin/aos-gc"
          "--keep=${toString cfg.keepGenerations}"
          "--older-than=${cfg.olderThan}"
        ];
        # GC can be I/O intensive; run at low priority.
        IOSchedulingClass = "idle";
        Nice = 19;
        CPUSchedulingPolicy = "idle";
      };
    };
  };
}

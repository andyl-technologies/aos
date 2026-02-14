# modules/services/aos-serve.nix — AOS binary cache server module
#
# Runs the `aos serve` HTTP binary cache server as a long-lived systemd
# service, with optional periodic garbage collection of cache views.
#
# Absorbed TOML config values:
#   [serve] enable, config_file, user, group
#   [serve.gc] schedule, views

{
  config,
  pkgs,
  lib,
  ...
}:

let
  cfg = config.aos.serve;
in
{
  options.aos.serve = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the AOS binary cache server.";
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      default = "/etc/aos/serve.toml";
      description = "Path to the aos serve configuration file.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "aos-serve";
      description = "User account under which the cache server runs.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "nix-daemon";
      description = ''
        Primary group for the cache server process. Defaults to nix-daemon
        so the server can read the Nix store.
      '';
    };

    gcSchedule = lib.mkOption {
      type = lib.types.str;
      default = "weekly";
      description = ''
        systemd calendar expression for when cache garbage collection runs.
        Examples: "weekly", "daily", "Mon *-*-* 03:00:00".
      '';
    };

    gcViews = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        List of cache views to garbage-collect on the timer schedule.
        Each view will be passed to `aos gc --view VIEW --collect`.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # System user for the cache server.
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = "/var/lib/aos";
      description = "AOS binary cache server";
    };

    # Supplementary group for token bootstrap administration.
    users.groups.aos-admins = { };

    # aos-serve.service — long-lived HTTP binary cache server.
    systemd.services."aos-serve" = {
      description = "AOS Binary Cache Server";
      after = [
        "network.target"
        "local-fs.target"
      ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${pkgs.aos}/bin/aos serve --config ${cfg.configFile}";
        User = cfg.user;
        Group = cfg.group;
        SupplementaryGroups = [ "aos-admins" ];
        KillMode = "mixed";
        TimeoutStopSec = 90;
        Restart = "on-failure";
        RestartSec = 5;
        ReadWritePaths = [
          "/var/lib/aos"
          "/run/aos"
        ];
        RuntimeDirectory = "aos";
        StateDirectory = "aos";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
      };
    };

    # aos-serve-gc.service — oneshot garbage collection of cache views.
    systemd.services."aos-serve-gc" = lib.mkIf (cfg.gcViews != [ ]) {
      description = "AOS Cache Server Garbage Collection";
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = builtins.map (view: "${pkgs.aos}/bin/aos gc --view ${view} --collect") cfg.gcViews;
        User = cfg.user;
        Group = cfg.group;
        IOSchedulingClass = "idle";
        Nice = 19;
      };
    };

    # aos-serve-gc.timer — periodic trigger for cache GC.
    systemd.timers."aos-serve-gc" = lib.mkIf (cfg.gcViews != [ ]) {
      description = "AOS Cache Server Garbage Collection Timer";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.gcSchedule;
        RandomizedDelaySec = "1h";
        Persistent = true;
      };
    };

    # System activation — create required directories and GC root symlink.
    system.activationScripts.aos-serve = ''
      install -d -o ${cfg.user} -g ${cfg.group} -m 0750 \
        /var/lib/aos/store \
        /var/lib/aos/gcroots \
        /var/lib/aos/meta \
        /var/lib/aos/views \
        /var/lib/aos/var/nix/db \
        /var/lib/aos/var/nix/gcroots
      install -d -m 0755 /etc/aos
      install -d -m 0755 /run/aos
      ln -sfn /var/lib/aos/gcroots /var/lib/aos/var/nix/gcroots/aos
    '';
  };
}

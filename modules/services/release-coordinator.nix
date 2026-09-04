##! modules/services/release-coordinator.nix — Canonical release maintainer services.
##!
##! Provides a manually started content-release coordinator plus independently
##! scheduled timestamp, backup, and restore-verification jobs. Deployment
##! configuration supplies hermetic wrapper programs and credential source
##! paths; neither secrets nor maintainer-machine identities enter the store.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.releaseCoordinator;
  absolutePath = lib.types.strMatching "/.*";
  optionalProgram = lib.types.nullOr absolutePath;
  credentialSet = lib.types.attrsOf absolutePath;
  renderCredentials = credentials:
    lib.mapAttrsToList (name: path: "${name}:${path}") credentials;
  credentialNames =
    builtins.attrNames cfg.releaseCredentials
    ++ builtins.attrNames cfg.timestampCredentials
    ++ builtins.attrNames cfg.backupCredentials
    ++ builtins.attrNames cfg.alertCredentials;
  credentialPaths =
    builtins.attrValues cfg.releaseCredentials
    ++ builtins.attrValues cfg.timestampCredentials
    ++ builtins.attrValues cfg.backupCredentials
    ++ builtins.attrValues cfg.alertCredentials;
  hardened = {
    Type = "oneshot";
    NoNewPrivileges = true;
    PrivateTmp = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = ["@system-service" "~@mount" "~@reboot" "~@swap"];
    SystemCallErrorNumber = "EPERM";
    UMask = "0077";
  };
  networked =
    hardened
    // {
      RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
    };
  timerDefaults = {
    Persistent = true;
    AccuracySec = "1m";
    RandomizedDelaySec = "5m";
  };
in {
  options.aos.services.releaseCoordinator = {
    enable = lib.mkEnableOption "canonical AOS release maintainer services";

    releaseProgram = lib.mkOption {
      type = optionalProgram;
      default = null;
      description = ''
        Absolute path to the hermetic, deployment-specific content-release
        wrapper. Operators start aos-release-coordinator.service manually.
      '';
    };

    timestampProgram = lib.mkOption {
      type = optionalProgram;
      default = null;
      description = ''
        Absolute path to the hermetic wrapper that refreshes and publishes only
        an already-authorized TUF snapshot.
      '';
    };

    backupProgram = lib.mkOption {
      type = optionalProgram;
      default = null;
      description = ''
        Absolute path to the hermetic encrypted-backup wrapper. It receives
        read-only access to release and timestamp state.
      '';
    };

    restoreCheckProgram = lib.mkOption {
      type = optionalProgram;
      default = null;
      description = ''
        Absolute path to the hermetic clean-directory restore verification
        wrapper. A successful exit must prove restored evidence integrity.
      '';
    };

    alertProgram = lib.mkOption {
      type = optionalProgram;
      default = null;
      description = ''
        Absolute path to the hermetic operator-alert wrapper. systemd passes
        the failed unit name as its sole argument.
      '';
    };

    releaseCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = "Credential source files loaded only for a manual release operation.";
    };

    timestampCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = "Restricted credential source files loaded only for timestamp renewal.";
    };

    backupCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = "Credential source files loaded only for encrypted backup.";
    };

    alertCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = "Credential source files loaded only for release-operation alerts.";
    };

    timestampCalendar = lib.mkOption {
      type = lib.types.str;
      default = "*-*-* 00/12:00:00";
      description = "systemd calendar for short-lived TUF timestamp renewal.";
    };

    backupCalendar = lib.mkOption {
      type = lib.types.str;
      default = "*-*-* 02:00:00";
      description = "systemd calendar for encrypted release-state backups.";
    };

    restoreCheckCalendar = lib.mkOption {
      type = lib.types.str;
      default = "Mon *-*-* 04:00:00";
      description = "systemd calendar for unattended backup restore verification.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.releaseProgram != null;
        message = "releaseCoordinator.releaseProgram must be configured";
      }
      {
        assertion = cfg.timestampProgram != null;
        message = "releaseCoordinator.timestampProgram must be configured";
      }
      {
        assertion = cfg.backupProgram != null;
        message = "releaseCoordinator.backupProgram must be configured";
      }
      {
        assertion = cfg.restoreCheckProgram != null;
        message = "releaseCoordinator.restoreCheckProgram must be configured";
      }
      {
        assertion = cfg.alertProgram != null;
        message = "releaseCoordinator.alertProgram must be configured";
      }
      {
        assertion = builtins.length credentialPaths == builtins.length (lib.unique credentialPaths);
        message = "release, timestamp, and backup services must use disjoint credential files";
      }
      {
        assertion = builtins.all (name: builtins.match "[A-Za-z0-9_.-]+" name != null) credentialNames;
        message = "release coordinator credential names contain unsupported characters";
      }
      {
        assertion = builtins.all (path: !lib.hasPrefix "/nix/store/" path) credentialPaths;
        message = "release coordinator credentials must not be sourced from the Nix store";
      }
    ];

    aos.users.groups = {
      aos-release = {
        gid = 803;
        members = [];
      };
      aos-release-timestamp = {
        gid = 804;
        members = [];
      };
      aos-release-backup = {
        gid = 805;
        members = [];
      };
      aos-release-monitor = {
        gid = 806;
        members = [];
      };
      aos-release-lock = {
        gid = 807;
        members = [];
      };
    };
    aos.users.users = {
      aos-release = {
        uid = 803;
        group = "aos-release";
        home = "/var/lib/aos-release-coordinator";
        shell = "/sbin/nologin";
        description = "AOS content release coordinator";
        extraGroups = ["aos-release-lock"];
      };
      aos-release-timestamp = {
        uid = 804;
        group = "aos-release-timestamp";
        home = "/var/lib/aos-release-timestamp";
        shell = "/sbin/nologin";
        description = "AOS TUF timestamp renewal";
        extraGroups = [];
      };
      aos-release-backup = {
        uid = 805;
        group = "aos-release-backup";
        home = "/var/lib/aos-release-backup";
        shell = "/sbin/nologin";
        description = "AOS release backup and restore verification";
        extraGroups = ["aos-release" "aos-release-timestamp" "aos-release-lock"];
      };
      aos-release-monitor = {
        uid = 806;
        group = "aos-release-monitor";
        home = "/var/lib/aos-release-monitor";
        shell = "/sbin/nologin";
        description = "AOS release operation alerts";
        extraGroups = [];
      };
    };

    environment.etc."tmpfiles.d/aos-release-coordinator.conf".text = ''
      d /run/lock/aos-release 0770 root aos-release-lock - -
    '';

    systemd.services.aos-release-coordinator = {
      description = "Run one reviewed canonical AOS content release operation";
      after = ["network-online.target"];
      wants = ["network-online.target"];
      unitConfig.OnFailure = ["aos-release-alert@%n.service"];
      serviceConfig =
        networked
        // {
          ExecStart = "${pkgs.util-linux}/bin/flock --exclusive --nonblock /run/lock/aos-release/coordinator.lock ${cfg.releaseProgram}";
          User = "aos-release";
          Group = "aos-release";
          StateDirectory = "aos-release-coordinator";
          StateDirectoryMode = "0750";
          RuntimeDirectory = "aos-release-coordinator";
          RuntimeDirectoryMode = "0700";
          WorkingDirectory = "/var/lib/aos-release-coordinator";
          LoadCredential = renderCredentials cfg.releaseCredentials;
          TimeoutStartSec = "7d";
        };
    };

    systemd.services.aos-release-timestamp = {
      description = "Refresh the authorized AOS TUF timestamp";
      after = ["network-online.target"];
      wants = ["network-online.target"];
      unitConfig.OnFailure = ["aos-release-alert@%n.service"];
      serviceConfig =
        networked
        // {
          ExecStart = cfg.timestampProgram;
          User = "aos-release-timestamp";
          Group = "aos-release-timestamp";
          StateDirectory = "aos-release-timestamp";
          StateDirectoryMode = "0750";
          RuntimeDirectory = "aos-release-timestamp";
          RuntimeDirectoryMode = "0700";
          WorkingDirectory = "/var/lib/aos-release-timestamp";
          LoadCredential = renderCredentials cfg.timestampCredentials;
          TimeoutStartSec = "15m";
        };
    };
    systemd.timers.aos-release-timestamp = {
      description = "Renew the AOS TUF timestamp before expiry";
      wantedBy = ["timers.target"];
      timerConfig = timerDefaults // {OnCalendar = cfg.timestampCalendar;};
    };

    systemd.services.aos-release-backup = {
      description = "Back up canonical AOS release evidence";
      unitConfig.OnFailure = ["aos-release-alert@%n.service"];
      serviceConfig =
        networked
        // {
          ExecStart = "${pkgs.util-linux}/bin/flock --exclusive --nonblock /run/lock/aos-release/coordinator.lock ${cfg.backupProgram}";
          User = "aos-release-backup";
          Group = "aos-release-backup";
          StateDirectory = "aos-release-backup";
          StateDirectoryMode = "0700";
          RuntimeDirectory = "aos-release-backup";
          RuntimeDirectoryMode = "0700";
          WorkingDirectory = "/var/lib/aos-release-backup";
          ReadOnlyPaths = [
            "/var/lib/aos-release-coordinator"
            "/var/lib/aos-release-timestamp"
          ];
          LoadCredential = renderCredentials cfg.backupCredentials;
          TimeoutStartSec = "6h";
        };
    };
    systemd.timers.aos-release-backup = {
      description = "Schedule encrypted AOS release evidence backups";
      wantedBy = ["timers.target"];
      timerConfig = timerDefaults // {OnCalendar = cfg.backupCalendar;};
    };

    systemd.services.aos-release-restore-check = {
      description = "Verify an AOS release evidence backup by restoring it";
      after = ["aos-release-backup.service"];
      unitConfig.OnFailure = ["aos-release-alert@%n.service"];
      serviceConfig =
        hardened
        // {
          ExecStart = "${pkgs.util-linux}/bin/flock --exclusive --nonblock /run/lock/aos-release/coordinator.lock ${cfg.restoreCheckProgram}";
          User = "aos-release-backup";
          Group = "aos-release-backup";
          StateDirectory = "aos-release-backup";
          StateDirectoryMode = "0700";
          RuntimeDirectory = "aos-release-restore-check";
          RuntimeDirectoryMode = "0700";
          WorkingDirectory = "/var/lib/aos-release-backup";
          PrivateNetwork = true;
          RestrictAddressFamilies = ["AF_UNIX"];
          TimeoutStartSec = "6h";
        };
    };
    systemd.timers.aos-release-restore-check = {
      description = "Schedule clean-directory AOS release backup verification";
      wantedBy = ["timers.target"];
      timerConfig = timerDefaults // {OnCalendar = cfg.restoreCheckCalendar;};
    };

    systemd.services."aos-release-alert@" = {
      description = "Report failure of AOS release operation %i";
      serviceConfig =
        networked
        // {
          ExecStart = "${cfg.alertProgram} %i";
          User = "aos-release-monitor";
          Group = "aos-release-monitor";
          StateDirectory = "aos-release-monitor";
          StateDirectoryMode = "0700";
          RuntimeDirectory = "aos-release-monitor";
          RuntimeDirectoryMode = "0700";
          WorkingDirectory = "/var/lib/aos-release-monitor";
          LoadCredential = renderCredentials cfg.alertCredentials;
          TimeoutStartSec = "5m";
        };
    };
  };
}

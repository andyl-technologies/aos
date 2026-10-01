##! modules/services/release-coordinator.nix — Canonical release maintainer services.
##!
##! Provides a manually started content-release coordinator plus independently
##! scheduled timestamp, backup, restore-verification, and alert-delivery
##! check jobs. Deployment configuration supplies hermetic wrapper programs and
##! credential source paths; neither secrets nor maintainer-machine identities
##! enter the store.
##!
##! The two unattended checks (restore verification and alert delivery) record
##! machine-run fitness attestations under a shared, group-writable fitness
##! root. Production destination profiles consume those attestations with a
##! 14 day maximum age; operator-run exercises are recorded manually with
##! `aos release fitness run <kind>` and age out after 90 days.
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
    ++ builtins.attrNames cfg.alertCredentials
    ++ builtins.attrNames cfg.fitnessCredentials;
  credentialPaths =
    builtins.attrValues cfg.releaseCredentials
    ++ builtins.attrValues cfg.timestampCredentials
    ++ builtins.attrValues cfg.backupCredentials
    ++ builtins.attrValues cfg.alertCredentials
    ++ builtins.attrValues cfg.fitnessCredentials;

  # The alert-delivery check exercises the alert path as the alert role and
  # then signs an attestation, so it loads both credential sets. Merging with
  # `//` would silently drop a colliding name; an assertion rejects overlap.
  alertCheckCredentials = cfg.alertCredentials // cfg.fitnessCredentials;
  overlappingAlertCheckNames =
    builtins.attrNames (builtins.intersectAttrs cfg.alertCredentials cfg.fitnessCredentials);

  # Role state directories. The fitness root may not coincide with one of them:
  # tmpfiles would then fight StateDirectoryMode over the same directory.
  roleStateDirectories = [
    "/var/lib/aos-release-coordinator"
    "/var/lib/aos-release-timestamp"
    "/var/lib/aos-release-backup"
    "/var/lib/aos-release-monitor"
  ];

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
        After a successful restore the wrapper records a `storage-restore`
        fitness attestation with
        `aos release fitness run storage-restore --report <retained report>`,
        signing through the release-evidence signer whose material arrives via
        fitnessCredentials. Production destination profiles accept that
        attestation for at most 14 days.
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

    alertCheckProgram = lib.mkOption {
      type = optionalProgram;
      default = null;
      description = ''
        Absolute path to the hermetic alert-delivery check wrapper, run weekly
        as the alert role. It must trigger the alert path with a synthetic unit
        name, confirm delivery to the configured on-call destination, and then
        record an `alert-delivery` fitness attestation with
        `aos release fitness run alert-delivery --report <retained report>`.
        Production destination profiles accept that attestation for at most
        14 days. Operator exercises (authority recovery, Hub restore, key
        rotation) are not automated here; operators record them with
        `aos release fitness run <kind>` and they age out after 90 days.
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

    fitnessCredentials = lib.mkOption {
      type = credentialSet;
      default = {};
      description = ''
        Credential source files for the release-evidence signer that signs
        machine-run fitness attestations. They are loaded only by the restore
        verification and alert-delivery check services and must not share a
        file or, for the alert-delivery check, a name with alertCredentials.
      '';
    };

    fitnessRoot = lib.mkOption {
      type = absolutePath;
      default = "/var/lib/aos-release-coordinator/fitness";
      description = ''
        Directory holding signed fitness attestations as
        `<kind>/<performed_at>.json`. It is created setgid and group-writable
        for the aos-release-fitness group so the release, backup, and monitor
        roles can each record attestations; every maintainer configuration
        used on the machine must set `fitness_root` to this path, because
        `aos release fitness` and `aos release advance` read it from there.
      '';
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

    alertCheckCalendar = lib.mkOption {
      type = lib.types.str;
      default = "weekly";
      description = ''
        systemd calendar for the alert-delivery check. Keep the interval
        inside the 14 day attestation age accepted by production profiles.
      '';
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
        assertion = cfg.alertCheckProgram != null;
        message = "releaseCoordinator.alertCheckProgram must be configured";
      }
      {
        assertion = builtins.length credentialPaths == builtins.length (lib.unique credentialPaths);
        message = "release, timestamp, backup, alert, and fitness services must use disjoint credential files";
      }
      {
        assertion = overlappingAlertCheckNames == [];
        message = "releaseCoordinator.alertCredentials and fitnessCredentials must not share a credential name";
      }
      {
        assertion = builtins.all (name: builtins.match "[A-Za-z0-9_.-]+" name != null) credentialNames;
        message = "release coordinator credential names contain unsupported characters";
      }
      {
        assertion = builtins.all (path: !lib.hasPrefix "/nix/store/" path) credentialPaths;
        message = "release coordinator credentials must not be sourced from the Nix store";
      }
      {
        assertion = !lib.hasPrefix "/nix/store/" cfg.fitnessRoot;
        message = "releaseCoordinator.fitnessRoot must not be inside the Nix store";
      }
      {
        assertion = !builtins.elem cfg.fitnessRoot roleStateDirectories;
        message = "releaseCoordinator.fitnessRoot must not be a release role's state directory";
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
      # Shared write access to the fitness root; membership is granted through
      # each role's extraGroups below.
      aos-release-fitness = {
        gid = 808;
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
        extraGroups = ["aos-release-lock" "aos-release-fitness"];
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
        extraGroups = ["aos-release" "aos-release-timestamp" "aos-release-lock" "aos-release-fitness"];
      };
      aos-release-monitor = {
        uid = 806;
        group = "aos-release-monitor";
        home = "/var/lib/aos-release-monitor";
        shell = "/sbin/nologin";
        description = "AOS release operation alerts";
        extraGroups = ["aos-release-fitness"];
      };
    };

    # The fitness root is setgid so attestations written by any role stay
    # group-owned. The attestation-producing services relax their umask to
    # 0027 so the release role can read what the backup and monitor roles
    # recorded; their own state directories are 0700, so nothing else opens up.
    environment.etc."tmpfiles.d/aos-release-coordinator.conf".text = ''
      d /run/lock/aos-release 0770 root aos-release-lock - -
      d ${cfg.fitnessRoot} 2770 aos-release aos-release-fitness - -
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

    # The restore check stays network-denied: the release-evidence signer is a
    # local executable, so recording the storage-restore attestation needs
    # only the fitness root and the signer credentials.
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
          ReadWritePaths = [cfg.fitnessRoot];
          UMask = "0027";
          LoadCredential = renderCredentials cfg.fitnessCredentials;
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

    # The monitor role must reach the fitness root beneath the coordinator's
    # 0750 state directory without joining the aos-release group. An empty
    # read-only tmpfs replaces the coordinator directory in this unit's mount
    # namespace and only the fitness root is bound back in, so the alert role
    # sees no other release state.
    systemd.services.aos-release-alert-check = {
      description = "Exercise AOS release alert delivery and record its fitness";
      after = ["network-online.target"];
      wants = ["network-online.target"];
      unitConfig.OnFailure = ["aos-release-alert@%n.service"];
      serviceConfig =
        networked
        // {
          ExecStart = cfg.alertCheckProgram;
          User = "aos-release-monitor";
          Group = "aos-release-monitor";
          StateDirectory = "aos-release-monitor";
          StateDirectoryMode = "0700";
          RuntimeDirectory = "aos-release-alert-check";
          RuntimeDirectoryMode = "0700";
          WorkingDirectory = "/var/lib/aos-release-monitor";
          TemporaryFileSystem = ["/var/lib/aos-release-coordinator:ro"];
          BindPaths = [cfg.fitnessRoot];
          ReadWritePaths = [cfg.fitnessRoot];
          UMask = "0027";
          LoadCredential = renderCredentials alertCheckCredentials;
          TimeoutStartSec = "30m";
        };
    };
    systemd.timers.aos-release-alert-check = {
      description = "Schedule the weekly AOS release alert-delivery check";
      wantedBy = ["timers.target"];
      timerConfig = timerDefaults // {OnCalendar = cfg.alertCheckCalendar;};
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

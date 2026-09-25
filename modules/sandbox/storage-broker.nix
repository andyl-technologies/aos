##! modules/sandbox/storage-broker.nix — authenticated root Storage repair boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.storageBroker;
  controller = config.aos.sandbox.controller;
  worker = config.aos.sandbox.storageWorker;
  brokerSession = import ./_broker-session-credentials.nix {inherit lib pkgs;};
  brokerSessionEndpoints = [
    {
      name = "storage-broker";
      description = "Storage broker";
      role = "broker";
      journalRoot = "/var/lib/aos/sandbox-storage/broker-session";
      options = {
        manifest = "brokerSessionManifest";
        hello = "brokerSessionHelloKey";
        record = "brokerSessionOutcomeKey";
      };
    }
    {
      name = "storage-host-client";
      description = "Storage-side Host cgroup readback client";
      role = "client";
      journalRoot = "/var/lib/aos/sandbox-storage/broker-session/host";
      options = {
        manifest = "brokerSessionHostManifest";
        hello = "brokerSessionHostHelloKey";
        record = "brokerSessionHostRecordKey";
      };
    }
  ];
  brokerSessionConfiguration = brokerSession.configure cfg.credentials brokerSessionEndpoints;
  minimumIdentityRange = 65536;
  operatorRecoveryConfigured =
    cfg.operatorRecoveryControllerPublicKey != null
    && cfg.operatorRecoveryStorageOwnerKey != null;
in {
  options.aos.sandbox.storageBroker = {
    enable = lib.mkEnableOption "the fixed AOS sandbox Storage repair broker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-storaged;
      defaultText = "pkgs.aos-storaged";
      description = "The independently packaged Storage repair and inventory broker.";
    };

    zfsPackage = lib.mkOption {
      type = lib.types.package;
      default = worker.zfsPackage;
      defaultText = "config.aos.sandbox.storageWorker.zfsPackage";
      description = "The exact AOS OpenZFS package compiled into broker worker requests.";
    };

    guestRootTemplate = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandbox-guest-root-template;
      defaultText = "pkgs.aos-sandbox-guest-root-template";
      description = "The exact AOS-built guest root and package closure measured by Storage inventory.";
    };

    authorityDirectory = lib.mkOption {
      type = lib.types.str;
      default = worker.authorityDirectory;
      defaultText = "config.aos.sandbox.storageWorker.authorityDirectory";
      description = "Existing root-owned Storage authority shared with the authenticated pin workers.";
    };

    bootstrapDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/etc/aos/sandbox-storage-bootstrap";
      description = "Existing root-owned directory containing storage-genesis.catalog and storage-minimum-generation.";
    };

    resolverPolicyDirectory = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional existing root-owned directory containing storage-resolver-policy.catalog.";
    };

    credentials = brokerSession.mkOptions brokerSessionEndpoints;

    kernelExportStageSignerCredential = lib.mkOption {
      type = lib.types.nullOr lib.serviceTypes.credentialName;
      default = null;
      description = "Reserved external AOSKGA02 stage-signing credential name. It is deliberately not loaded into Storage until a held-barrier signer is implemented.";
    };

    operatorRecoveryControllerPublicKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Protected AOSORCP1 controller public-key record for signed operator Repair. Null keeps the operator socket closed.";
    };

    operatorRecoveryStorageOwnerKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Protected AOSORSK2 Storage owner signing-key record for operator receipts. Both role keys must be provisioned together.";
    };

    zfsHoldSigningKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Separately provisioned root-only AOSZHK01 Storage ZFS hold receipt key source outside the Nix store. Issuance remains closed until physical readback and durable attempt admission are connected.";
    };

    executionOutputKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "External AOSOCK01 output capacity and MAC key source: root-owned mode 0400 or 0600 beneath root-owned nonwritable, symlink-free ancestors. Storage checks that source against systemd's credential copy and requires an existing AOSEOC01 execution-output.journal. Only the authenticated read-only Host query is enabled.";
    };

    identityPoolStart = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value >= minimumIdentityRange);
      default = 65536;
      description = "First host identity in the finite workspace subordinate-identity pool.";
    };

    identityPoolSize = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value >= minimumIdentityRange);
      default = 268435456;
      description = "Number of host identities in the finite workspace subordinate-identity pool.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions =
      [
        {
          assertion = worker.enable;
          message = "aos.sandbox.storageBroker requires aos.sandbox.storageWorker";
        }
        {
          assertion = toString cfg.zfsPackage == toString worker.zfsPackage;
          message = "aos.sandbox.storageBroker and storageWorker must use the same OpenZFS package";
        }
        {
          assertion = lib.hasPrefix "/" cfg.authorityDirectory;
          message = "aos.sandbox.storageBroker.authorityDirectory must be absolute";
        }
        {
          assertion = (cfg.operatorRecoveryControllerPublicKey == null) == (cfg.operatorRecoveryStorageOwnerKey == null);
          message = "aos.sandbox.storageBroker operator Recovery role keys must be provisioned together";
        }
        {
          assertion =
            (cfg.operatorRecoveryControllerPublicKey == null || lib.hasPrefix "/" cfg.operatorRecoveryControllerPublicKey)
            && (cfg.operatorRecoveryStorageOwnerKey == null || lib.hasPrefix "/" cfg.operatorRecoveryStorageOwnerKey);
          message = "aos.sandbox.storageBroker operator Recovery key paths must be absolute";
        }
        {
          assertion = cfg.zfsHoldSigningKey == null || lib.hasPrefix "/" cfg.zfsHoldSigningKey;
          message = "aos.sandbox.storageBroker.zfsHoldSigningKey must be null or absolute";
        }
        {
          assertion = cfg.executionOutputKey == null || lib.hasPrefix "/" cfg.executionOutputKey;
          message = "aos.sandbox.storageBroker.executionOutputKey must be null or absolute";
        }
        {
          assertion =
            cfg.executionOutputKey == null
            || (cfg.executionOutputKey != "/nix/store" && !lib.hasPrefix "/nix/store/" cfg.executionOutputKey);
          message = "aos.sandbox.storageBroker.executionOutputKey must be provisioned outside the Nix store";
        }
        {
          assertion =
            cfg.zfsHoldSigningKey == null
            || (cfg.zfsHoldSigningKey != "/nix/store" && !lib.hasPrefix "/nix/store/" cfg.zfsHoldSigningKey);
          message = "aos.sandbox.storageBroker.zfsHoldSigningKey must be provisioned outside the Nix store";
        }
        {
          assertion = lib.hasPrefix "/" cfg.bootstrapDirectory;
          message = "aos.sandbox.storageBroker.bootstrapDirectory must be absolute";
        }
        {
          assertion = cfg.resolverPolicyDirectory == null || lib.hasPrefix "/" cfg.resolverPolicyDirectory;
          message = "aos.sandbox.storageBroker.resolverPolicyDirectory must be null or absolute";
        }
        {
          assertion = cfg.identityPoolStart + cfg.identityPoolSize <= 4294967295;
          message = "aos.sandbox.storageBroker identity pool must fit within u32";
        }
      ]
      ++ brokerSessionConfiguration.assertions;

    # The controller receives traverse-only access to the socket directory. It
    # cannot unlink or replace the root-owned endpoint path.
    environment.etc."tmpfiles.d/aos-sandbox-storage.conf".text = ''
      d /run/aos/sandbox-storage 0710 root aos-sandboxd - -
    '';

    systemd.sockets.aos-storaged = {
      description = "AOS sandbox Storage broker socket";
      wantedBy = ["sockets.target"];
      requires = ["systemd-tmpfiles-setup.service"];
      after = ["systemd-tmpfiles-setup.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-storage/control.sock";
        FileDescriptorName = "aos-storaged";
        Service = "aos-storaged.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        SendBuffer = "4M";
        RemoveOnStop = true;
      };
    };

    systemd.sockets.aos-storaged-root-export = {
      description = "AOS Host-only detached guest-root export socket";
      wantedBy = ["sockets.target"];
      requires = ["systemd-tmpfiles-setup.service"];
      after = ["systemd-tmpfiles-setup.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-storage/root-export.sock";
        FileDescriptorName = "aos-storaged-root-export";
        Service = "aos-storaged.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    systemd.sockets.aos-storaged-existing-output = {
      description = "AOS Host-only retained execution-output query socket";
      wantedBy = lib.optional (cfg.executionOutputKey != null) "sockets.target";
      requires = ["systemd-tmpfiles-setup.service"];
      after = ["systemd-tmpfiles-setup.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-storage/existing-output.sock";
        FileDescriptorName = "aos-storaged-existing-output";
        Service = "aos-storaged.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    # This root-only endpoint can only return explicit unavailability until
    # durable Provider selection and independent physical grants qualify.
    systemd.sockets.aos-storaged-live-export-request = {
      description = "AOS Provider-to-Storage closed live-export request socket";
      wantedBy = lib.optional config.aos.sandbox.sourceProvider.enable "sockets.target";
      requires = ["systemd-tmpfiles-setup.service"];
      after = ["systemd-tmpfiles-setup.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-storage/live-export-request.sock";
        FileDescriptorName = "aos-storaged-live-export-request";
        Service = "aos-storaged.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0710";
        ReceiveBuffer = "4M";
        SendBuffer = "4M";
        RemoveOnStop = true;
      };
    };

    systemd.sockets.aos-storaged-operator-repair = {
      description = "AOS controller-signed operator Storage Repair socket";
      wantedBy = lib.optional operatorRecoveryConfigured "sockets.target";
      requires = ["systemd-tmpfiles-setup.service"];
      after = ["systemd-tmpfiles-setup.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-storage/operator-repair.sock";
        FileDescriptorName = "aos-storaged-operator-repair";
        Service = "aos-storaged.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        ReceiveBuffer = "4M";
        SendBuffer = "4M";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-storaged = {
      description = "AOS authenticated Storage Prepare, repair, and inventory broker";
      requires = [
        "aos-storaged.socket"
        "aos-storaged-root-export.socket"
        "aos-sandbox-zfs-worker.socket"
        "aos-sandbox-workspace-pin-worker.socket"
        "aos-sandbox-workspace-pin-observer.socket"
        "aos-sandbox-guest-root-publisher.socket"
      ]
      ++ lib.optional config.aos.sandbox.sourceProvider.enable "aos-storaged-live-export-request.socket"
      ++ lib.optional (cfg.executionOutputKey != null) "aos-storaged-existing-output.socket"
      ++ lib.optional operatorRecoveryConfigured "aos-storaged-operator-repair.socket";
      after = [
        "aos-storaged.socket"
        "aos-storaged-root-export.socket"
        "aos-sandbox-guest-root-publisher.socket"
        "aos-sandbox-zfs-ready.service"
        "local-fs.target"
      ]
      ++ lib.optional config.aos.sandbox.sourceProvider.enable "aos-storaged-live-export-request.socket"
      ++ lib.optional (cfg.executionOutputKey != null) "aos-storaged-existing-output.socket"
      ++ lib.optional operatorRecoveryConfigured "aos-storaged-operator-repair.socket";
      unitConfig = {
        RequiresMountsFor =
          [
            "/sys/fs/cgroup"
            cfg.authorityDirectory
            cfg.bootstrapDirectory
            cfg.guestRootTemplate
          ]
          ++ lib.optional (cfg.resolverPolicyDirectory != null) cfg.resolverPolicyDirectory;
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        ExecStartPre = brokerSessionConfiguration.installCommands;
        ExecStart = ''
          ${cfg.package}/bin/aos-storaged \
            ${toString controller.uid} \
            ${toString controller.gid} \
            ${toString cfg.identityPoolStart} \
            ${toString cfg.identityPoolSize} \
            ${cfg.zfsPackage}/sbin/zfs \
            ${cfg.authorityDirectory} \
            ${cfg.bootstrapDirectory} \
            ${lib.escapeShellArg (
            if cfg.resolverPolicyDirectory == null
            then "-"
            else cfg.resolverPolicyDirectory
          )} \
            ${cfg.guestRootTemplate} \
            ${if cfg.zfsHoldSigningKey == null then "-" else "zfs-hold-key-v1"} \
            ${lib.escapeShellArg (if cfg.executionOutputKey == null then "-" else cfg.executionOutputKey)}
        '';
        LoadCredential =
          brokerSessionConfiguration.loadCredentials
          ++ lib.optionals operatorRecoveryConfigured [
            "operator-recovery-controller-public-key-v1:${cfg.operatorRecoveryControllerPublicKey}"
            "operator-recovery-storage-owner-key-v1:${cfg.operatorRecoveryStorageOwnerKey}"
          ]
          ++ lib.optional (cfg.zfsHoldSigningKey != null)
          "storage-zfs-hold-key-v1:${cfg.zfsHoldSigningKey}"
          ++ lib.optional (cfg.executionOutputKey != null)
          "storage-execution-output-key-v1:${cfg.executionOutputKey}";
        Restart = "on-failure";
        RestartSec = "2s";
        StateDirectory = "aos/sandbox-storage";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-pins/workspaces";
        RuntimeDirectoryMode = "0700";
        # Pins outlive broker executions; only typed retirement removes them.
        # The volatile root is discarded independently when the host reboots.
        RuntimeDirectoryPreserve = "yes";
        UMask = "0077";
        User = "root";
        Group = "root";

        # The long-running broker only authenticates state and dispatches
        # fixed one-shot workers. It receives no ZFS or mount capability.
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LimitNOFILE = 256;
        LimitCORE = 0;
        LockPersonality = true;
        MemoryMax = "512M";
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        # Workspace pin proofs bind mount identities to the kernel boot ID at
        # /proc/sys/kernel/random/boot_id. Keep process metadata hidden and
        # kernel tunables read-only, but do not hide this required procfs ABI.
        ProcSubset = "all";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        ReadOnlyPaths =
          [cfg.authorityDirectory cfg.bootstrapDirectory cfg.guestRootTemplate]
          ++ lib.optional (cfg.resolverPolicyDirectory != null) "-${cfg.resolverPolicyDirectory}";
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        # The paired systemd and kernel policy permits strict openat2
        # resolution while preventing setid-file creation.
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        SystemCallArchitectures = ["native"];
        SystemCallFilter = [
          "~chmod"
          "~fchmod"
          "~fchmodat"
          "~fchmodat2"
          "~io_uring_setup"
          "~io_uring_enter"
          "~io_uring_register"
        ];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 32;
      };
    };

    # Root population is separate from the long-lived broker and unqualified
    # pin worker; neither receives ownership or mode-changing authority.
    systemd.sockets.aos-sandbox-guest-root-publisher = {
      description = "AOS protected guest-root publisher socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-guest-root-publisher/control.sock";
        Accept = true;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
        MaxConnections = 1;
      };
    };

    systemd.services."aos-sandbox-guest-root-publisher@" = {
      description = "AOS one-shot protected guest-root population";
      unitConfig.RequiresMountsFor = [
        "/sys/fs/cgroup"
        "/run/aos/sandbox-pins/workspaces"
        cfg.authorityDirectory
        cfg.guestRootTemplate
      ];
      serviceConfig = {
        Type = "exec";
        ExecStart = ''
          ${worker.package}/bin/aos-sandbox-guest-root-publisher \
            ${cfg.guestRootTemplate} \
            ${cfg.authorityDirectory} \
            /var/lib/aos-sandbox-guest-root-publisher
        '';
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        StateDirectory = "aos-sandbox-guest-root-publisher";
        StateDirectoryMode = "0700";
        RuntimeMaxSec = "120s";
        TimeoutStopSec = "1s";
        KillMode = "control-group";
        Restart = "no";
        UMask = "0077";
        User = "root";
        Group = "root";
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LimitNOFILE = 128;
        LimitCORE = 0;
        LockPersonality = true;
        MemoryMax = "1G";
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProcSubset = "all";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        ReadOnlyPaths = [cfg.authorityDirectory cfg.guestRootTemplate];
        ReadWritePaths = ["/run/aos/sandbox-pins/workspaces"];
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        SystemCallArchitectures = ["native"];
        SystemCallFilter = [
          "@system-service"
          "~@mount"
          "~@reboot"
          "~@swap"
          "~@module"
          "~@raw-io"
          "~socket"
          "~socketpair"
          "~connect"
          "~io_uring_setup"
          "~io_uring_enter"
          "~io_uring_register"
        ];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 16;
      };
    };
  };
}

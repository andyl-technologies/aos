##! modules/sandbox/fuse-worker.nix — closed image-owned FUSE worker role
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.sandbox.fuseWorker;
  unitName = "aos-view-worker@";
in {
  options.aos.sandbox.fuseWorker = {
    enable = lib.mkEnableOption "the fixed Mount-owned filesystem worker template";

    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "Image-owned package containing the fixed aos-filesystem-fuse-worker entry point.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.aos.sandbox.hostBroker.enable;
        message = "The FUSE worker role requires the existing authenticated Host owner";
      }
      {
        assertion = cfg.package != null;
        message = "The FUSE worker role requires its image-owned executable package";
      }
    ];

    systemd.slices.aos-view-workers = {
      description = "Original Mount-owned filesystem workers";
      sliceConfig = {
        CPUAccounting = true;
        MemoryAccounting = true;
        TasksAccounting = true;
      };
    };

    # No activation socket, enabled instance, credential, or restart policy.
    # PID 1's LaunchAosFuseWorkerV1 alone installs the exact five inherited
    # roles and arms the first command after measured-fragment admission.
    systemd.services.${unitName} = {
      description = "Original Mount-owned immutable filesystem worker";
      unitConfig = {
        StartLimitIntervalSec = "infinity";
        StartLimitBurst = 1;
        CollectMode = "inactive-or-failed";
        RequiresMountsFor = "/nix.lower/store";
      };
      serviceConfig = {
        Type = "exec";
        ExecStart = "${cfg.package}/bin/aos-filesystem-fuse-worker --mount-owned-session-v1";
        Restart = "no";
        Slice = "aos-view-workers.slice";
        KillMode = "control-group";
        TimeoutStartSec = "5s";
        DynamicUser = true;
        SetLoginEnvironment = false;
        UMask = "0077";
        StandardInput = "null";
        StandardOutput = "journal";
        StandardError = "journal";
        Environment = [];
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateNetwork = true;
        PrivateIPC = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateMounts = true;
        # Install before the dynamic loader runs; logical ELF/DSO paths must
        # resolve to the same physical image inodes pinned by PID 1.
        BindReadOnlyPaths = ["/nix.lower/store:/nix/store"];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictNamespaces = true;
        RestrictAddressFamilies = ["AF_UNIX"];
        SystemCallArchitectures = ["native"];
        SystemCallFilter = ["@system-service" "~@mount" "~accept" "~accept4" "~bind" "~connect" "~listen"];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 8;
        MemoryHigh = "64M";
        MemoryMax = "128M";
        MemorySwapMax = 0;
        LimitNOFILE = 128;
      };
    };
  };
}

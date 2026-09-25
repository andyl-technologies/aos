##! modules/sandbox/network-inspector.nix — guarded Network namespace-inspector activation
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.networkInspector;
  credentialFiles = {
    deploymentContract = "deployment-contract";
    lifecycleWorkerLaunchDigest = "lifecycle-worker-launch-digest";
    inspectorDeploymentVerifierV2 = "inspector-deployment-verifier-v2";
    inspectorDeploymentContractV2 = "inspector-deployment-contract-v2";
    inspectorLaunchPolicyV3 = "inspector-launch-policy-v3";
  };
  configuredCredentials =
    lib.filterAttrs (name: _: cfg.credentials.${name} != null) credentialFiles;
  loadCredentials =
    lib.mapAttrsToList (
      name: _: "${credentialFiles.${name}}:/run/credentials/@system/${cfg.credentials.${name}}"
    )
    configuredCredentials;
  inspectorServiceName = "aos-sandbox-network-namespace-inspector@";
  inspectorUnitName = "${inspectorServiceName}.service";
  protectedRootsUnit = "aos-sandbox-network-roots.service";

  loaderEnvironment = import ./_network-loader-environment.nix {inherit lib;};
  renderedInspectorUnit = config.systemd.units.${inspectorUnitName}.text;
  renderedEnvironmentScrub = loaderEnvironment.renderedUnitMatchesSourcePolicy renderedInspectorUnit;
in {
  options.aos.sandbox.networkInspector = {
    enable = lib.mkEnableOption "the guarded Network namespace-inspector service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-netd;
      defaultText = "pkgs.aos-netd";
      description = "Package containing the fixed Network namespace inspector and lifecycle worker.";
    };

    managerQueryPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-namespace-inspector-manager-query;
      defaultText = "pkgs.aos-namespace-inspector-manager-query";
      description = "Package containing the fixed native systemd manager-query helper named by the protected contract.";
    };

    credentials = lib.mapAttrs (name: credentialFile:
      lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description = "External protected ${name} credential loaded as ${credentialFile}; its bytes never enter the Nix store.";
      })
    credentialFiles;
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = false;
        message = "aos.sandbox.networkInspector remains unavailable until signed V2/V3 executable-closure custody, live service/manager/cgroup admission, and enforcing host-MAC behavior pass a deployed qualification gate";
      }
      {
        assertion = config.aos.sandbox.networkBroker.enable && config.aos.sandbox.networkWorker.enable;
        message = "aos.sandbox.networkInspector requires the Network broker and lifecycle worker";
      }
      {
        assertion =
          cfg.credentials.inspectorDeploymentVerifierV2 == config.aos.sandbox.networkBroker.credentials.inspectorDeploymentVerifierV2
          && cfg.credentials.inspectorDeploymentContractV2 == config.aos.sandbox.networkBroker.credentials.inspectorDeploymentContractV2
          && cfg.credentials.inspectorLaunchPolicyV3 == config.aos.sandbox.networkBroker.credentials.inspectorLaunchPolicyV3;
        message = "aos.sandbox.networkInspector and the Network broker must load the same signed V2/V3 credential sources";
      }
      {
        assertion = config.aos.security.selinux.protectedSandboxNetworkRoots.enable;
        message = "aos.sandbox.networkInspector requires the protected SELinux Network roots";
      }
      {
        assertion =
          config.aos.security.selinux.enable
          && config.aos.security.selinux.bootMode == "immutable-stage0"
          && config.aos.security.selinux.mode == "enforcing"
          && config.aos.security.selinux.policy == "aos";
        message = "aos.sandbox.networkInspector requires the immutable enforcing AOS SELinux policy";
      }
      {
        assertion = renderedEnvironmentScrub;
        message = "${inspectorUnitName} must render the inherited-environment scrub without EnvironmentFile or PassEnvironment";
      }
      {
        assertion = lib.hasInfix "RestrictSUIDSGID=true\n" renderedInspectorUnit;
        message = "${inspectorUnitName} must install the inherited AOS no-set-ID guard";
      }
      {
        assertion = builtins.all (name: lib.hasInfix "SystemCallFilter=~${name}\n" renderedInspectorUnit) [
          "io_uring_setup"
          "io_uring_enter"
          "io_uring_register"
        ];
        message = "${inspectorUnitName} must reject io_uring creation and operation";
      }
      {
        assertion = lib.hasInfix "CollectMode=inactive-or-failed\n" renderedInspectorUnit;
        message = "${inspectorUnitName} must collect failed Accept=yes instances";
      }
    ] ++ lib.mapAttrsToList (name: credentialFile: {
        assertion = cfg.credentials.${name} != null;
        message = "aos.sandbox.networkInspector.credentials.${name} is required for ${credentialFile}";
      })
      credentialFiles;

    # These roots are distinct capabilities in the runtime. The broker alone
    # publishes expected records; the inspector sees only final expected policy
    # and its separate append-only spent staging/final pair.
    environment.etc."tmpfiles.d/aos-sandbox-network-inspector.conf".text = ''
      d /var/lib/aos/sandbox-network 0700 root root - -
      d /var/lib/aos/sandbox-network/namespace-inspector 0700 root root - -
      d /var/lib/aos/sandbox-network/namespace-inspector/expected-staging 0700 root root - -
      d /var/lib/aos/sandbox-network/namespace-inspector/expected-final 0700 root root - -
      d /var/lib/aos/sandbox-network/namespace-inspector/spent-staging 0700 root root - -
      d /var/lib/aos/sandbox-network/namespace-inspector/spent-final 0700 root root - -
    '';

    systemd.sockets.aos-sandbox-network-namespace-inspector = {
      description = "AOS authenticated Network namespace inspector socket";
      wantedBy = ["sockets.target"];
      requires = ["systemd-tmpfiles-setup.service" protectedRootsUnit];
      after = ["systemd-tmpfiles-setup.service" protectedRootsUnit];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-network-namespace-inspector/control.sock";
        Accept = true;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
        MaxConnections = 128;
        MaxConnectionsPerSource = 32;
      };
    };

    systemd.services.${inspectorServiceName} = {
      description = "AOS authenticated one-shot Network namespace inspector";
      requires = ["aos-sandbox-network-namespace-inspector.socket" protectedRootsUnit];
      after = ["aos-sandbox-network-namespace-inspector.socket" "local-fs.target" protectedRootsUnit];
      unitConfig = {
        CollectMode = "inactive-or-failed";
        RequiresMountsFor = [
          "/sys/fs/cgroup"
          "/var/lib/aos/sandbox-network/namespace-inspector/expected-final"
          "/var/lib/aos/sandbox-network/namespace-inspector/spent-staging"
          "/var/lib/aos/sandbox-network/namespace-inspector/spent-final"
        ];
      };
      serviceConfig = {
        Type = "exec";
        ExecStart = "${cfg.package}/bin/aos-sandbox-network-namespace-inspector";
        LoadCredential = loadCredentials;

        # Accept=yes supplies the connected SOCK_SEQPACKET to this template;
        # stdin/stdout retain that one endpoint for the exact request/response.
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        RuntimeMaxSec = "5s";
        TimeoutStopSec = "1s";
        KillMode = "control-group";
        KillSignal = "SIGKILL";
        FinalKillSignal = "SIGKILL";
        SendSIGKILL = true;
        Restart = "no";
        User = "root";
        Group = "root";
        UMask = "0077";

        # CAP_SYS_PTRACE is required only for pidfs namespace inspection and
        # the retained cross-process procfs observations. The service receives
        # no Network mutation capability and cannot enter a namespace.
        CapabilityBoundingSet = ["CAP_SYS_PTRACE"];
        AmbientCapabilities = ["CAP_SYS_PTRACE"];
        SecureBits = [
          "noroot"
          "noroot-locked"
          "no-setuid-fixup"
          "no-setuid-fixup-locked"
        ];
        DevicePolicy = "closed";
        # The signed inventory retains up to 128 physical ELF members while
        # the V1 contract and live manager/session descriptors stay pinned.
        LimitNOFILE = 256;
        LimitCORE = 0;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        MemoryMax = "192M";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        InaccessiblePaths = [
          "/var/lib/aos/sandbox-network/broker-state"
          "/var/lib/aos/sandbox-network/namespace-inspector/expected-staging"
        ];
        ReadOnlyPaths = [
          "/nix/store"
          "${cfg.managerQueryPackage}"
          "/var/lib/aos/sandbox-network/namespace-inspector/expected-final"
        ];
        ReadWritePaths = [
          "/var/lib/aos/sandbox-network/namespace-inspector/spent-staging"
          "/var/lib/aos/sandbox-network/namespace-inspector/spent-final"
        ];
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
          "~bpf"
          "~setns"
          "~unshare"
          "~io_uring_setup"
          "~io_uring_enter"
          "~io_uring_register"
        ];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 8;
        UnsetEnvironment = loaderEnvironment.denylist;
      };
    };
  };
}

##! modules/sandbox/network-broker.nix — authenticated root Network inventory boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.networkBroker;
  brokerSession = import ./_broker-session-credentials.nix {inherit lib pkgs;};
  brokerSessionEndpoints = [
    {
      name = "network-broker";
      description = "Network broker";
      role = "broker";
      journalRoot = "/var/lib/aos/sandbox-network/broker-session";
      options = {
        manifest = "brokerSessionManifest";
        hello = "brokerSessionHelloKey";
        record = "brokerSessionOutcomeKey";
      };
    }
  ];
  brokerSessionConfiguration = brokerSession.configure cfg.credentials brokerSessionEndpoints;
  authorityCredentialFields = {
    brokerPlanPolicy = "broker-plan-policy.cbor";
    brokerPlanPublicKey = "broker-plan-public-key";
    brokerRevocationScope = "broker-revocation-scope";
    ownershipLeasePolicy = "ownership-lease-policy.cbor";
    ownershipLeasePublicKey = "ownership-lease-public-key";
    nodeId = "node-id";
    journalMacKey = "journal-mac-key";
    networkPolicyCatalog = "network-policy.catalog";
  };
  inspectorDeploymentCredentialFields = {
    inspectorDeploymentVerifierV2 = "inspector-deployment-verifier-v2";
    inspectorDeploymentContractV2 = "inspector-deployment-contract-v2";
  };
  inspectorLaunchPolicyCredential = "inspector-launch-policy-v3";
  configuredInspectorDeploymentCredentials =
    lib.filterAttrs (name: _: cfg.credentials.${name} != null) inspectorDeploymentCredentialFields;
  completeInspectorDeploymentCredentials =
    builtins.length (builtins.attrNames configuredInspectorDeploymentCredentials)
    == builtins.length (builtins.attrNames inspectorDeploymentCredentialFields);
  inspectorDeploymentLoadCredentials =
    lib.optionals completeInspectorDeploymentCredentials
    (lib.mapAttrsToList (
        name: _: "${inspectorDeploymentCredentialFields.${name}}:/run/credentials/@system/${cfg.credentials.${name}}"
      )
      inspectorDeploymentCredentialFields);
  inspectorLaunchPolicyLoadCredentials =
    lib.optional (cfg.credentials.inspectorLaunchPolicyV3 != null)
    "${inspectorLaunchPolicyCredential}:/run/credentials/@system/${cfg.credentials.inspectorLaunchPolicyV3}";
  configuredAuthorityCredentials =
    lib.filterAttrs (name: _: cfg.credentials.${name} != null) authorityCredentialFields;
  anyAuthorityCredential = configuredAuthorityCredentials != {};
  completeAuthorityCredentials =
    builtins.length (builtins.attrNames configuredAuthorityCredentials)
    == builtins.length (builtins.attrNames authorityCredentialFields);
  authorityLoadCredentials =
    lib.optionals completeAuthorityCredentials
    (lib.mapAttrsToList (
        name: _: "${authorityCredentialFields.${name}}:/run/credentials/@system/${cfg.credentials.${name}}"
      )
      authorityCredentialFields);
  protectedRoots = config.aos.security.selinux.protectedSandboxNetworkRoots.enable;
  protectedRootsUnit = "aos-sandbox-network-roots.service";
  workerSockets = [
    "aos-sandbox-network-worker.socket"
    "aos-sandbox-network-lifecycle-worker.socket"
    "aos-sandbox-network-observation-worker.socket"
    "aos-sandbox-network-pin-worker.socket"
  ];
  runtimeRootsExecutable = "${pkgs.aos-selinux-runtime-roots}/bin/aos-selinux-runtime-roots";
  runtimeRootsCommand = "/usr/lib/systemd/aos-selinux-root-handoff --launch-runtime-roots ${runtimeRootsExecutable} --root / --prepare-sandbox-network-roots";
in {
  options.aos.sandbox.networkBroker = {
    enable = lib.mkEnableOption "the fixed AOS sandbox Network broker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-netd;
      defaultText = "pkgs.aos-netd";
      description = "The independently packaged Network inventory broker.";
    };

    maximumRetainedNamespaces = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 1024);
      # Keep the boundary active in the evaluated value as well as its option metadata.
      apply = value:
        if builtins.isInt value && value > 0 && value <= 1024
        then value
        else throw "aos.sandbox.networkBroker.maximumRetainedNamespaces must be an integer from 1 through 1024";
      default = 1024;
      description = "The simultaneous Network namespace custody ceiling; 1024 keeps systemd's LISTEN_FDNAMES environment string below Linux's per-string exec limit.";
    };

    credentials =
      lib.mapAttrs (name: credentialFile:
        lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External system credential loaded as ${credentialFile}; its bytes never enter the Nix store.";
        })
      authorityCredentialFields
      // lib.mapAttrs (name: credentialFile:
        lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External protected Network inspector ${name} credential loaded as ${credentialFile}; its bytes never enter the Nix store.";
        })
      inspectorDeploymentCredentialFields
      // {
        inspectorLaunchPolicyV3 = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Signed V3 Network inspector and lifecycle-worker argv and unit-fragment policy bound to the V2 contract.";
        };
      }
      // brokerSession.mkOptions brokerSessionEndpoints;
  };

  config = lib.mkIf cfg.enable {
    assertions =
      [
        {
          assertion = config.aos.services.dbus.enable;
          message = "aos.sandbox.networkBroker requires aos.services.dbus for bounded systemd FD-store readback";
        }
        {
          assertion = config.aos.sandbox.networkWorker.enable;
          message = "aos.sandbox.networkBroker requires aos.sandbox.networkWorker for preparation, lifecycle, observation, and pin-teardown execution";
        }
        {
          assertion = !anyAuthorityCredential || completeAuthorityCredentials;
          message = "aos.sandbox.networkBroker authority and policy credentials must be configured together";
        }
        {
          assertion = configuredInspectorDeploymentCredentials == {} || completeInspectorDeploymentCredentials;
          message = "aos.sandbox.networkBroker inspector deployment verifier and signed contract must be configured together";
        }
        {
          assertion = cfg.credentials.inspectorLaunchPolicyV3 == null || completeInspectorDeploymentCredentials;
          message = "aos.sandbox.networkBroker V3 launch policy requires the complete V2 verifier and contract pair";
        }
        {
          assertion = !config.aos.sandbox.networkInspector.enable || (completeInspectorDeploymentCredentials && cfg.credentials.inspectorLaunchPolicyV3 != null);
          message = "aos.sandbox.networkBroker requires protected V2 deployment and V3 launch credentials when the inspector is enabled";
        }
      ]
      ++ brokerSessionConfiguration.assertions;

    systemd.sockets.aos-netd =
      {
        description = "AOS sandbox Network broker socket";
        wantedBy = ["sockets.target"];
        socketConfig = {
          ListenSequentialPacket = "/run/aos/sandbox-network/control.sock";
          FileDescriptorName = "aos-netd";
          Service = "aos-netd.service";
          Accept = false;
          PassCredentials = true;
          PassPIDFD = true;
          SocketUser = "aos-sandboxd";
          SocketGroup = "aos-sandboxd";
          SocketMode = "0600";
          DirectoryMode = "0710";
          # The complete 16,384-row inventory is larger than the kernel's
          # ordinary Unix-socket default. Accepted sockets inherit this bound.
          SendBuffer = "4M";
          RemoveOnStop = true;
        };
      }
      // lib.optionalAttrs protectedRoots {
        requires = [protectedRootsUnit];
        after = [protectedRootsUnit];
      };

    systemd.services.aos-sandbox-network-roots = lib.mkIf protectedRoots {
      description = "Prepare protected AOS sandbox Network roots";
      requiredBy = ["sysinit.target"];
      requires = ["var.mount"];
      after = ["var.mount"];
      before = [
        "sysinit.target"
        "systemd-tmpfiles-setup.service"
        "systemd-tmpfiles-setup-dev.service"
        "aos-netd.socket"
        "aos-netd.service"
        "shutdown.target"
      ];
      conflicts = ["shutdown.target"];
      unitConfig = {
        DefaultDependencies = false;
        RequiresMountsFor = ["/var/lib"];
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = runtimeRootsCommand;
        StandardOutput = "journal+console";
        StandardError = "journal+console";
        UMask = "0077";
      };
    };

    systemd.services.aos-netd = {
      description = "AOS authenticated sandbox Network inventory broker";
      requires =
        ["aos-netd.socket" "dbus.socket"]
        ++ workerSockets
        ++ lib.optional protectedRoots protectedRootsUnit;
      after =
        ["aos-netd.socket" "dbus.socket" "local-fs.target"]
        ++ workerSockets
        ++ lib.optional protectedRoots protectedRootsUnit;
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig =
        {
          Type = "simple";
          NotifyAccess = "main";
          # The broker's no-new-privileges sandbox must not suppress the
          # dedicated SELinux provisioner transition used by this fresh gate.
          ExecStartPre =
            lib.optional protectedRoots "+${runtimeRootsCommand}"
            ++ brokerSessionConfiguration.installCommands;
          ExecStart = "${cfg.package}/bin/aos-netd ${toString cfg.maximumRetainedNamespaces}";
          LoadCredential = authorityLoadCredentials ++ inspectorDeploymentLoadCredentials ++ inspectorLaunchPolicyLoadCredentials ++ brokerSessionConfiguration.loadCredentials;
          Restart = "on-failure";
          RestartSec = "2s";
          FileDescriptorStoreMax = cfg.maximumRetainedNamespaces;
          FileDescriptorStorePreserve = "yes";
          RuntimeDirectory = "aos/sandbox-pins/netns";
          RuntimeDirectoryMode = "0700";
          RuntimeDirectoryPreserve = "restart";
          UMask = "0077";

          # Kernel mutation remains isolated in fixed one-shot workers. The
          # broker itself retains no ambient network-administration capability.
          CapabilityBoundingSet = "";
          DevicePolicy = "closed";
          LimitNOFILE = cfg.maximumRetainedNamespaces + 128;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          SecureBits = [
            "noroot"
            "noroot-locked"
            "no-setuid-fixup"
            "no-setuid-fixup-locked"
          ];
          PrivateDevices = true;
          PrivateNetwork = true;
          PrivateTmp = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RestrictAddressFamilies = ["AF_UNIX"];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          Slice = "aos-control.slice";
          SystemCallArchitectures = ["native"];
          # A retained SQPOLL ring can run without io_uring_enter. The broker
          # checks every inherited descriptor before accepting FD-store state.
          SystemCallFilter = [
            "~io_uring_setup"
            "~io_uring_enter"
            "~io_uring_register"
          ];
          SystemCallErrorNumber = "EPERM";
          TasksMax = 32;
        }
        // lib.optionalAttrs (!protectedRoots) {
          StateDirectory = [
            "aos/sandbox-network/broker-state"
            "aos/sandbox-network/broker-session"
          ];
          StateDirectoryMode = "0700";
        }
        // lib.optionalAttrs protectedRoots {
          ReadWritePaths = [
            "/var/lib/aos/sandbox-network/broker-state"
            "/var/lib/aos/sandbox-network/broker-session"
          ];
        };
    };
  };
}

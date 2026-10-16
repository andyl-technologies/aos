##! Production Crucible campaign service composition.
##!
##! The option is disabled by default. Enabled systems expose the packaged
##! campaign service through its owner-only Unix socket and public CLI. Both
##! modes publish a non-secret immutable runtime identity so release gates can
##! bind observations to the exact evaluated system configuration.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.crucibleCampaign;
  listenPrefix =
    if lib.hasPrefix "127.0.0.1:" cfg.listenAddress
    then "127.0.0.1:"
    else if lib.hasPrefix "[::1]:" cfg.listenAddress
    then "[::1]:"
    else "";
  listenPortText =
    builtins.substring
    (builtins.stringLength listenPrefix)
    (builtins.stringLength cfg.listenAddress)
    cfg.listenAddress;
  listenPortMatch = builtins.match "[1-9][0-9]{0,4}" listenPortText;
  listenPort =
    if listenPrefix != "" && listenPortMatch != null
    then builtins.fromJSON listenPortText
    else 0;
  hasNoControlCharacters = value: builtins.match "[^[:cntrl:]]*" value != null;
  socketPathIsOwned =
    builtins.match
    "/run/crucible-campaign/[A-Za-z0-9][A-Za-z0-9._-]*"
    cfg.socketPath
    != null;
  stateDirectoryIsOwned =
    builtins.match
    "/var/lib/crucible-campaign(/[A-Za-z0-9][A-Za-z0-9._-]*)*"
    cfg.stateDirectory
    != null;
  process = cfg.processResources;
  executor = cfg.executor;
  executorDeployment =
    if executor == null
    then null
    else builtins.toFile "crucible-campaign-executor.toml" (builtins.readFile executor.deploymentFile);
  executorArguments = lib.optionals (executor != null) (
    [
      "--production-qemu"
      "--campaign-packaged-executor"
      (toString executorDeployment)
      "--campaign-component-authority"
      executor.componentAuthorityFile
      "--campaign-executor-socket"
      executor.socketPath
    ]
    ++ lib.optionals (executor.repositoryStoreFile != null) ["--campaign-store" executor.repositoryStoreFile]
    ++ lib.concatMap (manifest: ["--campaign-import-manifest" manifest]) executor.importManifests
    ++ lib.concatMap (name: ["--campaign-runtime" name]) executor.campaigns
  );
  transportArguments =
    if executor == null
    then ["--trusted-unauthenticated-bind"]
    else
      [
        "--tls-cert"
        executor.transport.serverCertificateFile
        "--tls-key"
        executor.transport.serverKeyFile
        "--client-ca"
        executor.transport.clientCaFile
      ]
      ++ lib.concatMap (fingerprint: ["--host-operator-certificate" fingerprint]) executor.transport.operatorCertificateFingerprints;
  partitionsFit =
    if process == null
    then false
    else
      process.baselineResidentBytes
      <= process.memoryMaxBytes
      && process.metadataBytes <= process.memoryMaxBytes - process.baselineResidentBytes
      && process.sqliteBootstrapBytes <= process.memoryMaxBytes - process.baselineResidentBytes - process.metadataBytes
      && process.sqliteHeapBytes <= process.memoryMaxBytes - process.baselineResidentBytes - process.metadataBytes - process.sqliteBootstrapBytes;
  runtimeFits =
    if process == null
    then false
    else
      process.workerThreads
      < process.tasksMax
      && process.blockingThreads <= process.tasksMax - 1 - process.workerThreads
      && process.threadStackBytes >= 16384
      && process.mainThreadStackBytes >= 16384
      && process.mainThreadStackBytes < process.baselineResidentBytes
      && process.threadStackBytes <= builtins.div (process.baselineResidentBytes - process.mainThreadStackBytes) (process.workerThreads + process.blockingThreads)
      && process.baselineFileDescriptors < process.fileDescriptors
      && process.sqliteConnections <= builtins.div (process.fileDescriptors - process.baselineFileDescriptors) 2
      && process.runtimeSeconds <= 9223372036854
      && process.startupTimeoutSeconds <= 9223372036854
      && process.cpuQuotaPercent <= 922337203685477;
  processPolicy =
    if process == null
    then ""
    else ''
      schema = "crucible.campaign-process.v1"
      unit = "crucible-campaign.service"
      executable = "${cfg.package.passthru.controller}/bin/crucible"
      memory_max_bytes = ${toString process.memoryMaxBytes}
      tasks_max = ${toString process.tasksMax}
      file_descriptors = ${toString process.fileDescriptors}
      runtime_seconds = ${toString process.runtimeSeconds}
      startup_timeout_seconds = ${toString process.startupTimeoutSeconds}
      main_thread_stack_bytes = ${toString process.mainThreadStackBytes}
      cpu_quota_percent = ${toString process.cpuQuotaPercent}
      baseline_resident_bytes = ${toString process.baselineResidentBytes}
      metadata_bytes = ${toString process.metadataBytes}
      sqlite_bootstrap_bytes = ${toString process.sqliteBootstrapBytes}
      sqlite_heap_bytes = ${toString process.sqliteHeapBytes}
      sqlite_connections = ${toString process.sqliteConnections}
      worker_threads = ${toString process.workerThreads}
      blocking_threads = ${toString process.blockingThreads}
      thread_stack_bytes = ${toString process.threadStackBytes}
      baseline_file_descriptors = ${toString process.baselineFileDescriptors}
      delegated_executor = ${
        if executor == null
        then "false"
        else "true"
      }
      executor_deployment = "${
        if executor == null
        then ""
        else toString executorDeployment
      }"
      userfaultfd_group_id = ${
        if executor == null
        then "0"
        else toString executor.userfaultfdGroupId
      }
    '';
  runtimeIdentity = builtins.hashString "sha256" (builtins.toJSON {
    schema = "aos.crucible.campaign-runtime.v1";
    inherit (cfg) enable listenAddress socketPath stateDirectory processResources executor;
  });
in {
  options.aos.crucibleCampaign = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the packaged local Crucible campaign service.";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:18080";
      description = "Trusted loopback API address for the Crucible daemon.";
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/crucible-campaign/service.sock";
      description = "Owner-only Unix socket for the local campaign service.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.crucible;
      description = "Complete source-retaining Crucible suite whose controller is bound by the installed Main policy.";
    };

    stateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/crucible-campaign";
      description = "Durable local campaign object and reference store.";
    };

    processResources = lib.mkOption {
      default = null;
      description = "Original finite process partitions installed before campaign service exec.";
      type = lib.types.nullOr (lib.types.submodule {
        options = builtins.mapAttrs (_: description:
          lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value > 0);
            inherit description;
          }) {
          memoryMaxBytes = "Prebirth memory ceiling of the complete service cgroup.";
          tasksMax = "Prebirth task ceiling including service helpers and runtime threads.";
          fileDescriptors = "Original soft and hard descriptor limit.";
          baselineFileDescriptors = "Complete main/runtime descriptor purpose, excluding separately charged SQLite and executor leases.";
          runtimeSeconds = "Original main invocation runtime ceiling in seconds.";
          startupTimeoutSeconds = "Finite service startup timeout, including preStart.";
          mainThreadStackBytes = "Installed original main-thread soft and hard stack bound.";
          cpuQuotaPercent = "Original cgroup CPU quota in percent of one CPU.";
          baselineResidentBytes = "Independent loader, parsing, service runtime and thread stack purpose.";
          metadataBytes = "Original resident partition for process and SQLite ownership controls.";
          sqliteBootstrapBytes = "Qualified permanent linked-native globals and initialization purpose.";
          sqliteHeapBytes = "One original process-native SQLite heap ceiling.";
          sqliteConnections = "Fixed managed connection roster from the original descriptor contract.";
          workerThreads = "Fixed Tokio worker count.";
          blockingThreads = "Fixed maximum Tokio blocking worker count.";
          threadStackBytes = "Authored stack extent of each runtime thread.";
        };
      });
    };

    executor = lib.mkOption {
      default = null;
      description = "Explicit production executor under the same authenticated service main.";
      type = lib.types.nullOr (lib.types.submodule {
        options = {
          deploymentFile = lib.mkOption {
            type = lib.types.path;
            description = "Required complete executor deployment; published immutably with the main policy.";
          };
          socketPath = lib.mkOption {
            type = lib.types.str;
            description = "Owner-only executor endpoint below /run/crucible-campaign.";
          };
          repositoryStoreFile = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "Explicit composed semantic repository deployment; null retains the original SQLite service store.";
          };
          componentAuthorityFile = lib.mkOption {
            type = lib.types.str;
            description = "Explicit protected component authority consumed by the normal planner and executor.";
          };
          importManifests = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            description = "Explicit authenticated campaign input manifests imported before executor preparation.";
          };
          transport = lib.mkOption {
            description = "Explicit mutual-TLS files for authenticated host operational control.";
            type = lib.types.submodule {
              options =
                (builtins.mapAttrs (_: description:
                  lib.mkOption {
                    type = lib.types.str;
                    inherit description;
                  }) {
                  serverCertificateFile = "Installed server certificate path.";
                  serverKeyFile = "Protected server private-key path.";
                  clientCaFile = "Installed client authority certificate path.";
                })
                // {
                  operatorCertificateFingerprints = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    description = "Explicit unique lowercase certificate SHA-256 fingerprints authorized for host operational control.";
                  };
                };
            };
          };
          guestAssets = lib.mkOption {
            description = "Exact installed guest and native assets consumed by the production lifecycle.";
            type = lib.types.submodule {
              options = {
                qemu = lib.mkOption {
                  type = lib.types.str;
                  description = "Installed matching QEMU executable.";
                };
                plugin = lib.mkOption {
                  type = lib.types.str;
                  description = "Installed matching plugin shared object.";
                };
                kernel = lib.mkOption {
                  type = lib.types.str;
                  description = "Installed guest kernel file.";
                };
                rootImage = lib.mkOption {
                  type = lib.types.str;
                  description = "Installed raw guest root image.";
                };
                initrd = lib.mkOption {
                  type = lib.types.str;
                  description = "Installed guest initramfs file.";
                };
                architecture = lib.mkOption {
                  type = lib.types.enum ["x86_64" "aarch64"];
                  description = "Architecture of the installed guest assets.";
                };
                kernelCommandLine = lib.mkOption {
                  type = lib.types.str;
                  description = "Explicit guest kernel command-line prefix.";
                };
                runStateRoot = lib.mkOption {
                  type = lib.types.str;
                  description = "Retained durable execution state root inside the admitted deployment namespace.";
                };
              };
            };
          };
          campaigns = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            description = "Explicit existing durable campaigns served by this executor.";
          };
          userfaultfdGroupId = lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 4294967295);
            description = "Explicit existing QEMU child group receiving only /dev/userfaultfd kernel-fault access; must match the deployment.";
          };
        };
      });
    };

    _runtimeIdentity = lib.mkOption {
      type = lib.types.str;
      default = runtimeIdentity;
      internal = true;
      readOnly = true;
      description = "Evaluated identity of the campaign runtime configuration.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = listenPort > 0 && listenPort <= 65535;
          message = "aos.crucibleCampaign.listenAddress must be a numeric loopback address with a valid nonzero TCP port";
        }
        {
          assertion = builtins.all hasNoControlCharacters [
            cfg.listenAddress
            cfg.socketPath
            cfg.stateDirectory
          ];
          message = "Crucible campaign runtime values must not contain control characters";
        }
        {
          assertion = socketPathIsOwned;
          message = "aos.crucibleCampaign.socketPath must be a normalized file below /run/crucible-campaign";
        }
        {
          assertion = stateDirectoryIsOwned;
          message = "aos.crucibleCampaign.stateDirectory must be a normalized path at or below /var/lib/crucible-campaign";
        }
      ];

      environment.etc."crucible/campaign-runtime.env".text = ''
        schema=aos.crucible.campaign-runtime.v1
        enabled=${
          if cfg.enable
          then "true"
          else "false"
        }
        identity=${runtimeIdentity}
        listen_address=${cfg.listenAddress}
        socket_path=${cfg.socketPath}
        state_directory=${cfg.stateDirectory}
      '';
    }
    (lib.mkIf cfg.enable {
      assertions =
        [
          {
            assertion = process != null;
            message = "An enabled Crucible campaign service requires explicit processResources partitions";
          }
          {
            assertion = partitionsFit && runtimeFits;
            message = "Campaign process partitions and runtime threads must fit the original prebirth limits";
          }
        ]
        ++ lib.optionals (executor != null) [
          {
            assertion =
              builtins.match "/run/crucible-campaign/[A-Za-z0-9][A-Za-z0-9._-]*" executor.socketPath
              != null
              && executor.socketPath != cfg.socketPath
              && executor.campaigns != []
              && builtins.all (name: builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" name != null) executor.campaigns;
            message = "Production executor requires an owned distinct socket and explicit canonical campaign names";
          }
          {
            assertion =
              executor.importManifests
              != []
              && executor.transport.operatorCertificateFingerprints != []
              && builtins.length (lib.unique executor.transport.operatorCertificateFingerprints) == builtins.length executor.transport.operatorCertificateFingerprints
              && builtins.all (fingerprint: builtins.match "[0-9a-f]{64}" fingerprint != null) executor.transport.operatorCertificateFingerprints;
            message = "Production executor requires explicit input manifests and unique authenticated host operator certificates";
          }
        ];
      # The existing native pager opens this device with USERFAULTFD_IOC_NEW.
      # This limits permission to the explicitly authored child group instead
      # of enabling the host-wide unprivileged syscall or user-only faults.
      environment.etc."udev/rules.d/80-crucible-userfaultfd.rules" = lib.mkIf (executor != null) {
        text = ''
          KERNEL=="userfaultfd", GROUP="${toString executor.userfaultfdGroupId}", MODE="0660"
        '';
      };
      environment.systemPackages = [cfg.package];
      environment.etc."crucible/campaign-process.toml".text = processPolicy;
      environment.etc."crucible/campaign-policy.toml".text = ''
        schema = "crucible.campaign-local-policy"
        version = 1

        [[bindings]]
        user_id = 0
        group_id = 0
        principal = "operator"

        [[grants]]
        principal = "operator"
        operation = "list-campaigns"
        campaign = "*"

        [[grants]]
        principal = "operator"
        operation = "get-campaign"
        campaign = "*"

        [[grants]]
        principal = "operator"
        operation = "create-campaign"
        campaign = "*"

        [[grants]]
        principal = "operator"
        operation = "attach-campaign-runtime"
        campaign = "*"

        ${lib.optionalString (executor != null) (
          lib.concatMapStringsSep "\n" (campaign:
            lib.concatMapStringsSep "\n" (operation: ''
              [[grants]]
              principal = "operator"
              operation = "${operation}"
              campaign = "${campaign}"
            '') ["get-campaign-status" "apply-campaign-command" "explain-campaign-attempt"])
          (lib.unique executor.campaigns)
        )}
      '';

      systemd.services.crucible-campaign = {
        environment = lib.optionalAttrs (executor != null) {
          CRUCIBLE_QEMU = executor.guestAssets.qemu;
          CRUCIBLE_PLUGIN = executor.guestAssets.plugin;
          CRUCIBLE_KERNEL = executor.guestAssets.kernel;
          CRUCIBLE_ROOT_IMAGE = executor.guestAssets.rootImage;
          CRUCIBLE_INITRD = executor.guestAssets.initrd;
          CRUCIBLE_NATIVE_GUEST_ARCHITECTURE = executor.guestAssets.architecture;
          CRUCIBLE_KERNEL_CMDLINE = executor.guestAssets.kernelCommandLine;
          CRUCIBLE_RUN_STATE_ROOT = executor.guestAssets.runStateRoot;
        };
        description = "Crucible campaign and lifecycle service";
        wantedBy = ["multi-user.target"];
        after = ["local-fs.target"];
        serviceConfig =
          lib.optionalAttrs (process != null) {
            MemoryMax = process.memoryMaxBytes;
            TasksMax = process.tasksMax;
            LimitNOFILE = "${toString process.fileDescriptors}:${toString process.fileDescriptors}";
            RuntimeMaxSec = process.runtimeSeconds;
            TimeoutStartSec = process.startupTimeoutSeconds;
            LimitSTACK = "${toString process.mainThreadStackBytes}:${toString process.mainThreadStackBytes}";
            CPUQuota = "${toString process.cpuQuotaPercent}%";
            CPUQuotaPeriodSec = "100ms";
          }
          // lib.optionalAttrs (executor != null) {
            Delegate = "cpu memory pids";
            DelegateSubgroup = "guardian";
            MemorySwapMax = 0;
            NoNewPrivileges = true;
            CapabilityBoundingSet = "";
            AmbientCapabilities = "";
            KillMode = "control-group";
          }
          // {
            Type = "simple";
            # A normal executor accepts only once in its original invocation.
            Restart =
              if executor == null
              then "on-failure"
              else "no";
            RestartSec = 1;
          };
        preStart = ''
          ${pkgs.coreutils}/bin/mkdir -p \
            ${lib.escapeShellArg cfg.stateDirectory} \
            ${lib.escapeShellArg (builtins.dirOf cfg.socketPath)}
          ${pkgs.coreutils}/bin/chmod 700 \
            ${lib.escapeShellArg cfg.stateDirectory} \
            ${lib.escapeShellArg (builtins.dirOf cfg.socketPath)}
          ${pkgs.coreutils}/bin/rm -f ${lib.escapeShellArg cfg.socketPath}
          ${lib.optionalString (executor != null) ''
            IFS= read -r control_group < /proc/self/cgroup
            case "$control_group" in
              0::/*/.control) service_group="''${control_group#0::}"; service_group="''${service_group%/.control}" ;;
              *) echo "executor preparation is outside PID1 control subgroup" >&2; exit 1 ;;
            esac
            # PID1 keeps preStart in .control and main in guardian, allowing the
            # authenticated service root to remain empty during delegation.
            service_root="/sys/fs/cgroup$service_group"
            ${pkgs.coreutils}/bin/mkdir -p "$service_root/guardian" "$service_root/workload"
            echo '+cpu +memory +pids' > "$service_root/cgroup.subtree_control"
            # The empty selected workload delegates the same controllers to
            # attempt children; the factory checks this before watcher birth.
            echo '+cpu +memory +pids' > "$service_root/workload/cgroup.subtree_control"
            for delegated_root in "$service_root" "$service_root/workload"; do
              IFS= read -r enabled_controllers < "$delegated_root/cgroup.subtree_control"
              for required_controller in cpu memory pids; do
                case " $enabled_controllers " in
                  *" $required_controller "*) ;;
                  *) echo "executor workload controller is unavailable" >&2; exit 1 ;;
                esac
              done
            done
            echo 0 > "$service_root/guardian/memory.swap.max"
            echo 0 > "$service_root/workload/memory.swap.max"
            test -c /dev/userfaultfd
            test "$(${pkgs.coreutils}/bin/stat -c '%g' /dev/userfaultfd)" = ${toString executor.userfaultfdGroupId}
            test "$(${pkgs.coreutils}/bin/stat -c '%a' /dev/userfaultfd)" = 660
          ''}
        '';
        script = ''
          exec ${cfg.package}/bin/crucible serve \
            --listen ${lib.escapeShellArg cfg.listenAddress} \
            ${lib.escapeShellArgs transportArguments} \
            --campaign-socket ${lib.escapeShellArg cfg.socketPath} \
            --campaign-state ${lib.escapeShellArg cfg.stateDirectory} \
            --campaign-policy /etc/crucible/campaign-policy.toml \
            --campaign-socket-mode 600 ${lib.escapeShellArgs executorArguments}
        '';
      };
    })
  ];
}

##! Typed, package-owned conntrackd service declaration.
{
  config,
  lib,
  ...
}: let
  cfg = config.conntrackd;
  inherit (lib) mkOption;
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;

  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = 9007199254740991;
  };
  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  ipv4Address = abilityTypes.refined {
    name = "conntrackd IPv4 address";
    description = "an IPv4 address accepted by conntrackd";
    type = abilityTypes.runtimeString;
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[0-9]{1,3}(\\.[0-9]{1,3}){3}";
      }
    ];
  };
  interfaceName = abilityTypes.refined {
    name = "conntrackd interface name";
    description = "a non-empty network interface name accepted by conntrackd";
    type = abilityTypes.runtimeString;
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Za-z0-9][A-Za-z0-9_.:-]*";
      }
    ];
  };
  onOff = value:
    if value
    then "on"
    else "off";
  syncConfig = lib.optionalString (cfg.mode == "sync") ''
    Sync {
      Mode FTFW {
        ResendQueueSize ${toString cfg.sync.resendQueueSize}
        ACKWindowSize ${toString cfg.sync.ackWindowSize}
      }
      UDP {
        IPv4_address ${cfg.sync.localAddress}
        IPv4_Destination_Address ${cfg.sync.peerAddress}
        Port ${toString cfg.sync.port}
        Interface ${cfg.sync.interface}
        Checksum ${onOff cfg.sync.checksum}
      }
    }
  '';
  statsConfig = lib.optionalString (cfg.mode == "stats") ''
    Stats {
      LogFile ${onOff cfg.logConnections}
    }
  '';
  literal = text: {
    kind = "literal";
    inherit text;
  };
  path = value: {
    kind = "execution-path";
    inherit value;
  };
  configPath = resultOf "daemon-configuration" "planned-path";
  runtimePath = resultOf "runtime-storage" "planned-path";
  logPath = resultOf "log-storage" "planned-path";
  configurationFragments = [
    (literal ''
      General {
        Systemd on
        HashSize ${toString cfg.hashSize}
        HashLimit ${toString cfg.hashLimit}
        LockFile
    '')
    (path runtimePath)
    (literal ''
      /conntrackd.lock
        UNIX {
          Path
    '')
    (path runtimePath)
    (literal ''
      /conntrackd.ctl
        }
        NetlinkBufferSize ${toString cfg.netlinkBufferSize}
        NetlinkBufferSizeMaxGrowth ${toString cfg.netlinkBufferSizeMaxGrowth}
        ${lib.optionalString (cfg.pollSeconds != null) "PollSecs ${toString cfg.pollSeconds}"}
        LogFile
    '')
    (path logPath)
    (literal ''
      /conntrackd.log
      }
      ${statsConfig}
      ${syncConfig}
    '')
  ];
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "sbin/conntrackd";
      inherit arguments;
    };
    ignore_failure = false;
  };
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "conntrack-tools";
      inherit key interface parameters;
    };
  runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
    name = "runtime";
    purpose = "runtime";
    mode = "0750";
  };
  logStorage = producer "log-storage" serviceManagement.interfaces.persistentStorageAllocation {
    name = "logs";
    purpose = "logs";
    mode = "0750";
  };
  networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = ["ipv4"];
  };
  configuration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "conntrack-tools";
    declaration = {
      name = "daemon-configuration";
      source = {
        kind = "interpolated-text";
        fragments = configurationFragments;
        maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
      };
      mode = "0444";
    };
  };
  service = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "hardening";
        requirementAlias = "service-hardening";
        description = "Requires the selected service-management provider to enforce the declared service hardening policy.";
        interface = "aos.service.hardening";
        abi = 1;
        parameters = {
          allow_privilege_escalation = false;
          ambient_privileges = ["administer-network" "raw-network"];
          privilege_bounds = {
            kind = "restricted";
            privileges = ["administer-network" "raw-network"];
          };
          resource_control_delegation = false;
          resource_control_access = "read-only";
          device_access_scope = "shared";
          host_clock_mutation = false;
          host_name_mutation = false;
          operating_system_log_access = false;
          operating_system_extension_access = false;
          operating_system_tunable_access = false;
          lock_execution_personality = true;
          writable_executable_memory = false;
          isolation_domains = [];
          network_families = ["ipv4" "ipv6" "route-control" "raw-packet" "local"];
          memory_pressure_adjustment = 0;
          permit_realtime = false;
          permit_elevated_file_identity = false;
          process_visibility = "all";
          security_label = "aos-pkg-conntrackd";
          operation_architectures = [];
          operation_allow = [];
          operation_deny = [];
          operation_profile = "system-service";
          isolated_identity_mapping = "none";
        };
      })
    ];
    inherit serviceTypes;
    consumerInstance = "conntrack-tools";
    declaration = {
      service = "main";
      enabled = true;
      lifecycle = {
        description = "Connection tracking state daemon";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [(command ["-C" configPath "-d"])];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_token = cfg.restartToken;
        restart_delay_millis = 1000;
        configuration_change_action = "restart";
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 60000;
      };
      dependencies = {
        after = [(resultOf "network-readiness" "resource")];
        before = [];
        requires = [];
        wants = [(resultOf "network-readiness" "resource")];
      };
      supervision = {
        startup_protocol = "notification";
        notification_access = "main-process";
      };
      readiness = {
        mechanism = "process-signal";
        signal_scope = "main-process";
        timeout_millis = 90000;
      };
      reload = {
        strategy = "command";
        commands = [(command ["-C" configPath "-R"])];
        completion = "command-exit";
      };
      configuration.views = [
        {
          name = "daemon";
          source = configPath;
          optional = false;
        }
      ];
      storage.mounts = [
        {
          name = "runtime";
          source = runtimePath;
          access = "read-write";
        }
        {
          name = "logs";
          source = logPath;
          access = "read-write";
        }
      ];
      logging = {
        standard_output = "structured";
        standard_error = "structured";
        directories = [];
        directory_mode = "0750";
      };
      identity = {
        supplementary_groups = [];
        ephemeral = false;
        file_creation_mask = "0027";
      };
      isolation = {
        privilege = "unprivileged";
        filesystem = "read-only-system";
        network = "host";
        process_visibility = "host";
        termination_scope = "all-processes";
        temporary_directory = "private";
        devices = [];
        host_paths = [];
        permit_core_dumps = false;
      };
    };
  };
  abilityFragments = [
    runtimeStorage
    logStorage
    networkReadiness
    configuration
    service
  ];
  staticAbilityFragments =
    builtins.map
    (fragment: (serviceManagement.splitContribution fragment).declarations)
    abilityFragments;
  configuredAbilityFragments =
    builtins.map
    (fragment: (serviceManagement.splitContribution fragment).configured)
    abilityFragments;
in {
  options.conntrackd = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Enable the package-owned connection tracking daemon.";
    };
    restartToken = mkOption {
      type = abilityTypes.optional serviceTypes.restartToken;
      default = null;
      description = "Operator-controlled token whose change requests a service restart.";
    };
    mode = mkOption {
      type = abilityTypes.enum ["stats" "sync"];
      default = "stats";
      description = "Run as a local statistics collector or an FTFW state replicator.";
    };
    hashSize = mkOption {
      type = positiveInt;
      default = 8192;
      description = "Number of daemon cache hash buckets.";
    };
    hashLimit = mkOption {
      type = positiveInt;
      default = 65535;
      description = "Maximum number of tracked connections in daemon caches.";
    };
    netlinkBufferSize = mkOption {
      type = positiveInt;
      default = 262142;
      description = "Initial netlink receive buffer size in bytes.";
    };
    netlinkBufferSizeMaxGrowth = mkOption {
      type = positiveInt;
      default = 655355;
      description = "Maximum dynamically grown netlink buffer size in bytes.";
    };
    pollSeconds = mkOption {
      type = abilityTypes.optional positiveInt;
      default = null;
      description = "Optional kernel conntrack polling interval.";
    };
    logConnections = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Log destroyed connections in statistics mode.";
    };
    sync = {
      localAddress = mkOption {
        type = ipv4Address;
        default = "127.0.0.1";
        description = "Local IPv4 address of the dedicated replication link.";
      };
      peerAddress = mkOption {
        type = ipv4Address;
        default = "127.0.0.1";
        description = "Peer IPv4 address receiving replicated state.";
      };
      interface = mkOption {
        type = interfaceName;
        default = "lo";
        description = "Dedicated replication network interface.";
      };
      port = mkOption {
        type = port;
        default = 3780;
        description = "UDP replication port.";
      };
      checksum = mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Verify checksums on state replication messages.";
      };
      resendQueueSize = mkOption {
        type = positiveInt;
        default = 131072;
        description = "Maximum FTFW resend queue length.";
      };
      ackWindowSize = mkOption {
        type = positiveInt;
        default = 300;
        description = "FTFW acknowledgement window size.";
      };
    };
  };

  config = lib.mkMerge (
    [
      {
        assertions = [
          {
            assertion = cfg.hashLimit >= cfg.hashSize;
            message = "conntrackd.hashLimit must be at least conntrackd.hashSize";
          }
          {
            assertion = cfg.mode != "sync" || cfg.sync.localAddress != cfg.sync.peerAddress;
            message = "conntrackd sync localAddress and peerAddress must differ";
          }
        ];
      }
      (lib.mkMerge (builtins.map
        (fragment: {aos.abilities = fragment;})
        staticAbilityFragments))
      (lib.mkIf cfg.enable {aos.abilities.instances."conntrack-tools" = {};})
    ]
    ++ builtins.map
    (mode:
      lib.mkIf
      (cfg.enable && cfg.mode == mode)
      (lib.mkMerge (builtins.map
        (fragment: {aos.abilities = fragment;})
        configuredAbilityFragments)))
    ["stats" "sync"]
  );
}

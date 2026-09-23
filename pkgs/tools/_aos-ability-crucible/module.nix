##! Package-owned Ability Crucible endpoint and service declaration.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.services.abilityCrucible;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  packageArtifact = lib.abilities.packageOutput {};
  settings = import ./settings.nix {socketName = cfg.socketName;};
  inherit (settings) runtimePath socketPath;
  readinessTimeoutMillis = 30000;

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "ability-crucible";
      inherit key interface parameters;
    };
  runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
    name = "ability-crucible";
    purpose = "runtime";
    mode = "0700";
    requested_path = runtimePath;
  };
  adapterConfiguration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "ability-crucible";
    declaration = {
      name = "configuration-file";
      source = {
        kind = "interpolated-text";
        fragments = [
          {
            kind = "literal";
            text = ''{"required_instruction_abi":1,"required_marker_kinds":["assertion","coverage","event","lifecycle"],"schema":"aos.ability-crucible-adapter/v1","socket":"'';
          }
          {
            kind = "execution-path";
            value = socketPath;
          }
          {
            kind = "literal";
            text = ''"}'';
          }
        ];
        maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
      };
      mode = "0400";
    };
  };
  command = arguments: {
    executable = {
      artifact = packageArtifact;
      entry_point = "bin/aos-ability-crucible";
      inherit arguments;
    };
    ignore_failure = false;
  };
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "ability-crucible";
    declaration = {
      service = "adapter";
      enabled = true;
      lifecycle = {
        description = "AOS ability boundary adapter (${packageName} ${packageVersion})";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [(command ["--config" (resultOf "configuration-file" "planned-path")])];
        post_start = [(command ["--wait-ready" socketPath])];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_delay_millis = 1000;
        configuration_change_action = "restart";
        remain_after_exit = false;
        start_timeout_millis = readinessTimeoutMillis;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        prerequisites = [
          (resultOf "runtime-storage" "resource")
          (resultOf "configuration-file" "resource")
        ];
        after = [];
        before = [];
        requires = [];
        wants = [];
      };
      supervision = {
        startup_protocol = "process";
        notification_access = "none";
      };
      manager_identity = {
        name = "aos-ability-crucible";
        aliases = [];
      };
      readiness = {
        mechanism = "process-running";
        signal_scope = "none";
        timeout_millis = readinessTimeoutMillis;
      };
      configuration.views = [
        {
          name = "adapter";
          source = resultOf "configuration-file" "planned-path";
          optional = false;
        }
      ];
      storage.mounts = [
        {
          name = "runtime";
          source = resultOf "runtime-storage" "planned-path";
          access = "read-write";
        }
      ];
      logging = {
        standard_output = "structured";
        standard_error = "structured";
        directories = [];
        directory_mode = "0700";
      };
      identity = {
        supplementary_groups = [];
        ephemeral = false;
        file_creation_mask = "0077";
      };
      isolation = {
        privilege = "privileged";
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
  endpointInterface = lib.abilities.interfaces.executionObservationEndpoint.interfaces.endpoint;
  endpoint = producer "observer-endpoint" endpointInterface {endpoint = "default";};
  fragments = [runtimeStorage adapterConfiguration service endpoint];
  definitions = builtins.map serviceManagement.splitDefinition fragments;
in {
  imports = [
    ./endpoint-implementation.nix
    ./endpoint-provider.nix
  ];

  options.aos.serviceOptionModules.abilityCrucible = lib.mkOption {
    type = lib.types.deferredModule;
    default.options = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Run the protected Ability Crucible execution-boundary adapter.";
      };
      socketName = lib.mkOption {
        type = abilityTypes.localKey;
        default = "controller.sock";
        description = "Runtime-directory entry used for the protected observer socket.";
      };
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (definition: definition.declarations) definitions
      );
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [
          {instances.ability-crucible = {};}
        ]
        ++ builtins.map (definition: definition.configured) definitions
      );
    })
  ];
}

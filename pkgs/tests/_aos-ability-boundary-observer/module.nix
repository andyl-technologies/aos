##! Package-owned fleet execution observer endpoint and controller service.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.tests.executionObserver;
  settings = import ./settings.nix;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  inherit (lib.abilities) resultOf;
  forwardEndpointInterface = {
    name = "aos.execution.observation-endpoint";
    abi = 1;
    descriptor = null;
  };
  forwardEndpointRequirement = {
    description = "Discovers the selected protected execution observer endpoint.";
    interface = forwardEndpointInterface.name;
    inherit (forwardEndpointInterface) abi descriptor;
    methods = ["observe"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  forwardEndpointRequest = {
    requirement = "forward-endpoint";
    consumer = "boundary-observer";
    scope = ["forward-endpoint"];
    parameters.endpoint = "default";
  };

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "boundary-observer";
      inherit key interface parameters;
    };
  runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
    name = "ability-boundary-observer-runtime";
    purpose = "runtime";
    mode = "0700";
    requested_path = settings.runtimeRoot;
  };
  stateStorage = producer "state-storage" serviceManagement.interfaces.persistentStorageAllocation {
    name = "ability-boundary-observer-state";
    purpose = "state";
    mode = "0700";
    requested_path = settings.stateRoot;
  };
  controllerCommand = {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/aos-ability-boundary-controller";
      arguments = [
        "serve"
        "--socket"
        settings.socketPath
      ];
    };
    ignore_failure = false;
  };
  controllerService = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "boundary-observer";
    declaration = {
      service = "controller";
      enabled = true;
      lifecycle = {
        description = "AOS fleet ability boundary observer (${packageName} ${packageVersion})";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [controllerCommand];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_delay_millis = 1000;
        configuration_change_action = "restart";
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        prerequisites =
          [
            (resultOf "runtime-storage" "retained-resource")
            (resultOf "state-storage" "retained-resource")
          ]
          ++ lib.optional cfg.forwardToSelectedEndpoint (resultOf "forward-endpoint" "retained-resource");
        after = lib.optional cfg.forwardToSelectedEndpoint (resultOf "forward-endpoint" "retained-resource");
        before = [];
        requires = lib.optional cfg.forwardToSelectedEndpoint (resultOf "forward-endpoint" "retained-resource");
        wants = [];
      };
      environment = {
        variables = lib.optionalAttrs cfg.forwardToSelectedEndpoint {
          AOS_ABILITY_FORWARD_SOCKET = resultOf "forward-endpoint" "socket-path";
        };
        search_path = [];
      };
      storage.mounts = [
        {
          name = "runtime";
          source = resultOf "runtime-storage" "planned-path";
          access = "read-write";
        }
        {
          name = "state";
          source = resultOf "state-storage" "planned-path";
          access = "read-write";
        }
      ];
      socket_activation.sockets = [
        {
          name = "observer";
          manager_name = "aos-ability-boundary-controller";
          enabled = true;
          endpoints = [
            {
              kind = "unix";
              path = settings.socketPath;
            }
          ];
          mode = "0600";
          remove_on_stop = true;
          prerequisites = [(resultOf "runtime-storage" "retained-resource")];
        }
      ];
      manager_identity = {
        name = "aos-ability-boundary-controller";
        aliases = [];
      };
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
        filesystem = "host";
        network = "host";
        process_visibility = "host";
        termination_scope = "all-processes";
        temporary_directory = "shared";
        devices = [];
        host_paths = [];
        permit_core_dumps = false;
      };
    };
  };
  endpointInterface = {
    alias = "execution-observer-endpoint";
    declaration = config.aos.abilities.interfaces."${packageName}:execution-observer-endpoint";
  };
  endpoint = producer "endpoint" endpointInterface {
    hosting = cfg.mode;
    service_resource =
      if cfg.mode == "managed-service"
      then resultOf "controller-lifecycle" "service-resource"
      else null;
    socket_path = settings.socketPath;
  };
  fragments = [runtimeStorage stateStorage controllerService endpoint];
  contributions = builtins.map serviceManagement.splitContribution fragments;
  configuredFragments =
    [endpoint]
    ++ lib.optionals (cfg.mode == "managed-service") [
      runtimeStorage
      stateStorage
      controllerService
    ];
in {
  imports = [
    ./endpoint-interface.nix
    ./endpoint-provider.nix
  ];

  options.aos.tests.executionObserver = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Select the package-owned fleet execution observer endpoint.";
    };
    mode = lib.mkOption {
      type = abilityTypes.enum ["managed-service" "external-test-mount"];
      default = "managed-service";
      description = "Whether this system owns the controller or consumes the test's externally mounted socket.";
    };
    forwardToSelectedEndpoint = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Forward observed events to the endpoint selected by the package requirement.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        [
          {requirementTemplates.forward-endpoint = forwardEndpointRequirement;}
        ]
        ++ builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [
          {
            instances.boundary-observer = {};
          }
          (lib.optionalAttrs cfg.forwardToSelectedEndpoint {
            requests.forward-endpoint = forwardEndpointRequest;
          })
        ]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        configuredFragments
      );
    })
  ];
}

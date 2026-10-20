##! Native fleet boundary observer service or explicit external test endpoint.
{
  config,
  lib,
  package,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.tests.executionObserver;
  settings = import ./settings.nix;
  managerOwned = cfg.activationOwner == "manager";
  runtimeDirectory = {
    path = settings.runtimeRoot;
    mode = "0700";
    owner = "root";
    group = "root";
  };
  stateDirectory = {
    path = settings.stateRoot;
    mode = "0700";
    owner = "root";
    group = "root";
  };
  runtimePath =
    if managerOwned
    then settings.runtimeRoot
    else config.aos.abilities.filesystem.operations.directory.effects.boundary-observer-runtime.outputs.path;
  statePath =
    if managerOwned
    then settings.stateRoot
    else config.aos.abilities.filesystem.operations.persistentAllocate.effects.boundary-observer-state.outputs.path;
  controllerCommand = {
    executable = {
      path = "${package}/bin/aos-ability-boundary-controller";
      arguments = [
        "serve"
        "--socket"
        settings.socketPath
      ];
    };
    ignore_failure = false;
  };
  controllerService = {
    service = "aos-ability-boundary-controller";
    activationOwner = cfg.activationOwner;
    activationAfter = lib.optionals (!managerOwned) [runtimePath statePath];
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
      after = [];
      before = [];
      requires = [];
      wants = [];
    };
    environment = {
      variables = lib.optionalAttrs (cfg.forwardSocketPath != null) {
        AOS_ABILITY_FORWARD_SOCKET = cfg.forwardSocketPath;
      };
      search_path = [];
    };
    storage.mounts = [
      {
        name = "runtime";
        source = runtimePath;
        access = "read-write";
      }
      {
        name = "state";
        source = statePath;
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
in {
  options.aos.tests.executionObserver = {
    activationOwner = lib.mkOption {
      type = lib.types.enum ["ability" "manager"];
      default = "ability";
      description = "Assign listener directories and startup to native realization or the image manager.";
    };
    bootstrap = lib.mkOption {
      readOnly = true;
      default = {
        serviceKey = "boundary-observer.controller";
        directories = [];
        files = [];
      };
      description = "Image bootstrap projection of the package-authored listener allocations.";
      type = lib.types.submodule {
        options = {
          serviceKey = lib.mkOption {type = lib.types.str;};
          directories = lib.mkOption {type = lib.types.listOf (lib.types.submodule config.aos.abilities.filesystem.operations.directory.input);};
          files = lib.mkOption {type = lib.types.listOf (lib.types.submodule config.aos.abilities.configuration.operations.file.input);};
        };
      };
    };

    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Select the native fleet observer endpoint.";
    };
    mode = lib.mkOption {
      type = lib.types.enum ["managed-service" "external-test-mount"];
      default = "managed-service";
      description = "Own the controller service or consume an externally mounted test endpoint.";
    };
    forwardSocketPath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Explicit protected downstream native observer socket.";
    };
  };
  config = lib.mkIf cfg.enable (lib.mkMerge [
    {aos.execution.observer = {socketPath = settings.socketPath;};}
    (lib.mkIf (cfg.mode == "managed-service") {
      aos.abilities.filesystem.operations.directory.effects = lib.mkIf (!managerOwned) {boundary-observer-runtime.input = runtimeDirectory;};
      aos.abilities.filesystem.operations.persistentAllocate.effects = lib.mkIf (!managerOwned) {
        boundary-observer-state = {
          lifetime = "persistent";
          input = stateDirectory;
        };
      };
      aos.tests.executionObserver.bootstrap = {
        serviceKey = "boundary-observer.controller";
        directories = lib.optionals managerOwned [runtimeDirectory stateDirectory];
        files = [];
      };
      aos.services."boundary-observer.controller" = controllerService // {enable = true;};
    })
  ]);
}

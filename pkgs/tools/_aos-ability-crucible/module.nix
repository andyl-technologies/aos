##! Native service and explicit endpoint for Crucible boundary instrumentation.
{
  config,
  lib,
  package,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.abilityCrucible;
  settings = import ./settings.nix {socketName = cfg.socketName;};
  inherit (settings) runtimePath socketPath;
  runtimeResource = config.aos.abilities.filesystem.operations.directory.effects.ability-crucible.outputs.resource;
  managerOwned = cfg.activationOwner == "manager";
  configurationFile = {
    path = "/run/aos/ability-crucible.json";
    mode = "0400";
    content = builtins.toJSON {
      schema = "aos.ability-crucible-adapter/v1";
      socket = socketPath;
      required_instruction_abi = 1;
      required_marker_kinds = ["assertion" "coverage" "event" "lifecycle"];
    };
  };
  runtimeDirectory = {
    path = runtimePath;
    mode = "0700";
    owner = "root";
    group = "root";
  };
  configurationPath =
    if managerOwned
    then configurationFile.path
    else config.aos.abilities.configuration.operations.file.effects.ability-crucible.outputs.path;
  readinessTimeoutMillis = 30000;
  command = arguments: {
    executable = {
      path = "${package}/bin/aos-ability-crucible";
      inherit arguments;
    };
    ignore_failure = false;
  };
  service = {
    service = "aos-ability-crucible";
    activationOwner = cfg.activationOwner;
    activationAfter = lib.optionals (!managerOwned) [runtimeResource configurationPath];
    lifecycle = {
      description = "AOS ability boundary adapter (${packageName} ${packageVersion})";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command ["--config" configurationPath])];
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
        source = configurationPath;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "runtime";
        source = runtimePath;
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
in {
  options.aos.abilityCrucible = {
    activationOwner = lib.mkOption {
      type = lib.types.enum ["ability" "manager"];
      default = "ability";
      description = "Assign listener bootstrap to the native image manager or to ability realization.";
    };
    bootstrap = lib.mkOption {
      readOnly = true;
      default = {
        serviceKey = "ability-crucible.adapter";
        directories = [];
        files = [];
      };
      description = "Image bootstrap projection of the same package-authored listener inputs.";
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
      description = "Run the protected native boundary adapter.";
    };
    socketName = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9._-]+";
      default = "controller.sock";
      description = "Protected observer socket name.";
    };
  };
  config = lib.mkIf cfg.enable {
    aos.execution.observer = lib.mkDefault {inherit socketPath;};
    aos.abilities.filesystem.operations.directory.effects = lib.mkIf (!managerOwned) {ability-crucible.input = runtimeDirectory;};
    aos.abilities.configuration.operations.file.effects.ability-crucible.input = configurationFile;
    aos.abilityCrucible.bootstrap = {
      serviceKey = "ability-crucible.adapter";
      directories = lib.optional managerOwned runtimeDirectory;
      files = lib.optional managerOwned configurationFile;
    };
    aos.services."ability-crucible.adapter" = service // {enable = true;};
  };
}

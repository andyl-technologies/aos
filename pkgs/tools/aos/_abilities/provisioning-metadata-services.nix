##! Package-owned initrd metadata acquisition and provisioning services.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.metadata.initrdServices;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "provisioning-metadata-services";
  initrdStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "initrd";

  command = operation: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {output = "metadataRuntime";};
      entry_point = "libexec/aos-metadata-initrd-service";
      arguments = [operation] ++ arguments;
    };
    ignore_failure = false;
  };
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
  milestone = key: name:
    producer key interfaces.systemMilestoneReadiness {milestone = name;};
  initrdRootFilesystems = milestone "initrd-root-filesystems" "initrd-root-filesystems";
  deviceManager = milestone "device-manager" "device-manager";
  deviceEvents = milestone "device-events" "device-events-triggered";
  deviceSettle = milestone "device-settle" "device-settle";
  networkReadiness = producer "network-readiness" interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = ["ipv4" "ipv6"];
  };
  readiness = key: resultOf key "readiness-resource";
  serviceResource = service: resultOf "${service}-lifecycle" "service-resource";
  emptyDependencies = {
    prerequisites = [];
    after = [];
    before = [];
    requires = [];
    wants = [];
    requisite = [];
    conflicts = [];
    binds_to = [];
    part_of = [];
    upholds = [];
    required_by = [];
    wanted_by = [];
    required_mounts = [];
    implicit_dependencies = false;
  };
  serviceEnvironment = variables: {
    inherit variables;
    search_path = builtins.map lib.abilities.packageOutput [
      {package = "coreutils";}
      {
        package = "aos";
        output = "metadataRuntime";
      }
      {package = "nix";}
      {package = "systemd";}
      {package = "util-linux";}
    ];
  };
  structuredLogging = {
    standard_output = "structured-and-console";
    standard_error = "structured-and-console";
    namespace = null;
    directories = [];
    directory_mode = "0755";
  };
  service = {
    key,
    description,
    operation,
    arguments ? [],
    dependencies,
    conditions ? null,
    variables ? {},
    logging ? null,
  }:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration =
        {
          service = key;
          enabled = true;
          lifecycle = {
            inherit description;
            execution_model = "oneshot";
            environment_files = [];
            condition = [];
            pre_start = [];
            start = [(command operation arguments)];
            post_start = [];
            stop = [];
            post_stop = [];
            restart = "never";
            restart_delay_millis = 0;
            configuration_change_action = "restart";
            remain_after_exit = true;
            start_timeout_millis = 90000;
            stop_timeout_millis = 90000;
          };
          inherit dependencies;
          readiness = {
            mechanism = "successful-exit";
            signal_scope = "none";
            timeout_millis = 90000;
          };
          environment = serviceEnvironment variables;
        }
        // lib.optionalAttrs (conditions != null) {inherit conditions;}
        // lib.optionalAttrs (logging != null) {inherit logging;};
    };

  rootFilesystemsReadiness = readiness "initrd-root-filesystems";
  deviceManagerReadiness = readiness "device-manager";
  deviceEventsReadiness = readiness "device-events";
  deviceSettleReadiness = readiness "device-settle";
  networkReady = readiness "network-readiness";

  provisioningState = service {
    key = "aos-provisioning-state";
    description = "Detect durable first-boot provisioning state";
    operation = "detect-state";
    arguments = [cfg.stashDir];
    dependencies =
      emptyDependencies
      // {
        after = [deviceManagerReadiness deviceEventsReadiness deviceSettleReadiness];
        before = builtins.map serviceResource [
          "aos-metadata-detect"
          "aos-metadata-fetch"
          "aos-metadata-authorize"
          "aos-provisioning-eval"
        ];
        requires = [deviceManagerReadiness deviceEventsReadiness];
        wanted_by = [rootFilesystemsReadiness];
      };
  };
  metadataDetect = service {
    key = "aos-metadata-detect";
    description = "Detect the metadata platform and configuration drive";
    operation = "detect-platform";
    arguments = [cfg.stashDir];
    dependencies =
      emptyDependencies
      // {
        after = [
          (serviceResource "aos-provisioning-state")
          deviceManagerReadiness
          deviceEventsReadiness
        ];
        before = builtins.map serviceResource ["aos-metadata-fetch" "aos-metadata-authorize"];
        requires = [
          (serviceResource "aos-provisioning-state")
          deviceManagerReadiness
          deviceEventsReadiness
        ];
        wanted_by = [rootFilesystemsReadiness];
      };
    logging = structuredLogging;
  };
  metadataNetwork = service {
    key = "aos-metadata-network";
    description = "Bring up networking for network-dependent metadata platforms";
    operation = "network-ready";
    dependencies =
      emptyDependencies
      // {
        after = [(serviceResource "aos-metadata-detect") networkReady];
        before = [(serviceResource "aos-metadata-fetch")];
        requires = [(serviceResource "aos-metadata-detect")];
        wants = [networkReady];
        wanted_by = [rootFilesystemsReadiness];
      };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "${cfg.stashDir}/need-network";
        negated = false;
      }
    ];
  };
  metadataFetch = service {
    key = "aos-metadata-fetch";
    description = "Fetch operator configuration and instance facts";
    operation = "fetch";
    arguments = [cfg.stashDir];
    dependencies =
      emptyDependencies
      // {
        after = builtins.map serviceResource ["aos-metadata-detect" "aos-metadata-network"];
        before = [(serviceResource "aos-metadata-authorize") rootFilesystemsReadiness];
        requires = [(serviceResource "aos-metadata-detect")];
        wanted_by = [rootFilesystemsReadiness];
      };
    logging = structuredLogging;
  };
  authorizationArguments =
    [cfg.stashDir cfg.trust]
    ++ lib.optional (cfg.trust == "signed") cfg.trustedConfigKeysDir;
  metadataAuthorize = service {
    key = "aos-metadata-authorize";
    description = "Authorize exact first-boot host.nix";
    operation = "authorize";
    arguments = authorizationArguments;
    dependencies =
      emptyDependencies
      // {
        after = [(serviceResource "aos-metadata-fetch")];
        before = [(serviceResource "aos-provisioning-eval") rootFilesystemsReadiness];
        requires = [(serviceResource "aos-metadata-fetch")];
        required_by = [rootFilesystemsReadiness];
      };
    logging = structuredLogging;
  };
  provisioningEvaluation = service {
    key = "aos-provisioning-eval";
    description = "Evaluate and validate one-time host provisioning";
    operation = "evaluate-provisioning";
    arguments = [
      cfg.stashDir
      cfg.baseLibrary
      (
        if cfg.measuredBoot
        then "true"
        else "false"
      )
    ];
    dependencies =
      emptyDependencies
      // {
        after = [(serviceResource "aos-metadata-authorize")];
        before = [rootFilesystemsReadiness];
        requires = [(serviceResource "aos-metadata-authorize")];
        required_by = [rootFilesystemsReadiness];
      };
    variables.NIX_CONFIG = "experimental-features = nix-command";
    logging = structuredLogging;
  };
  fragments = [
    initrdRootFilesystems
    deviceManager
    deviceEvents
    deviceSettle
    networkReadiness
    provisioningState
    metadataDetect
    metadataNetwork
    metadataFetch
    metadataAuthorize
    provisioningEvaluation
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.metadata.initrdServices = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether the package-owned initrd metadata services are active.";
    };
    stashDir = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/run/aos-metadata";
      internal = true;
      description = "Runtime directory shared by the package-owned metadata commands.";
    };
    trust = lib.mkOption {
      type = lib.abilities.types.enum ["platform" "signed"];
      default = "platform";
      internal = true;
      description = "Trust policy applied by the metadata authorization command.";
    };
    trustedConfigKeysDir = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/nonexistent/aos-provisioning-trust-anchors";
      internal = true;
      description = "Immutable trusted configuration key directory used in signed mode.";
    };
    baseLibrary = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/nonexistent/aos-base-lib";
      internal = true;
      description = "ABI-pinned base module library used by restricted provisioning evaluation.";
    };
    measuredBoot = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether provisioning evaluation must retain measured-boot storage semantics.";
    };
  };

  config = lib.mkMerge [
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);}
    (lib.mkIf (initrdStage && cfg.enable) {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (entry: entry.configured) contributions
      );
    })
  ];
}

##! Package-owned initrd verification of the complete dm-verity root.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.verityRootVerification;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "verity-root-verification";
  initrdStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "initrd";

  command = {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/aos-verity-root-verify";
      arguments = [];
    };
    ignore_failure = false;
  };
  systemMilestone = key: name:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.systemMilestoneReadiness;
      parameters.milestone = name;
    };
  bootIdentity = systemMilestone "boot-identity" "boot-identity-validated";
  verityRootMapping = systemMilestone "verity-root-mapping" "verity-root-mapping-ready";
  deviceEvents = systemMilestone "device-events" "device-settle";
  initrdStageExecution = systemMilestone "initrd-stage" "initrd-stage-executed";
  initrdFilesystems = systemMilestone "initrd-filesystems" "initrd-filesystems";
  persistentState = systemMilestone "persistent-state" "var";
  integrityFailure = systemMilestone "integrity-failure" "boot-integrity-failure";

  verification = serviceManagement.forService {
    inherit serviceTypes consumerInstance;
    declaration = {
      service = "aos-verity-root-verify";
      enabled = true;
      lifecycle = {
        description = "Verify the complete dm-verity root before persistent state";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [command];
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
      manager_identity = {
        name = "aos-verity-root-verify";
        aliases = [];
      };
      dependencies = {
        prerequisites = [];
        after = [
          (resultOf "boot-identity" "readiness-resource")
          (resultOf "verity-root-mapping" "readiness-resource")
          (resultOf "initrd-stage" "readiness-resource")
          (resultOf "device-events" "readiness-resource")
        ];
        before = [
          (resultOf "persistent-state" "readiness-resource")
          (resultOf "initrd-filesystems" "readiness-resource")
        ];
        requires = [
          (resultOf "boot-identity" "readiness-resource")
          (resultOf "verity-root-mapping" "readiness-resource")
        ];
        wants = [(resultOf "device-events" "readiness-resource")];
        requisite = [];
        conflicts = [];
        binds_to = [];
        part_of = [];
        upholds = [];
        required_by = [
          (resultOf "persistent-state" "readiness-resource")
          (resultOf "initrd-filesystems" "readiness-resource")
        ];
        wanted_by = [];
        required_mounts = [];
        implicit_dependencies = false;
      };
      failure_policy = {
        handlers = [(resultOf "integrity-failure" "readiness-resource")];
        dispatch = "isolate-active-goal";
      };
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 90000;
      };
    };
  };
  fragments = [
    bootIdentity
    verityRootMapping
    deviceEvents
    initrdStageExecution
    initrdFilesystems
    persistentState
    integrityFailure
    verification
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.security.verityRootVerification.enable = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = false;
    description = "Verify every dm-verity root block before persistent state is exposed.";
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf (cfg.enable && initrdStage) {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
    })
  ];
}

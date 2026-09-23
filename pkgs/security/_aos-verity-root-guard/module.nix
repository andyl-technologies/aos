##! Package-owned initrd verification of the complete dm-verity root.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.verityRootVerification;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  milestones = serviceManagement.milestones;
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
  bootIdentity = systemMilestone "boot-identity" milestones.bootIdentityValidated;
  verityRootMapping = systemMilestone "verity-root-mapping" milestones.verityRootMappingReady;
  deviceEvents = systemMilestone "device-events" milestones.deviceSettle;
  initrdStageExecution = systemMilestone "initrd-stage" milestones.initrdStageExecuted;
  initrdFilesystems = systemMilestone "initrd-filesystems" milestones.initrdFilesystems;
  persistentState = systemMilestone "persistent-state" milestones.var;
  integrityFailure = systemMilestone "integrity-failure" milestones.bootIntegrityFailure;

  verificationService = {
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
        (resultOf "boot-identity" "resource")
        (resultOf "verity-root-mapping" "resource")
        (resultOf "initrd-stage" "resource")
        (resultOf "device-events" "resource")
      ];
      before = [
        (resultOf "persistent-state" "resource")
        (resultOf "initrd-filesystems" "resource")
      ];
      requires = [
        (resultOf "boot-identity" "resource")
        (resultOf "verity-root-mapping" "resource")
      ];
      wants = [(resultOf "device-events" "resource")];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [
        (resultOf "persistent-state" "resource")
        (resultOf "initrd-filesystems" "resource")
      ];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
    failure_policy = {
      handlers = [(resultOf "integrity-failure" "resource")];
      dispatch = "isolate-active-goal";
    };
    readiness = {
      mechanism = "successful-exit";
      signal_scope = "none";
      timeout_millis = 90000;
    };
  };
  producers = [
    bootIdentity
    verityRootMapping
    deviceEvents
    initrdStageExecution
    initrdFilesystems
    persistentState
    integrityFailure
  ];
in {
  options.aos.security.verityRootVerification.enable = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = false;
    description = "Verify every dm-verity root block before persistent state is exposed.";
  };

  config = lib.mkMerge [
    {
      aos.services."verity-root-verification.aos-verity-root-verify" = verificationService // {enable = cfg.enable && initrdStage;};
    }
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = cfg.enable && initrdStage;
    })
  ];
}

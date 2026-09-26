##! Owns systemd's dynamic initrd dm-verity setup transaction.
{
  config,
  lib,
  ...
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  milestones = serviceManagement.milestones;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "systemd-verity-root";
  initrdStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "initrd";

  milestone = key: name:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.systemMilestoneReadiness;
      parameters.milestone = name;
    };
  bootIdentity = milestone "boot-identity" milestones.bootIdentityValidated;
  deviceManager = milestone "device-manager" milestones.deviceManager;
  deviceEvents = milestone "device-events" milestones.deviceEventsTriggered;
  deviceSettle = milestone "device-settle" milestones.deviceSettle;
  integrityFailure = milestone "integrity-failure" milestones.bootIntegrityFailure;
  readiness = key: resultOf key "resource";

  setup = {
    inherit consumerInstance;
    service = "aos-systemd-verity-root-setup";
    lifecycle = {
      description = "Materialize and start systemd's verified root mapping";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            artifact = lib.abilities.packageOutput {};
            entry_point = "libexec/aos-systemd-verity-root-setup";
            arguments = [];
          };
          ignore_failure = false;
        }
      ];
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
    dependencies = {
      prerequisites = [];
      after = builtins.map readiness [
        "boot-identity"
        "device-manager"
        "device-events"
        "device-settle"
      ];
      before = [];
      requires = builtins.map readiness ["boot-identity" "device-manager" "device-events"];
      wants = [(readiness "device-settle")];
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
    failure_policy = {
      handlers = [(readiness "integrity-failure")];
      dispatch = "isolate-active-goal";
    };
    readiness = {
      mechanism = "successful-exit";
      signal_scope = "none";
      timeout_millis = 90000;
    };
    environment = {
      variables = {};
      search_path = builtins.map lib.abilities.packageOutput [
        {}
        {package = "coreutils";}
      ];
    };
  };
  producers = [
    bootIdentity
    deviceManager
    deviceEvents
    deviceSettle
    integrityFailure
  ];
in {
  config = lib.mkMerge [
    {
      aos.services."systemd-verity-root.aos-systemd-verity-root-setup" =
        setup
        // {
          enable = initrdStage;
        };
    }
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = initrdStage;
    })
  ];
}

##! Package-owned recovery of interrupted credential publication.
{
  config,
  lib,
  ...
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "credential-recovery";
  hostStage =
    config.aos.abilities.environment != null
    && config.aos.abilities.environment.stage == "host";

  localFilesystems = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "local-filesystems";
    interface = interfaces.filesystemReadiness;
    parameters.scope = "local-filesystems";
  };
  earlySystem = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "early-system";
    interface = interfaces.activationMilestone;
    parameters.milestone = "early-system";
  };
  recovery = serviceManagement.forService {
    inherit serviceTypes consumerInstance;
    declaration = {
      service = "aos-credential-recovery";
      enabled = true;
      lifecycle = {
        description = "Recover interrupted AOS credential publication";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {output = "packageRuntime";};
              entry_point = "bin/aos-package-runtime";
              arguments = ["recover-credential-transactions"];
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
        after = [(resultOf "local-filesystems" "readiness-resource")];
        before = [(resultOf "early-system" "readiness-resource")];
        requires = [(resultOf "local-filesystems" "readiness-resource")];
        wants = [];
        requisite = [];
        conflicts = [];
        binds_to = [];
        part_of = [];
        upholds = [];
        required_by = [(resultOf "early-system" "readiness-resource")];
        wanted_by = [];
        required_mounts = [];
        implicit_dependencies = false;
      };
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 90000;
      };
    };
  };
  fragments = [localFilesystems earlySystem recovery];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  config = lib.mkMerge [
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);}
    (lib.mkIf hostStage {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (entry: entry.configured) contributions
      );
    })
  ];
}

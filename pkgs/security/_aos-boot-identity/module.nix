##! Package-owned normal-boot identity validation and fail-closed reporting.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.bootIdentityServices;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "boot-identity";
  initrdStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "initrd";
  packageArtifact = lib.abilities.packageOutput {};

  systemMilestone = key: milestone:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.systemMilestoneReadiness;
      parameters = {inherit milestone;};
    };
  deviceSettle = systemMilestone "device-settle" "device-settle";
  initrdFilesystems = systemMilestone "initrd-filesystems" "initrd-filesystems";
  integrityFailure = systemMilestone "integrity-failure" "boot-integrity-failure";
  readiness = key: resultOf key "readiness-resource";
  serviceResource = key: resultOf "${key}-lifecycle" "service-resource";
  command = key: {
    executable = {
      artifact = packageArtifact;
      entry_point = "bin/${key}";
      arguments = [];
    };
    ignore_failure = false;
  };
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
  service = {
    key,
    description,
    dependencies,
    failurePolicy ? null,
    logging ? false,
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
            start = [(command key)];
            post_start = [];
            stop = [];
            post_stop = [];
            restart = "never";
            restart_delay_millis = 0;
            configuration_change_action = "restart";
            remain_after_exit = key != "aos-boot-identity-failure-report";
            start_timeout_millis = 90000;
            stop_timeout_millis = 90000;
          };
          inherit dependencies;
          environment = {
            variables = {};
            search_path = builtins.map lib.abilities.packageOutput [
              {}
              {package = "coreutils";}
              {package = "util-linux";}
            ];
          };
          readiness = {
            mechanism = "successful-exit";
            signal_scope = "none";
            timeout_millis = 90000;
          };
        }
        // lib.optionalAttrs (failurePolicy != null) {failure_policy = failurePolicy;}
        // lib.optionalAttrs logging {
          logging = {
            standard_output = "structured-and-console";
            standard_error = "structured-and-console";
            namespace = null;
            directories = [];
            directory_mode = "0755";
          };
        };
    };
  identitySuccess = service {
    key = "aos-boot-identity-success";
    description = "Validate the normal boot identity";
    dependencies =
      emptyDependencies
      // {
        after = [(readiness "device-settle")];
        before = [(serviceResource "aos-boot-identity-guard")];
      };
    logging = true;
  };
  identityGuard = service {
    key = "aos-boot-identity-guard";
    description = "Require a validated normal boot identity";
    dependencies =
      emptyDependencies
      // {
        after = [(serviceResource "aos-boot-identity-success")];
        before = [(readiness "initrd-filesystems")];
        wants = [(serviceResource "aos-boot-identity-success")];
        required_by = [(readiness "initrd-filesystems")];
      };
    failurePolicy = {
      handlers = [(readiness "integrity-failure")];
      dispatch = "isolate-active-goal";
    };
  };
  failureReport = service {
    key = "aos-boot-identity-failure-report";
    description = "Confirm rejected boot identity left storage closed";
    dependencies =
      emptyDependencies
      // {
        before = [(readiness "integrity-failure")];
        required_by = [(readiness "integrity-failure")];
      };
    logging = true;
  };
  fragments = [
    deviceSettle
    initrdFilesystems
    integrityFailure
    identitySuccess
    identityGuard
    failureReport
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.security.bootIdentityServices.enable = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = false;
    internal = true;
    description = "Whether fail-closed normal-boot identity services are active.";
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf (initrdStage && cfg.enable) {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
    })
  ];
}

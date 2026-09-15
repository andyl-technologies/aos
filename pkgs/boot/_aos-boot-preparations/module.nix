##! Package-owned initrd credential recovery and configuration seeding.
{
  config,
  lib,
  ...
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "boot-preparations";
  initrdStage =
    config.aos.abilities.environment != null
    && config.aos.abilities.environment.stage == "initrd";

  command = operation: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/aos-boot-preparations";
      arguments = [operation];
    };
    ignore_failure = false;
  };
  earlySystem = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "early-system";
    interface = interfaces.activationMilestone;
    parameters.milestone = "early-system";
  };
  earlySystemReadiness = resultOf "early-system" "readiness-resource";
  systemMilestone = key: milestone:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.systemMilestoneReadiness;
      parameters = {inherit milestone;};
    };
  switchRoot = systemMilestone "switch-root" "switch-root";
  sysroot = systemMilestone "sysroot" "sysroot";
  var = systemMilestone "var" "var";
  nixOverlay = systemMilestone "nix-overlay" "nix-overlay";
  etcOverlay = systemMilestone "etc-overlay" "etc-overlay";
  runEtc = systemMilestone "run-etc" "run-etc";
  switchRootReadiness = resultOf "switch-root" "readiness-resource";
  sysrootReadiness = resultOf "sysroot" "readiness-resource";
  varReadiness = resultOf "var" "readiness-resource";
  nixOverlayReadiness = resultOf "nix-overlay" "readiness-resource";
  etcOverlayReadiness = resultOf "etc-overlay" "readiness-resource";
  runEtcReadiness = resultOf "run-etc" "readiness-resource";
  service = {
    key,
    description,
    operation,
    dependencies,
  }:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration = {
        service = key;
        enabled = true;
        lifecycle = {
          inherit description;
          execution_model = "oneshot";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [(command operation)];
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
      };
    };

  credentialRecovery = service {
    key = "aos-credential-recovery";
    description = "Recover interrupted AOS credential publication";
    operation = "recover-credentials";
    dependencies = {
      prerequisites = [];
      after = [sysrootReadiness varReadiness nixOverlayReadiness];
      before = [
        (resultOf "aos-config-seed-lifecycle" "service-resource")
        etcOverlayReadiness
        earlySystemReadiness
        switchRootReadiness
      ];
      requires = [sysrootReadiness varReadiness nixOverlayReadiness];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [earlySystemReadiness];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
  };
  configurationSeed = service {
    key = "aos-config-seed";
    description = "Seed the per-generation /etc lower for on-host configuration";
    operation = "seed-configuration";
    dependencies = {
      prerequisites = [];
      after = [
        varReadiness
        (resultOf "aos-credential-recovery-lifecycle" "service-resource")
        runEtcReadiness
      ];
      before = [etcOverlayReadiness earlySystemReadiness switchRootReadiness];
      requires = [
        varReadiness
        (resultOf "aos-credential-recovery-lifecycle" "service-resource")
        runEtcReadiness
      ];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [earlySystemReadiness];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
  };
  fragments = [
    earlySystem
    switchRoot
    sysroot
    var
    nixOverlay
    etcOverlay
    runEtc
    credentialRecovery
    configurationSeed
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf initrdStage {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
    })
  ];
}

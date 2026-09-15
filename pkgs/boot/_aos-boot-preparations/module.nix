##! Package-owned initrd credential recovery and configuration seeding.
{
  config,
  lib,
  ...
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "boot-preparations";
  initrdStage =
    config.aos.abilities.environment != null
    && config.aos.abilities.environment.stage == "initrd";

  qualifiedResultOf = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  unitResource = key: qualifiedResultOf "systemd:${key}" "unit-resource";
  initrdFiles = unitResource "initrd-fs-target";
  initrdSwitchRoot = unitResource "initrd-switch-root-target";
  sysroot = unitResource "sysroot-mount";
  mountVar = unitResource "mount-var-service";
  nixOverlay = unitResource "nix-overlay-setup-service";
  runEtc = unitResource "run-etc-setup-service";
  etcOverlay = unitResource "etc-overlay-setup-service";

  command = operation: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/aos-boot-preparations";
      arguments = [operation];
    };
    ignore_failure = false;
  };
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
      after = [sysroot mountVar nixOverlay];
      before = [
        (resultOf "configuration-seed-lifecycle" "service-resource")
        etcOverlay
        initrdFiles
        initrdSwitchRoot
      ];
      requires = [sysroot mountVar nixOverlay];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [initrdFiles];
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
        mountVar
        (resultOf "aos-credential-recovery-lifecycle" "service-resource")
        runEtc
      ];
      before = [etcOverlay initrdFiles initrdSwitchRoot];
      requires = [
        mountVar
        (resultOf "aos-credential-recovery-lifecycle" "service-resource")
        runEtc
      ];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [initrdFiles];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
  };
  fragments = [credentialRecovery configurationSeed];
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

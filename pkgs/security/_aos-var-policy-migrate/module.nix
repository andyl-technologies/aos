##! Package-owned measured-boot encryption and TPM2 sealing of persistent state.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.measuredVar;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "measured-var";
  initrdStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "initrd";

  systemMilestone = key: name:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.systemMilestoneReadiness;
      parameters.milestone = name;
    };
  bootIdentity = systemMilestone "boot-identity" "boot-identity-validated";
  deviceEvents = systemMilestone "device-events" "device-settle";
  partitionLayout = systemMilestone "partition-layout" "partition-layout-ready";
  initrdFilesystems = systemMilestone "initrd-filesystems" "initrd-filesystems";
  persistentState = systemMilestone "persistent-state" "var";
  verityRoot = systemMilestone "verity-root" "verity-root-verified";
  verityReadiness = resultOf "verity-root" "readiness-resource";

  service = serviceManagement.forService {
    inherit serviceTypes consumerInstance;
    declaration = {
      service = "aos-var-crypt";
      enabled = true;
      lifecycle = {
        description = "Encrypt and TPM2-seal persistent state";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/aos-var-crypt";
              arguments = [
                cfg.pcrPublicKey
                cfg.signedPcrs
                cfg.pinnedPcrs
                cfg.recoveryKeyPath
              ];
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
      manager_identity = {
        name = "aos-var-crypt";
        aliases = [];
      };
      dependencies = {
        prerequisites = [];
        after =
          [
            (resultOf "boot-identity" "readiness-resource")
            (resultOf "partition-layout" "readiness-resource")
            (resultOf "device-events" "readiness-resource")
          ]
          ++ lib.optional cfg.requireVerity verityReadiness;
        before = [
          (resultOf "persistent-state" "readiness-resource")
          (resultOf "initrd-filesystems" "readiness-resource")
        ];
        requires =
          [
            (resultOf "boot-identity" "readiness-resource")
          ]
          ++ lib.optional cfg.requireVerity verityReadiness;
        wants = [];
        requisite = [];
        conflicts = [];
        binds_to = [];
        part_of = [];
        upholds = [];
        required_by = [(resultOf "initrd-filesystems" "readiness-resource")];
        wanted_by = [];
        required_mounts = [];
        implicit_dependencies = true;
      };
      conditions.all = [
        {
          kind = "kernel-argument";
          argument = "aos.recovery=1";
          negated = true;
        }
      ];
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 90000;
      };
      logging = {
        standard_output = "structured-and-console";
        standard_error = "structured-and-console";
        directories = [];
        directory_mode = "0755";
      };
    };
  };
  fragments = [
    bootIdentity
    deviceEvents
    partitionLayout
    initrdFilesystems
    persistentState
    verityRoot
    service
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.security.measuredVar = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      description = "Encrypt persistent state and seal its unlock key to the measured boot policy.";
    };

    pcrPublicKey = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/nonexistent/aos-pcr-public-key";
      description = "Initrd path to the public key that authenticates signed PCR policy.";
    };

    signedPcrs = lib.mkOption {
      type = lib.abilities.types.string {
        maxLength = 128;
        syntax = null;
      };
      default = "11";
      description = "PCR set covered by the signed policy.";
    };

    pinnedPcrs = lib.mkOption {
      type = lib.abilities.types.string {
        maxLength = 128;
        syntax = null;
      };
      default = "7+12";
      description = "PCR set pinned by value when the TPM2 token is enrolled.";
    };

    recoveryKeyPath = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/run/aos-var-recovery.key";
      description = "Volatile path that receives the generated recovery credential.";
    };

    requireVerity = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      description = "Require complete dm-verity root verification before persistent-state unlock.";
    };
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

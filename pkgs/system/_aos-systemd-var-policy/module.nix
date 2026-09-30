##! Systemd-owned measured-boot encryption and TPM2 sealing of persistent state.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.security.measuredVar;
  initrdStage = config.aos.boot.stage == "initrd";
  measuredBoot = config.aos.boot.secureBoot.measuredBoot;
  units = {
    bootIdentity = "aos-boot-identity-guard.service";
    deviceEvents = "systemd-udev-settle.service";
    initrdStage = "aos-ability-initrd-controller.service";
    filesystems = "initrd-fs.target";
    persistentState = "mount-var.service";
    verityRoot = "aos-verity-root-verify.service";
  };
  absolutePath = lib.types.strWith {
    maxLength = 4096;
    pattern = "/[^[:space:]]+";
  };
  pcrSelection = lib.types.strWith {
    maxLength = 128;
    pattern = "[0-9]+([+][0-9]+)*";
  };

  serviceDefinition = {
    activationOwner = "image";
    autoStart = false;
    lifecycle = {
      description = "Encrypt and TPM2-seal persistent state";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/bin/aos-var-crypt";
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
          units.bootIdentity
          units.initrdStage
          units.deviceEvents
        ]
        ++ lib.optional cfg.requireVerity units.verityRoot;
      before = [
        units.persistentState
        units.filesystems
      ];
      requires =
        [
          units.bootIdentity
        ]
        ++ lib.optional cfg.requireVerity units.verityRoot;
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [units.filesystems];
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
in {
  options.aos.security.measuredVar = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      extensible = true;
      description = "Encrypt persistent state and seal its unlock key to the measured boot policy.";
    };

    pcrPublicKey = lib.mkOption {
      type = absolutePath;
      default = "/nonexistent/aos-pcr-public-key";
      description = "Initrd path to the public key that authenticates signed PCR policy.";
    };

    signedPcrs = lib.mkOption {
      type = pcrSelection;
      default = "11";
      description = "PCR set covered by the signed policy.";
    };

    pinnedPcrs = lib.mkOption {
      type = pcrSelection;
      default = "7+12";
      description = "PCR set pinned by value when the TPM2 token is enrolled.";
    };

    recoveryKeyPath = lib.mkOption {
      type = absolutePath;
      default = "/run/aos-var-recovery.key";
      description = "Volatile path that receives the generated recovery credential.";
    };

    requireVerity = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Require complete dm-verity root verification before persistent-state unlock.";
    };
  };

  config = {
    aos.security.measuredVar = {
      enable = lib.mkDefault (initrdStage && measuredBoot.enable && config.aos.boot.storage.backend != "zfs-zvol");
      pcrPublicKey = lib.mkIf (measuredBoot._effectivePcrPublicKey != null) (lib.mkDefault measuredBoot._effectivePcrPublicKey);
      signedPcrs = lib.mkDefault measuredBoot.signedPcrs;
      pinnedPcrs = lib.mkDefault measuredBoot.pinnedPcrs;
      recoveryKeyPath = lib.mkDefault measuredBoot.recoveryKeyPath;
      requireVerity = lib.mkDefault config.aos.security.verity.enable;
    };
    aos.services."measured-var.aos-var-crypt" = serviceDefinition // {enable = cfg.enable && initrdStage;};
  };
}

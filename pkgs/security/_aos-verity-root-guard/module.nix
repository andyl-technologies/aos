##! Package-owned initrd verification of the complete dm-verity root.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.security.verityRootVerification;
  initrdStage = config.aos.boot.stage == "initrd";
  units = {
    boot-identity = "aos-boot-identity-guard.service";
    verity-root-mapping = "aos-systemd-verity-root-setup.service";
    device-events = "systemd-udev-settle.service";
    initrd-stage = "aos-ability-initrd-controller.service";
    initrd-filesystems = "initrd-fs.target";
    persistent-state = "mount-var.service";
    integrity-failure = "aos-boot-integrity-failure.target";
  };
  resultOf = key: _: units.${key};
  command = {
    executable = {
      path = "${package}/bin/aos-verity-root-verify";
      arguments = [];
    };
    ignore_failure = false;
  };
  verificationService = {
    activationOwner = "image";
    autoStart = false;
    service = "aos-verity-root-verify";
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
in {
  options.aos.security.verityRootVerification.enable = lib.mkOption {
    type = lib.types.bool;
    default = config.aos.security.verity.enable;
    description = "Verify every dm-verity root block before persistent state is exposed.";
  };

  config.aos.services."verity-root-verification.aos-verity-root-verify" = verificationService // {enable = cfg.enable && initrdStage;};
}

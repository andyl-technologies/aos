##! Owns image lifecycle requirements, measurement floors and regression coverage.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification.images;
  types = import ./_types.nix {inherit lib;};
in {
  options.qualification.images = {
    rebootCycles = (types.option types.positive "Minimum clean reboot cycles.") // {default = 10;};
    coldBootCycles = (types.option types.positive "Minimum complete power-off boot cycles.") // {default = 3;};
    updateRollbackCycles = (types.option types.positive "Minimum predecessor/candidate update and rollback cycles.") // {default = 3;};
  };
  config.qualification.assertions = [
    {
      assertion = cfg.rebootCycles >= 10 && cfg.coldBootCycles >= 3 && cfg.updateRollbackCycles >= 3;
      message = "Image cycle counts must preserve the release acceptance floors.";
    }
  ];
  config.qualification.requirements = {
    image-installation = {
      measurements = {
        reboot_cycles.minimum = cfg.rebootCycles;
        cold_boot_cycles.minimum = cfg.coldBootCycles;
      };
      checks = [
        "anonymous-download-and-resume"
        "disk-format-equivalence"
        "uefi-boot"
        "repeated-warm-and-cold-boot"
        "provisioning"
        "host-configuration"
        "ssh-dns-time-network"
        "boot-integrity-and-encrypted-state"
        "no-fixture-authorities"
      ];
      invalidated_by = ["subject" "policy" "executor" "environment"];
      method = "automated";
      phase = "staging";
      production_only = false;
      regressions = ["checks.fleet.install-from-image" "checks.fleet.provisioning-boot"];
      scope = "images";
    };
    image-lifecycle = {
      checks = [
        "configuration-activation-and-rollback"
        "package-install-change-remove-recover"
        "nginx-http-tls"
        "persistent-workload"
        "reboot-persistence"
        "bounded-generation-retention"
        "disk-and-memory-pressure"
      ];
      invalidated_by = ["subject" "policy" "executor" "environment"];
      method = "automated";
      phase = "staging";
      production_only = false;
      regressions = ["checks.fleet.runtime-config-all" "checks.fleet.qualification-workload"];
      scope = "images";
    };
    image-update-recovery = {
      measurements.update_rollback_cycles.minimum = cfg.updateRollbackCycles;
      checks = [
        "preceding-image-identity"
        "upgrade"
        "configuration-rebind"
        "boot-blessing"
        "interrupted-writes-and-reboots"
        "automatic-fallback"
        "explicit-rollback"
        "repeated-update-and-rollback"
        "committed-data-preserved"
        "offline-recovery"
        "update-after-recovery"
      ];
      invalidated_by = ["subject" "policy" "executor" "environment"];
      method = "automated";
      phase = "staging";
      production_only = false;
      regressions = ["checks.fleet.system-image-rollback" "checks.fleet.boot-identity-fail-closed"];
      scope = "images";
    };
    image-observation = {
      phase = "complete";
      scope = "images";
      checks = ["mixed-workload-soak" "operation-denominators" "committed-data-preserved"];
      measurements = {
        workload_operations.minimum = 1;
        data_integrity_failures = {
          minimum = 0;
          maximum = 0;
        };
      };
    };
  };
}

##! Preserves authored bare-metal addressing and closed provisioning defaults.
let
  lib = import ../../lib {system = "x86_64-linux";};
  outputDeclarations = {
    options.aos.image.budgets.maxRuntimeClosureMiB = lib.mkOption {
      type = lib.types.int;
      default = 768;
    };
    options.aos.security.verity.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
    };
    options.aos.hardware.nvidia.open.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
    };
    options.aos.hardware.serverManagement.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
    };
    options.aos.monitoring.hardware.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
    };
  };
  evaluate = configuration:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../modules/profiles/bare-metal-zfs.nix
        ../../pkgs/boot/_aos-boot-storage/options.nix
        outputDeclarations
        configuration
      ];
    };
  defaults = evaluate {};
  selected = evaluate {
    aos.profiles.bareMetalZfs = {
      enable = true;
      espDevices = ["/dev/disk/by-partlabel/aos-esp-1" "/dev/disk/by-partlabel/aos-esp-2"];
    };
  };
  provisioning = lib.evalModules {
    inherit lib;
    modules = [
      ../../pkgs/system/_aos-storage-provisioning-provider/configuration.nix
      {
        aos.provisioning.storage.partitions.var.sizeMin = "8G";
        services.unrelated.enable = throw "closed provisioning projection forced unrelated runtime policy";
      }
    ];
  };
  plan = provisioning.config.aos.provisioning.storage;
  partitions = builtins.mapAttrs (_: partition: builtins.removeAttrs partition ["_module"]) plan.partitions;
in {
  defaultGptAddressing = assert defaults.config.aos.boot.storage.backend == "gpt-partitions"; assert defaults.config.aos.boot.storage.resolvedDevices.rootA == "/dev/disk/by-partlabel/root-a"; true;
  encryptedZvolAddressing = assert selected.config.aos.boot.storage.backend == "zfs-zvol"; assert selected.config.aos.boot.storage.resolvedDevices.rootA == "/dev/zvol/rpool/aos/slots/root-a"; assert selected.config.aos.boot.storage.zfs.encryptionRoot == "rpool"; true;
  redundantAuthoritativeEsps = assert builtins.length selected.config.aos.boot.storage.espDevices == 2; assert selected.config.aos.security.verity.enable; true;
  explicitRuntimeBudget = assert selected.config.aos.image.budgets.maxRuntimeClosureMiB == 1024; true;
  closedProvisioningProjection = assert plan.partitions.var.sizeMin == "8G"; assert plan.partitions.swap.type == "swap"; assert plan.partitions.swap.format == "swap"; true;
  plainPartitionJson = assert builtins.match ".*_module.*" (builtins.toJSON partitions) == null; true;
}

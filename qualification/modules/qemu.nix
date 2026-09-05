##! Defines QEMU scope, boot requirements and reference resource policy.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification.qemu;
  types = import ./_types.nix {inherit lib;};
  host = platform: {
    inherit platform;
    backend = {
      kind = "physical";
      physical = {};
    };
  };
  target = platform: machine: accelerator: {
    inherit platform;
    kind = "image";
    required = true;
    environment = {
      layers = [
        (host (
          if accelerator == "kvm"
          then platform
          else null
        ))
        {
          inherit platform;
          backend = {
            kind = "qemu";
            qemu = {inherit machine accelerator;};
          };
        }
      ];
      boot = "systemd-boot-uki";
      security = {
        secure_boot = true;
        measured_boot = true;
        verity = true;
        encrypted_state = true;
        persistent_firmware = true;
      };
      resources = {inherit (cfg) cpus memory_mib disk_mib;};
      devices = [
        {
          driver = "virtio_blk";
          stage = "initrd";
        }
        {
          driver = "virtio_net";
          stage = "initrd";
        }
      ];
      kernel_options.CONFIG_EFI = "y";
    };
  };
in {
  options.qualification.qemu = {
    cpus = (types.option types.positive "Reference VM logical CPUs.") // {default = 2;};
    memory_mib = (types.option types.positive "Reference VM memory in MiB.") // {default = 8192;};
    disk_mib = (types.option types.positive "Reference VM persistent storage in MiB.") // {default = 32768;};
  };
  config.qualification = {
    targets = {
      disk-x86_64-linux = target "x86_64-linux" "q35" "kvm";
      disk-aarch64-linux = target "aarch64-linux" "virt" "tcg";
    };
    assertions = [
      {
        assertion = builtins.all (platform:
          builtins.any (target:
            target.platform == platform && target.kind == "image" && target.required)
          (builtins.attrValues config.qualification.targets)) ["x86_64-linux" "aarch64-linux"];
        message = "QEMU requires both Linux architectures.";
      }
    ];
  };
}

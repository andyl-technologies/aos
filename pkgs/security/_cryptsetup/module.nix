##! Package-owned encrypted swap resource composition.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.filesystems.encryptedSwap;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceInterfaces = serviceManagement.interfaces;
  storageInterfaces = lib.abilities.interfaces.blockStorage.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "cryptswap";

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
  device = producer "swap-device" serviceInterfaces.devicePresence {
    name = "swap-partition";
    device = cfg.device;
  };
  mapping = producer "encrypted-swap-mapping" storageInterfaces.encryptedMapping {
    name = cfg.mappingName;
    enabled = true;
    source = resultOf "swap-device" "device-node";
    cipher = cfg.cipher;
    key_size_bits = cfg.keySizeBits;
    key.kind = "ephemeral-random";
    prerequisites = [];
  };
  format = producer "encrypted-swap-format" storageInterfaces.storageFormat {
    name = "encrypted-swap";
    enabled = true;
    source = resultOf "encrypted-swap-mapping" "mapped-device";
    format = "swap";
    policy = "always";
    prerequisites = [
      (resultOf "encrypted-swap-mapping" "resource")
    ];
  };
  swap = producer "encrypted-swap" serviceInterfaces.swapResource {
    name = "encrypted-swap";
    enabled = true;
    source = resultOf "encrypted-swap-format" "formatted-path";
  };
  fragments = [device mapping format swap];
  contributions = builtins.map serviceManagement.splitContribution fragments;
  configured =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
in {
  options.aos.filesystems.encryptedSwap = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = true;
      description = "Enable ephemeral plain dm-crypt swap on the swap partition.";
    };

    device = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/dev/disk/by-partlabel/swap";
      description = "Stable device path for the encrypted swap partition.";
    };

    mappingName = lib.mkOption {
      type = lib.abilities.types.localKey;
      default = "cryptswap";
      description = "Kernel device-mapper name for encrypted swap.";
    };

    cipher = lib.mkOption {
      type = lib.abilities.types.string {
        maxLength = 128;
        syntax = "local-key-v1";
      };
      default = "aes-xts-plain64";
      description = "Plain dm-crypt cipher used for ephemeral swap.";
    };

    keySizeBits = lib.mkOption {
      type = lib.abilities.types.integer {
        minimum = 128;
        maximum = 512;
      };
      default = 256;
      description = "Ephemeral dm-crypt key size in bits.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf (cfg.enable && configured) {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
    })
  ];
}

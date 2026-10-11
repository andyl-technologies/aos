##! Composes ephemeral encrypted swap using native checked device outputs.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.filesystems.encryptedSwap;
  abilities = config.aos.abilities;
  device = abilities.device.operations.present.effects.cryptswap.outputs;
  mapping = abilities.encryptedMapping.operations.open.effects.cryptswap.outputs;
  format = abilities.storageFormat.operations.format.effects.cryptswap.outputs;
in {
  options.aos.filesystems.encryptedSwap = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable ephemeral plain dm-crypt swap on the swap partition.";
    };
    device = lib.mkOption {
      type = lib.types.str;
      default = "/dev/disk/by-partlabel/swap";
      description = "Stable device path for the encrypted swap partition.";
    };
    mappingName = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9_.-]+";
      default = "cryptswap";
      description = "Kernel device-mapper name for encrypted swap.";
    };
    cipher = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9_.-]+";
      default = "aes-xts-plain64";
      description = "Plain dm-crypt cipher used for ephemeral swap.";
    };
    keySizeBits = lib.mkOption {
      type = lib.types.ints.between 128 512;
      default = 256;
      description = "Ephemeral dm-crypt key size in bits.";
    };
  };

  # Selecting cryptsetup for initrd storage unlocks must not activate host swap.
  config = lib.mkIf (cfg.enable && (config.aos.boot.stage or "host") == "host") {
    aos.abilities = {
      device.operations.present.effects.cryptswap.input = {
        path = cfg.device;
        kind = "block";
      };
      encryptedMapping.operations.open.effects.cryptswap.input = {
        name = cfg.mappingName;
        cryptsetup = "${package}/sbin/cryptsetup";
        source = device.resource;
        inherit (cfg) cipher keySizeBits;
      };
      storageFormat.operations.format.effects.cryptswap.input = {
        name = "encrypted-swap";
        source = mapping.path;
        format = "swap";
        policy = "always";
      };
      swap.operations.ensure.effects.cryptswap.input = {
        name = "encrypted-swap";
        source = format.path;
      };
    };
  };
}

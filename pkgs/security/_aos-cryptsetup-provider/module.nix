##! Native ephemeral encrypted mapping operations.
{
  lib,
  package,
  dependencies,
  ...
}: {
  aos.abilities.encryptedMapping.operations.open = {
    input.options = {
      name = lib.mkOption {
        type = lib.types.str;
        description = "Kernel device-mapper name owned by this effect.";
      };
      source = lib.mkOption {
        type = lib.types.deferred lib.types.str;
        description = "Stable source device path verified before opening.";
      };
      cipher = lib.mkOption {
        type = lib.types.str;
        default = "aes-xts-plain64";
        description = "Plain dm-crypt cipher.";
      };
      keySizeBits = lib.mkOption {
        type = lib.types.ints.between 128 512;
        default = 256;
        description = "Ephemeral random key size in bits.";
      };
      cryptsetup = lib.mkOption {
        type = lib.types.str;
        description = "Exact retained cryptsetup executable.";
      };
    };
    result.options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "Mapped device path.";
      };
      resource = lib.mkOption {
        type = lib.types.str;
        description = "Logical identity of the mapping effect.";
      };
    };
    handler.program = package;
  };
}

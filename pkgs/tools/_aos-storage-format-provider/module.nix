##! Explicit native storage formatting through retained util-linux tools.
{
  lib,
  package,
  dependencies,
  ...
}: {
  aos.abilities.storageFormat.operations.format = {
    input.options = {
      name = lib.mkOption {
        type = lib.types.str;
        description = "Stable format operation name.";
      };
      source = lib.mkOption {
        type = lib.types.deferred lib.types.str;
        description = "Checked absolute device path to format.";
      };
      format = lib.mkOption {
        type = lib.types.enum ["swap"];
        default = "swap";
        description = "Requested device format.";
      };
      policy = lib.mkOption {
        type = lib.types.enum ["always" "if-absent"];
        default = "if-absent";
        description = "Whether to replace an existing format explicitly.";
      };
      mkswap = lib.mkOption {
        type = lib.types.str;
        default = "${dependencies.util-linux}/sbin/mkswap";
        description = "Retained immutable formatter executable.";
      };
      blkid = lib.mkOption {
        type = lib.types.str;
        default = "${dependencies.util-linux}/sbin/blkid";
        description = "Retained immutable format inspection executable.";
      };
    };
    result.options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "Checked formatted device path.";
      };
      resource = lib.mkOption {
        type = lib.types.str;
        description = "Logical identity of the formatting effect.";
      };
    };
    handler.program = package;
  };
}

##! Defines native mount realization and its manager-owned lifecycle.
{lib, ...}: {
  aos.abilities.mount.operations.ensure = {
    input.options = {
      name = lib.mkOption {
        type = lib.types.str;
        description = "Logical mount name.";
      };
      source = lib.mkOption {
        type = lib.types.deferred lib.types.str;
        description = "Mount source path or device.";
      };
      destination = lib.mkOption {
        type = lib.types.deferred lib.types.str;
        description = "Mount point path.";
      };
      filesystem = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Filesystem type when explicitly selected.";
      };
      options = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Ordered mount options.";
      };
      timeout_millis = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = null;
        description = "Optional mount deadline in milliseconds.";
      };
      enabled = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Enable this managed mount.";
      };
      optional = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Retain the mount unit when its source is absent and report unavailable instead of blocking activation.";
      };
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Manager-owned mount unit identity.";
    };
    result.options.state = lib.mkOption {
      type = lib.types.enum ["mounted" "unavailable" "disabled"];
      description = "Observed mount availability; unavailable never promises that the filesystem is mounted.";
    };
  };
}

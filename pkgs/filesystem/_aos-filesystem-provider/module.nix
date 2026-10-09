##! Package-owned filesystem operations and merged directory declarations.
{
  config,
  lib,
  package,
  ...
}: let
  inherit (lib) mkOption types;
  pathOption = description:
    mkOption {
      type = types.deferred types.str;
      inherit description;
    };
  directoryInput = {
    options = {
      path = pathOption "Absolute mutable path owned by this effect.";
      mode = mkOption {
        type = types.str;
        default = "0755";
        description = "Octal permission mode.";
      };
      parentResource = mkOption {
        type = types.nullOr (types.deferred types.str);
        default = null;
        description = "Identity of the exact owning parent directory effect, when allocating within one.";
      };
      owner = mkOption {
        type = types.nullOr (types.deferred types.str);
        default = null;
        description = "Local user name owning the entry.";
      };
      group = mkOption {
        type = types.nullOr (types.deferred types.str);
        default = null;
        description = "Local group name owning the entry.";
      };
    };
  };
  result.options = {
    path = mkOption {
      type = types.str;
      description = "Realized filesystem path.";
    };
    resource = mkOption {
      type = types.str;
      description = "Logical identity of the owning effect.";
    };
  };
  directory = {
    input = directoryInput;
    inherit result;
    handler.program = package;
  };
  enabled = lib.filterAttrs (_: value: value.enable) config.aos.directories;
  effects = persistent:
    lib.mapAttrs (_: value: {
      input = builtins.removeAttrs value ["enable" "persistent"];
      lifetime =
        if persistent
        then "persistent"
        else "instance";
    }) (lib.filterAttrs (_: value: value.persistent == persistent) enabled);
in {
  options.aos.directories = mkOption {
    extensible = true;
    default = {};
    description = "Merged filesystem allocations with explicit retention policy.";
    type = types.attrsOf (types.submodule [
      directoryInput
      {
        options.enable = lib.mkEnableOption "this filesystem allocation";
        options.persistent = mkOption {
          type = types.bool;
          default = false;
          description = "Retain allocation after its declaring package is removed.";
        };
      }
    ]);
  };
  config.aos.abilities.filesystem.operations = {
    directory = directory;
    allocate = directory // {effects = effects false;};
    persistentAllocate = directory // {effects = effects true;};
    view = {
      input.options = {
        sourcePath = pathOption "Previously realized storage root.";
        relativePath = mkOption {
          type = types.nullOr (types.deferred types.str);
          default = null;
          description = "Normalized child path within the storage root.";
        };
      };
      inherit result;
      handler.program = package;
    };
    symlinkTree = {
      input = {
        imports = [{options = builtins.removeAttrs directoryInput.options ["mode"];}];
        options = {
          mode = lib.mkOption {
            type = lib.types.str;
            default = "0777";
            description = "Symlink mode; source tree keeps its immutable file modes.";
          };
          sourcePath = pathOption "Retained immutable directory exposed by this owned link.";
        };
      };
      inherit result;
      handler.program = package;
    };
    privilegedExecutable = {
      input.options = {
        name = mkOption {
          type = types.str;
          description = "Executable basename under /run/wrappers/bin.";
        };
        source = pathOption "Retained executable copied into the privileged wrapper directory.";
        mode = mkOption {
          type = types.str;
          default = "4755";
          description = "Octal privileged executable permission mode.";
        };
        owner = mkOption {
          type = types.str;
          default = "root";
          description = "Local user owning the privileged executable.";
        };
        group = mkOption {
          type = types.str;
          default = "root";
          description = "Local group owning the privileged executable.";
        };
      };
      inherit result;
      handler.program = package;
    };
    entry = {
      input = {
        imports = [directoryInput];
        options = {
          kind = mkOption {
            type = types.enum ["directory" "copied-file" "empty-file"];
            default = "directory";
            description = "Filesystem entry kind; empty-file allocates mutable contents without replacing them.";
          };
          sourcePath = mkOption {
            type = types.nullOr (types.deferred types.str);
            default = null;
            description = "Retained source file for a copied entry.";
          };
          maxBytes = mkOption {
            type = types.int;
            default = 16777216;
            description = "Maximum number of source bytes copied.";
          };
        };
      };
      inherit result;
      handler.program = package;
    };
  };
}

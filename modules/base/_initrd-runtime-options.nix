##! Package-authored non-package initrd runtime artifacts.
{
  config,
  lib,
  pkgs,
  ...
}: let
  validFileName = name:
    builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" name != null;
  runtimeFileTree = group: files:
    pkgs.runCommand "aos-initrd-runtime-files-${group}" {} ''
      mkdir -p "$out"
      ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: content:
        if validFileName name
        then "printf '%s' ${lib.escapeShellArg content} > \"$out/${name}\""
        else throw "initrd runtime file name '${name}' is not a canonical local file name")
      files)}
    '';
in {
  options = {
    aos.initrdRuntime = {
      artifacts = lib.mkOption {
        type = lib.types.attrsOf (lib.types.listOf lib.types.str);
        default = {};
        extensible = true;
        description = ''
          Package-owned groups of generated store artifacts copied into the
          initial runtime without admitting them as package module roots.
        '';
      };

      files = lib.mkOption {
        type = lib.types.attrsOf (lib.types.attrsOf lib.types.str);
        default = {};
        extensible = true;
        description = ''
          Package-owned groups of flat runtime files rendered once into
          immutable trees for the initial runtime.
        '';
      };
    };

    aos.initrdRuntime.renderedFileTrees = lib.mkOption {
      type = lib.types.attrsOf lib.types.pathInStore;
      readOnly = true;
      internal = true;
      description = "Immutable initrd file trees derived from package file definitions.";
    };
  };

  config.aos.initrdRuntime.renderedFileTrees =
    lib.mapAttrs runtimeFileTree config.aos.initrdRuntime.files;
}

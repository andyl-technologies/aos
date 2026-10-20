##! Declares retained configuration directory sources in their owning package.
{lib, ...}: let
  targetType = lib.types.strMatching "[^/]+(/[^/]+)*";
in {
  options.aos.filesystems.etcTrees = lib.mkOption {
    type = lib.types.listOf (lib.types.submodule {
      options = {
        target = lib.mkOption {
          type = targetType;
          description = "Relative destination beneath /etc.";
        };
        source = lib.mkOption {
          type = lib.types.pathInStore;
          description = "Admitted immutable directory source expanded into real directories and leaf links.";
        };
      };
    });
    default = [];
    extensible = true;
    description = "Package-owned immutable trees merged into the native configuration lower.";
  };
}

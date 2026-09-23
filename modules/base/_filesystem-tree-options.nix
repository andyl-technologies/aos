##! Package-authored immutable filesystem-tree options.
{lib, ...}: let
  types = lib.abilities.types;
  filesystemTree = types.record {
    fields = {
      target = types.relativePath;
      source = types.artifactPathReference;
    };
  };
in {
  options.aos.filesystems.etcTrees = lib.mkOption {
    type = types.list {
      element = filesystemTree;
      maxItems = 4096;
    };
    default = [];
    extensible = true;
    description = "Package-owned immutable directory trees materialized beneath /etc.";
  };
}

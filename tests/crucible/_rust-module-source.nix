{
  lib,
  entry,
}: let
  filename = builtins.baseNameOf entry;
  moduleName = lib.removeSuffix ".rs" filename;
  fragmentDir = builtins.dirOf entry + "/${moduleName}";
in
  import ./_rust-source.nix {
    inherit lib entry;
    fragmentDirs = lib.optional (builtins.pathExists fragmentDir) fragmentDir;
  }

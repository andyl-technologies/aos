# modules/module-list.nix — Auto-discovered module registry
#
# Scans configured module directories for .nix files and returns
# them as a list of paths. profiles/ is excluded — system variants
# import profiles explicitly.

let
  # Directories containing auto-loaded modules
  moduleDirs = [
    ./base
    ./security
    ./services
    ./kubernetes
    ./monitoring
    ./image
  ];

  # Discover all .nix files in a directory (non-recursive)
  discoverModules =
    dir:
    let
      entries = builtins.readDir dir;
      nixFileNames = builtins.filter (name: builtins.match ".*\\.nix" name != null) (
        builtins.attrNames entries
      );
    in
    map (name: dir + "/${name}") nixFileNames;
in
builtins.concatMap discoverModules moduleDirs

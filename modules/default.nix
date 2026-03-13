##! modules/default.nix — Auto-discovered module registry
##!
##! Scans configured module directories for .nix files and returns
##! them as a list of paths. All modules including profiles are loaded —
##! profiles use enable flags so they are inert unless activated.
let
  # Directories containing auto-loaded modules
  moduleDirs = [
    ./base
    ./security
    ./services
    ./kubernetes
    ./monitoring
    ./image
    ./profiles
  ];

  # Discover all .nix files in a directory (non-recursive).
  # Skips _-prefixed files (internal helpers, not modules).
  discoverModules =
    dir:
    let
      entries = builtins.readDir dir;
      nixFileNames = builtins.filter (
        name:
        entries.${name} == "regular"
        && builtins.match ".*\\.nix" name != null
        && builtins.match "_.*" name == null
      ) (builtins.attrNames entries);
    in
    map (name: dir + "/${name}") nixFileNames;
in
builtins.concatMap discoverModules moduleDirs

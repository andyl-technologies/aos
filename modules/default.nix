##! modules/default.nix — Auto-discovered module registry
##!
##! Scans configured module directories recursively for .nix files
##! and returns them as a list of paths. All modules including profiles
##! are loaded — profiles use enable flags so they are inert unless
##! activated.
let
  # Directories containing auto-loaded modules
  moduleDirs = [
    ./base
    ./security
    ./services
    ./monitoring
    ./image
    ./profiles
    ./systemd
    ./tests
  ];

  # Discover all .nix files in a directory tree (recursive).
  # Skips _-prefixed files and directories — by convention those are
  # internal helpers that other modules `import` directly (e.g.
  # `pkgs/kubernetes/_k3s-common.nix`), not auto-loaded
  # NixOS-style modules. Mirrors `pkgs/default.nix`'s
  # `discoverPackages` so the two halves of the tree behave the same.
  discoverModules = dir: let
    entries = builtins.readDir dir;
    names = builtins.attrNames entries;
    nixFileNames =
      builtins.filter (
        name:
          entries.${name}
          == "regular"
          && builtins.match ".*\\.nix" name != null
          && builtins.match "_.*" name == null
      )
      names;
    subdirs =
      builtins.filter (
        name:
          entries.${name}
          == "directory"
          && builtins.match "_.*" name == null
      )
      names;
    here = map (name: dir + "/${name}") nixFileNames;
    nested =
      builtins.concatMap (
        name: discoverModules (dir + "/${name}")
      )
      subdirs;
  in
    here ++ nested;
in
  [./packages.nix] ++ builtins.concatMap discoverModules moduleDirs

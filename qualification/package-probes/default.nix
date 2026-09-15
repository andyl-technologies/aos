##! Discovers the reviewed package-probe catalog without allowing duplicates.
{testing}: let
  entries = builtins.readDir ./.;
  probeFiles = builtins.filter (
    name:
      entries.${name}
      == "regular"
      && builtins.match ".*\\.nix" name != null
      && name != "default.nix"
      && builtins.substring 0 1 name != "_"
  ) (builtins.attrNames entries);
  probeSets =
    map (
      name: import (./. + "/${name}") {inherit testing;}
    )
    probeFiles;
  declaredNames = builtins.concatMap builtins.attrNames probeSets;
  probes = builtins.foldl' (catalog: entries: catalog // entries) {} probeSets;
in
  assert builtins.length declaredNames == builtins.length (builtins.attrNames probes); probes

##! Auto-discovered canonical core ability interface modules.
##!
##! Each sibling module owns one provider-neutral interface family. Its
##! ordinary module definition is authoritative; the library view exposes
##! constructors and typed schemas derived beside that same definition.
args: let
  entries = builtins.readDir ./.;
  moduleFiles = builtins.filter (
    name:
      name
      != "default.nix"
      && entries.${name} == "regular"
      && builtins.match ".*\\.nix" name != null
      && builtins.match "_.*" name == null
  ) (builtins.attrNames entries);
  importBundle = name: let
    bundle = import (./. + "/${name}");
    dependencies = builtins.intersectAttrs (builtins.functionArgs bundle) args;
  in
    bundle dependencies;
  bundles = builtins.map importBundle moduleFiles;
  registry =
    builtins.foldl' (
      result: bundle:
        if !builtins.isString (bundle.name or null) || bundle.name == ""
        then throw "core ability interface module has no library name"
        else if !(builtins.isAttrs (bundle.readView or null))
        then throw "core ability interface module '${bundle.name}' has no library read view"
        else if !(builtins.isAttrs (bundle.module or null))
        then throw "core ability interface module '${bundle.name}' has no module definition"
        else if builtins.hasAttr bundle.name result
        then throw "duplicate core ability interface library name '${bundle.name}'"
        else result // {${bundle.name} = bundle;}
    ) {}
    bundles;
in {
  module.imports = builtins.map (bundle: bundle.module) bundles;
  readView = builtins.mapAttrs (_: bundle: bundle.readView) registry;
}

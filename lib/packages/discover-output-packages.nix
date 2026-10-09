##! Discovers recipe-owned output names without evaluating package dependencies.
{root}: let
  merge = left: right:
    if builtins.any (name: builtins.hasAttr name left) (builtins.attrNames right)
    then throw "Output packages must have unique installable names."
    else left // right;
  discover = directory: let
    entries = builtins.readDir directory;
    declaration = directory + "/_outputs.nix";
    owners =
      if builtins.pathExists declaration
      then import declaration
      else {};
    local = builtins.foldl' (result: owner: let
      recipe = directory + "/${owner}.nix";
      outputs = owners.${owner};
      outputNames = builtins.attrValues outputs;
      uniqueOutputs = builtins.attrNames (builtins.listToAttrs (map (output: {
          name = output;
          value = true;
        })
        outputNames));
      records = builtins.mapAttrs (name: output:
        if
          builtins.match "[A-Za-z0-9][A-Za-z0-9+._=-]*" name
          == null
          || name == "."
          || name == ".."
          || !builtins.isString output
          || builtins.match "[A-Za-z0-9+._-]+" output == null
        then throw "Output package declarations require valid package and Nix output names."
        else {inherit owner output recipe;})
      outputs;
    in
      if
        builtins.match "[A-Za-z0-9][A-Za-z0-9+._=-]*" owner
        == null
        || !(builtins.pathExists recipe)
        || !builtins.isAttrs outputs
      then throw "Output package declarations must belong to an adjacent package recipe."
      else if builtins.length outputNames != builtins.length uniqueOutputs
      then throw "Each source output must have one installable subpackage name."
      else merge result records) {} (builtins.attrNames owners);
    children = builtins.filter (name:
      entries.${name} == "directory" && builtins.substring 0 1 name != "_")
    (builtins.attrNames entries);
  in
    builtins.foldl' (result: child: merge result (discover (directory + "/${child}"))) local children;
in
  discover root

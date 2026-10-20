##! Retains a package's portable module tree without evaluating its configuration.
{
  name,
  source,
}: let
  regularTree = path:
    builtins.all (entry: let
      kind = (builtins.readDir path).${entry};
    in
      kind == "regular" || (kind == "directory" && regularTree (path + "/${entry}")))
    (builtins.attrNames (builtins.readDir path));
in
  if source == null
  then null
  else if !builtins.isPath source || builtins.readFileType source != "directory"
  then throw "Package '${name}' module must be a source directory."
  else if !(builtins.pathExists (source + "/module.nix")) || builtins.readFileType (source + "/module.nix") != "regular" || !regularTree source
  then throw "Package '${name}' module must contain module.nix and only regular files and directories."
  else
    builtins.path {
      path = source;
      name = "${name}-module";
    }

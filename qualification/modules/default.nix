##! Discovers qualification feature modules; underscore paths are private helpers.
let
  discover = dir: let
    entries = builtins.readDir dir;
    names = builtins.filter (name: builtins.match "_.*" name == null && name != "default.nix") (builtins.attrNames entries);
  in
    builtins.concatMap (name:
      if entries.${name} == "directory"
      then discover (dir + "/${name}")
      else if entries.${name} == "regular" && builtins.match ".*\\.nix" name != null
      then [(dir + "/${name}")]
      else [])
    names;
in
  discover ./.

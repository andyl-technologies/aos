##! Separates installable runtime packages from private physical closure inputs.
let
  values = dependencies:
    if builtins.isList dependencies
    then dependencies
    else if builtins.isAttrs dependencies && (dependencies.type or null) != "derivation"
    then builtins.attrValues dependencies
    else throw "Runtime dependencies must be a list or a named attribute set.";

  normalize = dependency:
    if builtins.isAttrs dependency && dependency ? package && (dependency.type or null) != "derivation"
    then
      if builtins.attrNames dependency != ["closureOnly" "package"] || dependency.closureOnly != true
      then throw "Private runtime dependency requires package and closureOnly = true, with no other fields."
      else if !builtins.isAttrs dependency.package || (dependency.package.type or null) != "derivation"
      then throw "Private runtime dependency package must be a derivation."
      else {
        inherit (dependency) package;
        installable = false;
      }
    else {
      package = dependency;
      installable = true;
    };

  inputs = dependencies: map (dependency: (normalize dependency).package) (values dependencies);
  packages = dependencies:
    builtins.seq (values dependencies) (
      if builtins.isList dependencies
      then map (dependency: dependency.package) (builtins.filter (dependency: dependency.installable) (map normalize dependencies))
      else let
        declarations = builtins.mapAttrs (_: normalize) dependencies;
      in
        builtins.mapAttrs (_: dependency: dependency.package) (builtins.removeAttrs declarations (builtins.filter (name: !declarations.${name}.installable) (builtins.attrNames declarations)))
    );
in {
  inherit inputs packages;
}

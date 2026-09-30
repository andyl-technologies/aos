##! Exact module edges and explicitly compatible dependency declarations.
let
  semver = import ./semver.nix;
  validAbilityName = name:
    builtins.stringLength name <= 256 && builtins.match "[A-Za-z0-9_.-]+" name != null;
  compatible = dependency:
    builtins.isAttrs dependency
    && dependency ? package
    && (dependency.type or null) != "derivation";
  normalize = dependency:
    if !compatible dependency
    then {
      package = dependency;
      requirements = null;
    }
    else let
      extra = builtins.removeAttrs dependency ["package" "abilities" "packageVersion"];
      abilities = dependency.abilities or {};
      packageVersion = dependency.packageVersion or null;
      validAbilities =
        builtins.isAttrs abilities
        && builtins.length (builtins.attrNames abilities) <= 1024
        && builtins.all
        (name:
          validAbilityName name
          && builtins.isString abilities.${name}
          && builtins.deepSeq (semver.parseRequirement abilities.${name}) true)
        (builtins.attrNames abilities);
      validPackageVersion =
        packageVersion
        == null
        || (builtins.isString packageVersion
          && builtins.deepSeq (semver.parseRequirement packageVersion) true);
    in
      if
        extra
        != {}
        || !validAbilities
        || !validPackageVersion
        || (abilities == {} && packageVersion == null)
      then throw "Compatible module dependency requires package, ability ranges and/or packageVersion, with no unknown fields."
      else {
        inherit (dependency) package;
        requirements =
          {inherit abilities;}
          // (
            if packageVersion == null
            then {}
            else {inherit packageVersion;}
          );
      };
  seed = dependency: (normalize dependency).package;
  reference = moduleReference: dependency: let
    normalized = normalize dependency;
    source = moduleReference normalized.package;
  in
    if normalized.requirements == null
    then source
    else {package = source;} // normalized.requirements;
  requirement = nameFor: dependency: let
    normalized = normalize dependency;
  in
    if normalized.requirements == null
    then null
    else {package = nameFor normalized.package;} // normalized.requirements;
  references = moduleReference: declarations: let
    values = map (reference moduleReference) declarations;
    checked = builtins.foldl' (seen: value: let
      name = (value.package or value).name;
    in
      if seen ? ${name}
      then throw "Module dependency '${name}' is declared more than once; combine its compatibility ranges in one declaration."
      else seen // {${name} = true;}) {}
    values;
  in
    builtins.deepSeq checked values;
in {
  inherit normalize seed reference references requirement validAbilityName;
}

##! Inferred release requirements, explicit ranges, and immutable source pins.
let
  semver = import ./semver.nix;
  isDeclaration = dependency:
    builtins.isAttrs dependency
    && dependency ? package
    && (dependency.type or null) != "derivation";
  versions = import ./version.nix;
  normalize = dependency:
    if !isDeclaration dependency
    then let
      packageVersion = versions.requirementFor dependency;
    in {
      package = dependency;
      requirements =
        if packageVersion == null
        then null
        else {inherit packageVersion;};
    }
    else if dependency ? exact
    then
      if dependency.exact != true || builtins.removeAttrs dependency ["package" "exact"] != {}
      then throw "Exact module dependency requires package and exact = true, with no other fields."
      else {
        inherit (dependency) package;
        requirements = null;
      }
    else let
      extra = builtins.removeAttrs dependency ["package" "packageVersion"];
      packageVersion = dependency.packageVersion or null;
    in
      if extra != {} || !builtins.isString packageVersion
      then throw "Compatible module dependency requires package and packageVersion, with no unknown fields."
      else
        builtins.deepSeq (semver.parseRequirement packageVersion) {
          inherit (dependency) package;
          requirements = {inherit packageVersion;};
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
  inherit normalize seed reference references requirement;
}

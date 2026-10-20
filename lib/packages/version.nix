##! Derives release requirements from recipe versions without changing payload identity.
let
  semver = import ./semver.nix;
  strict = version: (builtins.tryEval (builtins.deepSeq (semver.parseVersion version) true)).success;
  normalize = authored:
    if !builtins.isString authored
    then throw "Package version must be a string."
    else let
      shorthand = builtins.match "([~^=])(.*)" authored;
      version =
        if shorthand == null
        then authored
        else builtins.elemAt shorthand 1;
      operator =
        if shorthand == null
        then "^"
        else builtins.head shorthand;
      valid = strict version;
    in
      if shorthand != null && !valid
      then throw "Package version shorthand requires ^, ~, or = followed by one complete SemVer release."
      else if builtins.stringLength version > 255 || (!valid && builtins.match "[A-Za-z0-9][A-Za-z0-9._+-]*" authored == null)
      then throw "Package version must identify one release; dependency ranges belong in moduleDeps."
      else {
        inherit version;
        versionRequirement =
          if valid
          then operator + version
          else null;
      };
  requirementFor = package: let
    release = normalize (package.version or "0");
    requirement = package.versionRequirement or release.versionRequirement;
  in
    if requirement == null && release.versionRequirement == null
    then null
    else if !builtins.isString requirement || !(builtins.elem requirement (map (operator: operator + release.version) ["^" "~" "="])) || !strict release.version
    then throw "Generated versionRequirement must bind one operator to the package's exact SemVer release."
    else requirement;
in {
  inherit normalize requirementFor;
}

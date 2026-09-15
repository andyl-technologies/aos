##! Package-output selector normalization at the package carrier boundary.
{
  diagnostics,
}: let
  marker = "aos-package-output-selector";
  fail = message:
    diagnostics.throw "value-type-mismatch" "abilities: ${message}";

  isLocalKey = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9._-]+" value != null;
  requireLocalKey = context: value:
    if isLocalKey value
    then value
    else fail "${context} must match [A-Za-z0-9._-]+ and contain at most 128 bytes";

  normalize = owner: depth: value:
    if depth > 64
    then fail "package output selector value exceeds 64 structural levels"
    else if builtins.isList value
    then map (normalize owner (depth + 1)) value
    else if builtins.isAttrs value && (value._type or null) == marker
    then
      if builtins.attrNames value != ["_type" "output" "package"]
      then fail "package output selector must contain only _type, package, and output"
      else {
        _type = marker;
        package =
          if requireLocalKey "package output package" value.package == "self"
          then owner
          else value.package;
        output = requireLocalKey "package output output" value.output;
      }
    else if builtins.isAttrs value
    then builtins.mapAttrs (_: normalize owner (depth + 1)) value
    else value;
in {
  normalizePackageOutputSelectors = {
    owner,
    value,
  }:
    normalize (requireLocalKey "ability package owner" owner) 1 value;
}

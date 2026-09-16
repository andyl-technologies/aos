##! Provenance-preserving package artifact resolution for OCI assembly.
##!
##! A checked projection owns a resolver closed over one authenticated package
##! record. Local selector aliases therefore have meaning only inside that
##! origin. This layer deliberately does not accept a package registry, split
##! qualified names, or reconstruct ownership from strings.
{common}: let
  checkedProjection = projection:
    if
      builtins.isAttrs projection
      && (projection._type or null) == "aos-checked-package-projection"
      && builtins.isAttrs (projection.origin or null)
      && (projection.origin._type or null) == "aos-authenticated-package-origin"
      && builtins.isAttrs (projection.origin.package or null)
      && builtins.isString (projection.origin.package.name or null)
      && builtins.isString (projection.origin.package.version or null)
      && builtins.isString (projection.origin.package.document or null)
      && builtins.isFunction (projection.origin.packageArtifactFor or null)
      && builtins.isAttrs (projection.payload or null)
      && builtins.isAttrs (projection.contract or null)
    then projection
    else common.fail "static ability contract packages must be checked projections with authenticated origins";

  checkedSelector = selector:
    if
      builtins.isAttrs selector
      && builtins.all
      (name: builtins.elem name ["_type" "package" "output"])
      (builtins.attrNames selector)
      && (!selector ? _type || selector._type == "aos-package-output-selector")
      && builtins.isString (selector.package or null)
      && selector.package != ""
      && builtins.isString (selector.output or null)
      && selector.output != ""
    then selector
    else common.fail "ability artifact must be a typed package-output selector";
in {
  inherit checkedProjection;

  resolve = projection: selector: let
    checked = checkedProjection projection;
    selected = checked.origin.packageArtifactFor (checkedSelector selector);
  in
    if builtins.isString selected || (builtins.isAttrs selected && selected ? outPath)
    then selected
    else common.fail "ability selector must resolve through its authenticated package origin";
}

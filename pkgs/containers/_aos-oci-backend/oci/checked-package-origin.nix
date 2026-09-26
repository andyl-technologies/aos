##! Provenance-preserving package artifact resolution for OCI assembly.
##!
##! A checked projection owns a resolver closed over one authenticated package
##! record. Local selector aliases therefore have meaning only inside that
##! origin. This layer deliberately does not accept a package registry, split
##! qualified names, or reconstruct ownership from strings.
{
  abilities,
  common,
}: let
  checkedProjection = abilities.checkedAuthenticatedPackageProjection;
in {
  inherit checkedProjection;

  resolve = projection: selector: let
    selected = abilities.authenticatedProjectionOutputFor {
      inherit projection selector;
    };
  in
    if builtins.isString selected || (builtins.isAttrs selected && selected ? outPath)
    then selected
    else common.fail "ability selector must resolve through its authenticated package origin";
}

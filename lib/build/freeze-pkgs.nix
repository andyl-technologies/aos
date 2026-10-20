##! lib/build/freeze-pkgs.nix — frozen `pkgs` for on-host configuration evaluation
##!
##! The stage-2 on-host evaluator must compute the config manifest WITHOUT
##! traversing the from-source `pkgs` build graph: under the eval sandbox
##! (`restrict-eval`, no IFD) forcing any from-source derivation pulls in the
##! bootstrap chain's eval-time fetches, which the sandbox forbids. Store paths
##! selected by host configuration are therefore computed at image-build time
##! without retaining packages that the evaluated image does not select.
##!
##! Freezing serializes the selected packages' explicit artifact records with
##! reversibly encoded store paths. Deployment restores string-coercible artifact
##! values; lib.getOutput selects named outputs without recreating derivations.
##! Encoding prevents unselected references from retaining the image closure.
##!
##! freezeSelectedToJSON runs at build time; frozenFromJSON restores those exact
##! records during deployment without traversing the package build graph.
##!
##! Frozen packages are data, not functions: `pkgs.foo.override`,
##! `pkgs.writeText`, `pkgs.runCommand`, etc. are NOT available. Config modules
##! that need to *build* something at eval time are by definition not eval-only
##! and must instead carry rendered text/store-path strings (the F2-A
##! render/assemble split). A frozen access to a missing builder surfaces as a
##! clear `attribute 'X' missing` rather than a build-graph escape.
{lib}: let
  isDrv = v: builtins.isAttrs v && (v.type or null) == "derivation";

  # Discard string context so the path is a plain string with no derivation
  # dependency riding along into the frozen value.
  pathString = p: builtins.unsafeDiscardStringContext (toString p);
  reverse = value: let
    length = builtins.stringLength value;
  in
    lib.concatStrings (builtins.genList (
        index: builtins.substring (length - index - 1) 1 value
      )
      length);
  encodePath = p: let
    value = pathString p;
  in
    if lib.hasPrefix "/nix/store/" value
    then "@nix-store@/${reverse (lib.removePrefix "/nix/store/" value)}"
    else throw "freeze-pkgs: package output is not a Nix store path: ${value}";
  decodePath = value:
    if lib.hasPrefix "@nix-store@/" value
    then "/nix/store/${reverse (lib.removePrefix "@nix-store@/" value)}"
    else throw "freeze-pkgs: invalid encoded store path";

  mapStorePaths = transform: value:
    if builtins.isString value
    then transform value
    else if builtins.isList value
    then builtins.map (mapStorePaths transform) value
    else if builtins.isAttrs value
    then builtins.mapAttrs (_: mapStorePaths transform) value
    else value;

  encodeStorePaths = mapStorePaths (value:
    if lib.hasPrefix "/nix/store/" value
    then encodePath value
    else value);
  decodeStorePaths = mapStorePaths (value:
    if lib.hasPrefix "@nix-store@/" value
    then decodePath value
    else value);

  # A rendered manifest can contain paths inside shell text and PATH values,
  # not just as whole JSON strings. Encode those references before placing the
  # manifest in the evaluator bundle so Nix does not retain their closures.
  transformEmbeddedPaths = pattern: transform: value:
    lib.concatStrings (builtins.map
      (part:
        if builtins.isList part
        then transform (builtins.head part)
        else part)
      (builtins.split pattern value));
  encodeEmbeddedStorePaths =
    transformEmbeddedPaths "(/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+)" encodePath;
  decodeEmbeddedStorePaths =
    transformEmbeddedPaths "(@nix-store@/[A-Za-z0-9+._?=-]+)" decodePath;

  artifacts = import ../packages/artifacts.nix {};
  freezeDrv = name: drv:
    encodeStorePaths (artifacts.reference (drv
      // {
        catalogName = drv.catalogName or name;
      }));
in {
  inherit encodeStorePaths decodeStorePaths encodeEmbeddedStorePaths decodeEmbeddedStorePaths;

  ## Stage-1: serialise the selected top-level package derivations. The caller
  ## derives `packageNames` from package-native platform declarations before
  ## this function touches a package value.
  freezeSelectedToJSON = {
    packageSet,
    packageNames,
  }: let
    checkedNames =
      if !builtins.isList packageNames || !builtins.all builtins.isString packageNames
      then throw "freeze-pkgs: packageNames must be a list of strings"
      else packageNames;
    normalizedNames = builtins.sort builtins.lessThan (lib.unique checkedNames);
    invalidNames =
      builtins.filter (
        name: !builtins.isString name || !(builtins.hasAttr name packageSet)
      )
      normalizedNames;
    candidates =
      if invalidNames == []
      then
        builtins.listToAttrs (builtins.map (name: {
            inherit name;
            value = packageSet.${name};
          })
          normalizedNames)
      else throw "freeze-pkgs: selected package names are absent from the package set: ${builtins.toJSON invalidNames}";
  in
    builtins.toJSON (lib.filterAttrs (_: v: v != null) (
      builtins.mapAttrs (
        name: v:
          if isDrv v
          then freezeDrv name v
          else null
      )
      candidates
    ));

  ## Stage-2 restores explicit artifact values. No derivation, builder, or
  ## ambient package metadata is reconstructed during deployment evaluation.
  frozenFromJSON = json:
    builtins.mapAttrs (_: reference: artifacts.value (decodeStorePaths reference))
    (builtins.fromJSON (builtins.unsafeDiscardStringContext json));
}

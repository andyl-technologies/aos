##! Package-owned evaluated OCI package evidence.
##!
##! Maps every named AOS package output to the package metadata and source
##! identity still available at evaluation time. A later realized-graph join
##! selects exact runtime outputs; declared dependency metadata is deliberately
##! not trusted as a closure approximation.
{
  lib,
  pkgs,
  packageNames ? pkgs.packageNames,
  overrides ? [],
}: let
  discard = value:
    builtins.unsafeDiscardStringContext (builtins.toString value);

  derivationPackageNames =
    builtins.filter
    (name: lib.isDerivation pkgs.${name})
    packageNames;

  normalizeLicense = license:
    if builtins.isList license
    then license
    else if builtins.isString license && license != ""
    then [license]
    else [];

  sourceIdentity = source: let
    sourcePath = discard source;
    sourceUrls =
      if builtins.isAttrs source && source ? urls
      then source.urls
      else if builtins.isAttrs source && source ? url
      then [source.url]
      else [];
    sourceHash =
      if builtins.isAttrs source && source ? outputHash
      then builtins.toString source.outputHash
      else null;
    sourceDerivation =
      if builtins.isAttrs source && source ? drvPath
      then discard source.drvPath
      else null;
  in {
    path = sourcePath;
    derivationPath = sourceDerivation;
    urls = sourceUrls;
    contentHash = sourceHash;
  };

  normalizeSourceValue = source: let
    path = builtins.toString source;
    storeSubpath = builtins.match "^(/nix/store/[0-9a-z]{32}-[^/]+)/.+$" path;
  in
    # Generated archives can be files within a derivation output. Retain that
    # output as the evidence root without realizing it during evaluation.
    if builtins.isString source && storeSubpath != null
    then builtins.substring 0 (builtins.stringLength (builtins.head storeSubpath)) source
    # A flake source subdirectory is already under /nix/store, but is not a
    # store root. Retain that exact subtree as its own source root, just as
    # when evaluating the same checked-in source from a working checkout.
    else if builtins.isPath source && builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" path == null
    then
      builtins.path {
        path = source;
        name = builtins.baseNameOf path;
      }
    else source;

  packageSourceValues = package: let
    source = package.src or null;
    explicitSources = package.passthru.evidenceSources or null;
    sources =
      if explicitSources != null
      then explicitSources
      else if source == null
      then []
      else if builtins.isList source
      then source
      else if builtins.toString source == ""
      then []
      else [source];
  in
    map normalizeSourceValue sources;

  entriesForPackage = attribute: package: let
    # Bootstrap tools can retain an unversioned runtime alias for the same
    # derivation exported by the public package set. Reuse that one canonical
    # version so an exact output does not become falsely ambiguous.
    canonicalVersions =
      if package ? version
      then []
      else
        lib.unique (
          map
          (name: pkgs.${name}.version)
          (builtins.filter
            (name:
              pkgs.${name}
              ? version
              && discard pkgs.${name}.drvPath == discard package.drvPath)
            packageNames)
        );
    version =
      if package ? version
      then package.version
      else if builtins.length canonicalVersions == 1
      then builtins.head canonicalVersions
      else "0";
    selectedOutputName = package.outputName or "out";
    # A named split-output alias (for example `pkgs.getent`) still exposes
    # every sibling in `outputs`. Only enumerate the selected output for such
    # aliases; the primary `out` package remains authoritative for all of its
    # split outputs and supplies their shared source/package identity.
    outputNames =
      if selectedOutputName == "out"
      then package.outputs or ["out"]
      else [selectedOutputName];
    sourceValues = packageSourceValues package;
    packageIdentity = {
      inherit attribute sourceValues;
      aliasOnly = selectedOutputName != "out";
      override = false;
      derivationPath = discard package.drvPath;
      pname = package.pname or package.name;
      inherit version;
      licenses = normalizeLicense (package.meta.license or []);
      sources = map sourceIdentity sourceValues;
    };
  in
    builtins.concatMap
    (outputName: let
      output =
        if builtins.hasAttr outputName package
        then package.${outputName}
        else if outputName == "out"
        then package
        else null;
    in
      lib.optional (output != null) (packageIdentity
        // {
          output = {
            name = outputName;
            path = discard output;
          };
        }))
    outputNames;

  packageEntries = builtins.concatMap (attribute: let
    package = pkgs.${attribute};
    runtimePackages = package.passthru.evidenceRuntimePackages or [];
  in
    entriesForPackage attribute package
    ++ builtins.concatLists (lib.imap (index: runtimePackage:
      entriesForPackage "${attribute}-runtime-${toString index}" runtimePackage)
    runtimePackages))
  derivationPackageNames;
  overrideEntries =
    map (override: {
      attribute = "container-evidence-override";
      aliasOnly = false;
      override = true;
      derivationPath = discard override.output.drvPath;
      pname = override.pname;
      version = override.version;
      licenses = override.licenses;
      sources = map sourceIdentity override.sources;
      sourceValues = override.sources;
      output = {
        name = override.outputName;
        path = discard override.output;
      };
    })
    overrides;
  entries = packageEntries ++ overrideEntries;

  sourcePaths =
    uniqueByPath (builtins.concatMap (entry: entry.sourceValues) entries);

  uniqueByPath = lib.uniqueBy discard;

  catalog = map (entry: builtins.removeAttrs entry ["sourceValues"]) entries;
in {
  inherit catalog sourcePaths;
}

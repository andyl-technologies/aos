##! lib/containers/package-evidence.nix -- Evaluated package evidence catalog
##!
##! Maps every named AOS package output to the package metadata and source
##! identity still available at evaluation time. A later realized-graph join
##! selects exact runtime outputs; declared dependency metadata is deliberately
##! not trusted as a closure approximation.
{
  lib,
  pkgs,
  overrides ? [],
}: let
  discard = value:
    builtins.unsafeDiscardStringContext (builtins.toString value);

  packageNames =
    builtins.filter
    (name: lib.isDerivation pkgs.${name})
    pkgs.packageNames;

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
  in
    if builtins.isPath source && builtins.match "^/nix/store/.*" path == null
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

  entriesForPackage = attribute: let
    package = pkgs.${attribute};
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
      version = package.version or "0";
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

  packageEntries = builtins.concatMap entriesForPackage packageNames;
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

  uniqueByPath = values: let
    step = state: value: let
      path = discard value;
    in
      if builtins.elem path state.seen
      then state
      else {
        seen = state.seen ++ [path];
        result = state.result ++ [value];
      };
  in
    (builtins.foldl' step {
        seen = [];
        result = [];
      }
      values).result;

  catalog = map (entry: builtins.removeAttrs entry ["sourceValues"]) entries;
in {
  inherit catalog sourcePaths;
}

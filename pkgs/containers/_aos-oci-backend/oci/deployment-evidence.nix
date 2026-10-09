##! Exact provenance for native module sources and generated deployment outputs.
{
  lib,
  packages,
  bundle,
  artifact,
}: let
  discard = value: builtins.unsafeDiscardStringContext (builtins.toString value);
  backendSource = builtins.path {
    path = ../.;
    name = "aos-oci-backend-source";
  };
  libraryLicense = builtins.path {
    path = ../../../../LICENSE;
    name = "aos-library-license";
  };
  selected = builtins.genericClosure {
    startSet =
      map (package: {
        key = discard package;
        inherit package;
      })
      packages;
    operator = entry:
      map (package: {
        key = discard package;
        inherit package;
      }) (entry.package.moduleDeps or []);
  };
  normalizeLicense = value:
    if builtins.isList value
    then value
    else if builtins.isString value
    then [value]
    else [];
  sourceIdentity = source: {
    path = discard source;
    derivationPath = null;
    urls = [];
    contentHash = null;
  };
  entry = name: version: output: licenses: sources: {
    attribute = name;
    aliasOnly = false;
    override = false;
    derivationPath =
      if output ? drvPath
      then discard output.drvPath
      else null;
    pname = name;
    inherit version licenses;
    sources = map sourceIdentity sources;
    output = {
      name =
        if output ? drvPath
        then "out"
        else "source";
      path = discard output;
    };
  };
  moduleEntries = lib.concatMap (selected: let
    package = selected.package;
    source = package.module or null;
    name = package.catalogName or package.pname or package.name;
    # A module may carry an explicit license distinct from its software payload.
    # Missing metadata stays empty and the existing publication gate rejects it.
    licenses = normalizeLicense (package.moduleLicense or package.meta.moduleLicense or package.meta.license or []);
  in
    lib.optional (source != null) (entry "${name}-module" (package.version or "0") source licenses [source]))
  selected;
  libraryEntry = entry "aos-module-library" "1" bundle.nativeSourceLibrary ["Apache-2.0"] [bundle.nativeSourceLibrary libraryLicense];
  sourceInputs =
    [backendSource libraryLicense bundle.nativeSourceLibrary]
    ++ map (record: record.package.module) (builtins.filter (record: record.package ? module) selected)
    ++ builtins.filter (input:
      !(builtins.elem (discard input) (map discard bundle.nativeDeploymentParts)))
    bundle.nativeEvaluationInputs;
  generatedSources = lib.uniqueBy discard sourceInputs;
  generatedEntries = lib.imap (index: output:
    entry "aos-native-deployment-${toString index}" "1" output ["Apache-2.0"] generatedSources)
  ([artifact bundle] ++ bundle.nativeDeploymentParts);
  unknownInputs = builtins.filter (input:
    !(builtins.elem (discard input) (map (entry: entry.output.path) (moduleEntries ++ [libraryEntry] ++ generatedEntries))))
  bundle.nativeEvaluationInputs;
  # Caller-owned configuration inputs need their own explicit package catalog
  # attribution; generated-output provenance does not assign their license.
  unknownEntries = map (input: entry "native-configuration-input" "1" input [] [input]) unknownInputs;
in {
  catalog = moduleEntries ++ [libraryEntry] ++ generatedEntries ++ unknownEntries;
  sourcePaths = generatedSources;
}

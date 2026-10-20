##! Exact provenance for native module sources and generated deployment outputs.
{
  lib,
  packages,
  bundle,
  artifact,
  knownPackageCatalog ? [],
  backendConfigurationInputs ? [],
}: let
  moduleDependencies = import ../../../../lib/packages/module-dependencies.nix;
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
      }) (map moduleDependencies.seed (entry.package.moduleDeps or [])
        ++ (entry.package.runtimeDeps or []));
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
  moduleSources = lib.uniqueBy discard (
    [bundle.nativeSourceLibrary libraryLicense]
    ++ map (record: record.package.module) (builtins.filter (record: record.package ? module) selected)
  );
  # These documents are generated from the same evaluated package modules.
  # Preserve their declared attribution rather than treating them as unknown
  # caller configuration, or assigning a license to arbitrary input files.
  companionEntries = lib.concatMap (record: let
    package = record.package;
    name = package.catalogName or package.pname or package.name;
    licenses = normalizeLicense (package.moduleLicense or package.meta.moduleLicense or package.meta.license or []);
  in
    lib.optional (package ? deploymentArtifact)
    (entry "${name}-deployment" (package.version or "0") package.deploymentArtifact licenses moduleSources)
    ++ lib.optional (package ? documentationArtifact)
    (entry "${name}-documentation" (package.version or "0") package.documentationArtifact licenses moduleSources))
  selected;
  backendEntries = lib.imap (index: input:
    entry "aos-oci-backend-configuration-${toString index}" "1" input ["Apache-2.0"] [backendSource libraryLicense])
  backendConfigurationInputs;
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
    !(builtins.elem (discard input) (map (entry: entry.output.path)
        (knownPackageCatalog ++ moduleEntries ++ companionEntries ++ backendEntries ++ [libraryEntry] ++ generatedEntries))))
  bundle.nativeEvaluationInputs;
  # Caller-owned configuration inputs need their own explicit package catalog
  # attribution; generated-output provenance does not assign their license.
  unknownEntries = map (input: entry "native-configuration-input" "1" input [] [input]) unknownInputs;
in {
  catalog = moduleEntries ++ companionEntries ++ backendEntries ++ [libraryEntry] ++ generatedEntries ++ unknownEntries;
  sourcePaths = generatedSources;
}

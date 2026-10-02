##! Retains immutable native evaluation inputs before constructing a graph.
{
  lib,
  pkgs,
  packages,
  packageArtifacts ? lib.packageModules.payloads packages,
  scope,
  system,
  configuration ? [],
  runtimeConfiguration ? [],
  supplementalInputs ? [],
  retainPayloads ? true,
  osRelease ? null,
}: let
  modules = lib.packageModules;
  library = lib.packageModuleLibrary;
  artifacts = lib.packageArtifacts;
  selectedArtifact = artifact:
    artifacts.metadata artifact
    // lib.optionalAttrs retainPayloads {inherit (artifact) path;};
  packageRecords = map (record:
    record
    // {
      artifacts = {
        package = artifacts.metadata record.artifacts.package;
        dependencies = builtins.mapAttrs (_: artifacts.metadata) record.artifacts.dependencies;
      };
    }) (modules.closure packages);
  moduleEnvelopes = builtins.mapAttrs (_: builtins.toString) (modules.envelopes packages);
  # Source admission and installed artifacts are independent. Only selected
  # artifacts receive payload envelopes; every admitted module keeps its source.
  resolvedPackages = modules.resolved packages;
  envelopeFor = artifact: let
    canonical = artifacts.metadata (artifacts.canonical artifact);
    matching = builtins.filter (entry:
      artifacts.metadata entry.identity.artifact == canonical)
    resolvedPackages;
  in
    if builtins.length matching != 1
    then throw "Selected artifact '${artifact.path}' does not identify one admitted package envelope."
    else builtins.toString (builtins.head matching).package.deploymentArtifact;
  packageEnvelopes = builtins.listToAttrs (map (artifact: {
      name = builtins.unsafeDiscardStringContext (artifacts.canonical artifact).path;
      value = envelopeFor artifact;
    })
    packageArtifacts);
  resolutionLock = import ../packages/resolution-lock.nix {inherit packages;};
  descriptor =
    {
      schema = "aos.package.evaluation-input";
      library = "${library}/default.nix";
      inherit scope;
      # Envelope payload catalogs discard contexts; these companions retain only
      # module sources, including schema dependencies absent from selected payloads.
      inherit moduleEnvelopes packageEnvelopes osRelease;
      packages = {
        inherit system;
        artifacts = map selectedArtifact packageArtifacts;
        modules = packageRecords;
      };
      configuration = map builtins.toString configuration;
      runtimeConfiguration = map builtins.toString runtimeConfiguration;
      supplementalInputs = map (input: let
        path = builtins.toString input;
      in
        if builtins.match "/nix/store/[^/]+" path == null
        then throw "Supplemental evaluation inputs must name immutable store roots."
        else path)
      supplementalInputs;
    }
    // lib.optionalAttrs (resolutionLock != null) {inherit resolutionLock;};
  buildPackages = pkgs.buildPackages;
  writeArtifact = lib.build.writeArtifact {
    inherit (buildPackages) bash coreutils;
    system = buildPackages.stdenv.buildPlatform.system;
  };
  libraryClosure = (lib.build.closureInfo {pkgs = buildPackages;}) {
    rootPaths = [library];
    pname = "aos-evaluation-library-identity";
  };
  # Early projections need the original module sources and catalog identities,
  # but do not install or execute the host payloads. Full deployment descriptors
  # retain those payloads; only the early projection opts into source retention.
  template = writeArtifact {
    name = "aos-native-evaluation-template";
    destination = "/template.json";
    text = builtins.toJSON descriptor;
  };
  artifact = lib.build.runArtifact {pkgs = buildPackages;} "aos-native-evaluation-inputs" {} ''
    library_hash=$(${buildPackages.jq}/bin/jq -er \
      --arg library ${lib.escapeShellArg (builtins.toString library)} \
      '.paths[] | select(.path == $library) | .narHash' ${libraryClosure}/inventory.json)
    library_hash=$(${buildPackages.nix}/bin/nix --extra-experimental-features nix-command \
      hash to-base16 --type sha256 "$library_hash")
    ${buildPackages.jq}/bin/jq --arg hash "$library_hash" \
      '. + {libraryNarHash:("sha256:" + $hash)}' ${template}/template.json > "$out"
  '';
in
  artifact
  // {
    nativeEvaluationDescriptor = true;
    nativeModuleEnvelopes = moduleEnvelopes;
    nativePackageEnvelopes = packageEnvelopes;
    # Exposes the original inputs for build-time replay checks without reading
    # the generated descriptor or treating this metadata as runtime authority.
    nativeEvaluationInputs = {
      inherit packages packageArtifacts scope configuration runtimeConfiguration supplementalInputs osRelease;
    };
  }

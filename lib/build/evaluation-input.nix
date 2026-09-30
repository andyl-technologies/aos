##! Retains immutable native evaluation inputs before constructing a graph.
{
  lib,
  pkgs,
  packages,
  scope,
  system,
  configuration ? [],
  runtimeConfiguration ? [],
  supplementalInputs ? [],
  retainPayloads ? true,
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
  resolutionLock = import ../packages/resolution-lock.nix {inherit packages;};
  descriptor =
    {
      schema = "aos.package.evaluation-input";
      library = "${library}/default.nix";
      inherit scope;
      # Envelope payload catalogs discard contexts; these companions retain only
      # module sources, including schema dependencies absent from selected payloads.
      inherit moduleEnvelopes;
      packages = {
        inherit system;
        artifacts = map selectedArtifact (modules.payloads packages);
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
  libraryClosure = (lib.build.closureInfo {pkgs = buildPackages;}) {
    rootPaths = [library];
    pname = "aos-evaluation-library-identity";
  };
  # Early projections need the original module sources and catalog identities,
  # but do not install or execute the host payloads. Full deployment descriptors
  # retain those payloads; only the early projection opts into source retention.
  template = buildPackages.writeTextFile {
    name = "aos-native-evaluation-template";
    destination = "/template.json";
    text = builtins.toJSON descriptor;
  };
  artifact = pkgs.runCommand "aos-native-evaluation-inputs" {} ''
    rmdir "$out"
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
    # Exposes the original inputs for build-time replay checks without reading
    # the generated descriptor or treating this metadata as runtime authority.
    nativeEvaluationInputs = {
      inherit packages scope configuration runtimeConfiguration supplementalInputs;
    };
  }

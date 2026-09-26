##! Authenticated artifact backend selection and provider identity.
{
  lib,
  pkgs,
}: let
  packageModule = lib.abilities.authenticatedPackageModuleRecordFor pkgs.aos-oci-backend;
  policyModule = {
    name = "aos";
    version = pkgs.aos.version;
    module = pkgs.aos.module + "/artifact-backend.nix";
  };
  providerModule = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos-oci-backend;
    implementation = "artifact-backend";
  };
  backendArtifact = lib.abilities.packageOutput {};
  baseModules = [
    ../../modules/abilities/default.nix
    ../../modules/base/artifact-backend.nix
    {
      options.assertions = lib.mkOption {
        type = lib.types.listOf lib.types.anything;
        default = [];
      };
    }
  ];
  static = lib.evalModules {
    inherit lib;
    enableAbilitySelection = true;
    modules = baseModules;
    packageModules = [packageModule policyModule];
  };
  evaluateSelected = {request ? "aos:artifact-backend"}:
    lib.evalModules {
      inherit lib;
      enableAbilitySelection = true;
      modules =
        baseModules
        ++ [
          {
            aos.abilities = {
              environment = {
                authority = "test";
                key = "artifact-backend";
                stage = "host";
              };
              bindings.selected = {
                inherit request;
                implementation = "aos-oci-backend:artifact-backend";
                providerInstance = "aos-oci-backend:artifact-backend-provider";
                slot = "artifact-backend";
              };
              requirementTemplates = lib.mkIf (request != "aos:artifact-backend") {
                ${request} = {
                  interface = lib.abilities.interfaces.artifactBackend.interfaces.backend.identity.name;
                  inherit (lib.abilities.interfaces.artifactBackend.interfaces.backend.identity) abi descriptor;
                };
              };
              instances = lib.mkIf (request != "aos:artifact-backend") {
                ${request} = {};
              };
              requests = lib.mkIf (request != "aos:artifact-backend") {
                ${request} = {
                  requirement = request;
                  consumer = request;
                  parameters = true;
                };
              };
            };
          }
        ];
      packageModules =
        [packageModule]
        ++ lib.optional (request == "aos:artifact-backend") policyModule;
      selectedProviderModules = [providerModule];
    };
  selected = evaluateSelected {};
  systemOwned = evaluateSelected {request = "system:wrong-artifact-backend";};
  alternateRequest = builtins.tryEval (builtins.deepSeq
    systemOwned.config.aos.artifacts.backend
    true);
  backend = selected.config.aos.artifacts.backend;
  output = selected.config.aos.abilities.compositionOutputs."aos:artifact-backend".artifact-reference;
  projectedArtifact = evaluated: request:
    (lib.abilities.sourceStageFixedPoint evaluated.config.aos.abilities)
    .compositionOutputs.${request}.artifact-reference.value;
  providerArtifact = lib.abilities.packageOutput {package = "aos-oci-backend";};
in
  assert builtins.elem "ability-effects-v1" pkgs.aos-oci-backend.contract.value.required_features;
  assert static.config.aos.artifacts.backend == null;
  assert !(static.config.aos.abilities.instances ? "aos-oci-backend:artifact-backend-provider");
  assert alternateRequest.success;
  assert backend._type == "aos-package-artifact-backend";
  assert backend.package == builtins.toString pkgs.aos-oci-backend;
  assert backend.artifact == output.value;
  assert backend.artifact == backendArtifact;
  assert projectedArtifact selected "aos:artifact-backend" == providerArtifact;
  assert projectedArtifact systemOwned "system:wrong-artifact-backend" == providerArtifact;
  assert output.phase == "planning";
  assert output.lifetime == "persistent";
  assert output.visibility == "protected";
  assert builtins.all (entry: entry.assertion) selected.config.assertions; true

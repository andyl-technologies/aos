##! Authenticated artifact backend selection and provider identity.
{
  lib,
  pkgs,
}: let
  packageModule = lib.abilities.authenticatedPackageModuleRecordFor pkgs.aos-oci-backend;
  providerModule = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos-oci-backend;
    implementation = "artifact-backend";
  };
  backendArtifact = lib.abilities.packageOutput {};
  baseModules = [
    lib.abilities.module
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
    packageModules = [packageModule];
  };
  evaluateSelected = {request ? "system:artifact-backend"}:
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
              requirementTemplates = lib.mkIf (request != "system:artifact-backend") {
                ${request} = {
                  interface = lib.abilities.interfaces.artifactBackend.interfaces.backend.identity.name;
                  inherit (lib.abilities.interfaces.artifactBackend.interfaces.backend.identity) abi descriptor;
                };
              };
              instances = lib.mkIf (request != "system:artifact-backend") {
                ${request} = {};
              };
              requests = lib.mkIf (request != "system:artifact-backend") {
                ${request} = {
                  requirement = request;
                  consumer = request;
                  parameters = true;
                };
              };
            };
          }
      ];
      packageModules = [packageModule];
      selectedProviderModules = [providerModule];
    };
  selected = evaluateSelected {};
  wrongRequest = builtins.tryEval (builtins.deepSeq
    (evaluateSelected {request = "system:wrong-artifact-backend";}).config.aos.artifacts.backend
    true);
  backend = selected.config.aos.artifacts.backend;
  output = selected.config.aos.abilities.compositionOutputs."system:artifact-backend".artifact-reference;
in
  assert static.config.aos.artifacts.backend == null;
  assert !(static.config.aos.abilities.instances ? "aos-oci-backend:artifact-backend-provider");
  assert !wrongRequest.success;
  assert backend._type == "aos-package-artifact-backend";
  assert backend.package == builtins.toString pkgs.aos-oci-backend;
  assert backend.artifact == output.value;
  assert backend.artifact == backendArtifact;
  assert output.phase == "planning";
  assert output.lifetime == "persistent";
  assert output.visibility == "protected";
  assert builtins.all (entry: entry.assertion) selected.config.assertions; true

##! Package-owned artifact construction backend requirement.
{
  config,
  lib,
  ...
}: let
  backend = lib.abilities.interfaces.artifactBackend.interfaces.backend;
  hostStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
in {
  config.aos.abilities = {
    requirementTemplates.artifact-backend = {
      description = "Requires one authenticated package-owned artifact construction backend.";
      interface = backend.identity.name;
      inherit (backend.identity) abi descriptor;
    };
    instances = lib.mkIf hostStage {artifact-backend = {};};
    requests = lib.mkIf hostStage {
      artifact-backend = {
        requirement = "artifact-backend";
        consumer = "artifact-backend";
        parameters = true;
      };
    };
  };
}

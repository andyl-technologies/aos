##! Package-owned immutable image builder requirement.
{
  config,
  lib,
  ...
}: let
  builder = lib.abilities.interfaces.imageBuilder.interfaces.builder;
  configured = config.aos.abilities.environment != null;
in {
  config.aos.abilities = {
    requirementTemplates.image-builder = {
      description = "Requires one package-owned immutable image builder.";
      interface = builder.identity.name;
      inherit (builder.identity) abi descriptor;
    };
    instances = lib.mkIf configured {image-builder = {};};
    requests = lib.mkIf configured {
      image-builder = {
        requirement = "image-builder";
        consumer = "image-builder";
        parameters = true;
      };
    };
  };
}

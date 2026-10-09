##! Authored runtime defaults shared by golden-image profiles.
{
  config,
  lib,
  options,
  ...
}: let
  generation = lib.mkOption {
    type = lib.types.deferred lib.types.str;
    default = config.aos.abilities.configurationLower.operations.install.effects.image.outputs.image;
    description = "Mounted configuration generation required before realizing this resource.";
  };
in {
  imports = [./boot-policy.nix];
  config = lib.mkMerge [
    {
      aos.login.profile.enable = true;
      aos.configurationLower.enable = true;
      aos.security.ebpfLsm.enable = lib.mkDefault true;

      # This typed input reference orders handlers after the overlay mount without
      # inspecting their effect keys. The lower consumes only literal file inputs.
      aos.abilities = {
        configuration.operations.file.input.options.configurationGeneration = generation;
        serviceManagement.operations.realize.input.options.configurationGeneration = generation;
        network.operations.configure.input.options.configurationGeneration = generation;
      };
    }
    (lib.optionalAttrs (options.aos ? abilityCrucible) {
      aos.abilityCrucible.activationOwner = lib.mkIf config.aos.abilityCrucible.enable (lib.mkDefault "manager");
    })
    (lib.optionalAttrs (options.aos.tests or {} ? executionObserver) {
      aos.tests.executionObserver.activationOwner =
        lib.mkIf
        (config.aos.tests.executionObserver.enable && config.aos.tests.executionObserver.mode == "managed-service")
        (lib.mkDefault "manager");
    })
  ];
}

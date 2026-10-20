##! Authored runtime defaults shared by golden-image profiles.
{
  config,
  lib,
  options,
  ...
}: let
  generation = config.aos.abilities.configurationLower.operations.install.effects.image.outputs.image;
  orderedOperations = {
    configuration = "file";
    serviceManagement = "realize";
    network = "configure";
  };
in {
  imports = [./boot-policy.nix];

  # Extend the invocation modules so ordering stays in the effect graph rather
  # than adding host-specific arguments to otherwise portable handler inputs.
  options.aos.abilities = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: let
      abilityName = name;
    in {
      options.operations = lib.mkOption {
        type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: {
          options.effects = lib.mkOption {
            type = lib.types.attrsOf (lib.types.submodule {
              config.after =
                lib.mkIf ((orderedOperations.${abilityName} or null) == name)
                (lib.mkAfter [generation]);
            });
          };
        }));
      };
    }));
  };

  config = lib.mkMerge [
    {
      aos.login.profile.enable = true;
      aos.configurationLower.enable = true;
      aos.security.ebpfLsm.enable = lib.mkDefault true;
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

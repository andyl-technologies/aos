##! An unbundled package supplies this option only after authenticated acquisition.
{
  config,
  lib,
  package,
  ...
}: let
  field = type: lib.mkOption {inherit type;};
in {
  options.aos.acquiredFixture = {
    value = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
    };
    stateDir = lib.mkOption {
      type = lib.types.strMatching "/.*";
      default = "/build/aos-boot-acquired-state";
    };
  };
  config = lib.mkMerge [
    {
      aos.abilities.acquiredFixture.operations.ensure = {
        input.options = {
          stateDir = field (lib.types.strMatching "/.*");
          value = field lib.types.str;
          failAfterWrite = field lib.types.bool;
        };
        result.options = {
          value = field lib.types.str;
          resource = field lib.types.str;
        };
        handler.program = package;
      };
    }
    (lib.mkIf (config.aos.acquiredFixture.value != null) {
      aos.abilities.acquiredFixture.operations.ensure.effects.host = {
        lifetime = "persistent";
        input = {
          value = config.aos.acquiredFixture.value;
          stateDir = config.aos.acquiredFixture.stateDir;
          failAfterWrite = false;
        };
      };
    })
  ];
}

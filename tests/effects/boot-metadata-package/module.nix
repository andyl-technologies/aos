##! Native fixture contracts with the actual retained OS source declarations.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.bootstrapFixture;
  field = type: lib.mkOption {inherit type;};
in {
  options.aos.apm.desiredPackages = lib.mkOption {
    type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9+._=-]*");
    default = [];
    extensible = true;
  };
  options.aos.bootstrapFixture = {
    stateDir = lib.mkOption {
      type = lib.types.strMatching "/.*";
      default = "/build/aos-boot-bootstrap-state";
    };
    value = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
    };
    failAfterWrite = lib.mkOption {
      type = lib.types.bool;
      default = false;
    };
  };
  config = lib.mkMerge [
    {
      aos.abilities.storageProvisioning.operations.prepare = {
        input.options = {
          stateDir = field (lib.types.strMatching "/.*");
          authorized_input = field lib.types.str;
          committed_plan = field lib.types.str;
        };
        result.options = {
          resource = field lib.types.str;
          source = field (lib.types.enum ["operator" "fallback"]);
          committed_plan = field lib.types.str;
          authorized_input = field lib.types.str;
          authorized_input_sha256 = field lib.types.str;
        };
        handler.program = package;
      };
      aos.abilities.bootstrapFixture.operations.ensure = {
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
    (lib.mkIf (cfg.value != null) {
      aos.abilities.bootstrapFixture.operations.ensure.effects.host = {
        lifetime = "persistent";
        input = {inherit (cfg) value failAfterWrite stateDir;};
      };
    })
  ];
}

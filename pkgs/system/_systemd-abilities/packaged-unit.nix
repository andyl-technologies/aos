##! Retains upstream unit bodies with explicit native augmentation ownership.
{lib, ...}: {
  aos.abilities.packagedUnit.operations.ensure = {
    input.options = {
      source = lib.mkOption {
        type = lib.types.str;
        description = "Immutable upstream service unit file whose body is preserved.";
      };
      activation = lib.mkOption {
        type = lib.types.enum ["reference"];
        default = "reference";
        description = "Retain a unit reference without starting template instances.";
      };
      accepted_exit_statuses = lib.mkOption {
        type = lib.types.listOf (lib.types.ints.between 0 255);
        default = [];
        description = "Additional successful service exit statuses.";
      };
      search_path = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Immutable executable directories for the inherited upstream commands.";
      };
      reload_triggers = lib.mkOption {
        type = lib.types.listOf (lib.types.deferred lib.types.str);
        default = [];
        description = "Owned resources whose changes require manager reload.";
      };
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Canonical upstream service unit name.";
    };
  };
}

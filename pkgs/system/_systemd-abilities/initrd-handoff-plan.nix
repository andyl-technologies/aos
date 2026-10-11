##! Projects completed native boot scope handoff into systemd unit topology.
{
  config,
  lib,
  ...
}: let
  plan = config.aos.boot.handoffParameters or null;
  unitIdentity = lib.types.submodule {
    options = {
      kind = lib.mkOption {
        type = lib.types.enum ["unit"];
        default = "unit";
        description = "Systemd handoff identity kind.";
      };
      unit_name = lib.mkOption {
        type = lib.types.str;
        description = "Unit whose completion is required before switch-root.";
      };
    };
  };
in {
  options.aos.systemd.initrdHandoffRealization = lib.mkOption {
    type = lib.types.nullOr (lib.types.submodule {
      options = {
        schema = lib.mkOption {
          type = lib.types.enum ["aos.systemd.initrd-handoff-plan/v1"];
          default = "aos.systemd.initrd-handoff-plan/v1";
          description = "Systemd boot topology format.";
        };
        mechanism = lib.mkOption {
          type = lib.types.enum ["systemd-switch-root"];
          default = "systemd-switch-root";
          description = "Mechanism preserving the completed initrd scope.";
        };
        completion_unit = lib.mkOption {
          type = unitIdentity;
          description = "Bootstrap completion target.";
        };
        required_units = lib.mkOption {
          type = lib.types.listOf unitIdentity;
          description = "Bootstrap services completed before switch-root.";
        };
      };
    });
    default = null;
    internal = true;
    description = "Systemd topology derived from the native boot handoff configuration.";
  };

  config.aos.systemd.initrdHandoffRealization = lib.mkIf (plan != null) {
    completion_unit.unit_name = plan.completion;
    required_units = builtins.map (unit: {unit_name = unit;}) plan.preparations;
  };
}

##! Typed systemd projection of the executor's initrd handoff plan.
{lib, ...}: let
  types = lib.abilities.types;
  unitIdentity = types.record {
    fields = {
      kind = types.enum ["unit"];
      unit_name = types.string {
        maxLength = 255;
        syntax = null;
      };
    };
  };
  realizationType = types.record {
    fields = {
      schema = types.enum ["aos.systemd.initrd-handoff-plan/v1"];
      mechanism = types.enum ["systemd-switch-root"];
      completion_unit = unitIdentity;
      required_units = types.list {
        element = unitIdentity;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
in {
  options.aos.systemd.initrdHandoffRealization = lib.mkOption {
    type = lib.types.nullOr realizationType;
    default = null;
    internal = true;
    description = "Systemd unit topology derived from the typed initrd handoff plan.";
  };
}

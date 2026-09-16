##! Systemd realization of the provider-neutral boot-preparation handoff.
{lib, ...}: let
  types = lib.abilities.types;
  interface = lib.abilities.interfaces.bootPreparation.interfaces.handoff;
  artifact = lib.abilities.packageOutput {};
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
      schema = types.enum ["aos.systemd.boot-preparation-handoff-realization/v1"];
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
  config.aos.abilities.implementations.boot-preparation-handoff = {
    description = "Realizes the checked initrd-to-host preparation handoff through systemd bootstrap units.";
    interface = interface.identity;
    inherit artifact;
    inherit (interface) methods;
    guarantees = [];
    providerModule = {
      inherit artifact;
      path = "share/aos/providers/systemd.nix";
    };
    desiredType = realizationType;
    requiredFeatures = [];
  };
}

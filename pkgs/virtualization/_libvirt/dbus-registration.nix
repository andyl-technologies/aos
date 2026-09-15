##! Package-owned D-Bus registration supplied by libvirt.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.services.libvirt;
  contributionInterface = {
    name = "aos.dbus.system-registration-contribution";
    abi = 1;
    descriptor = null;
  };
  artifact = lib.abilities.packageOutput {};
  registrationAvailable =
    config.aos.abilities.environment
    == null
    || builtins.any (declaration:
      declaration.name
      == contributionInterface.name
      && declaration.abi == contributionInterface.abi)
    (builtins.attrValues config.aos.abilities.interfaces);
in {
  config.aos.abilities = lib.mkIf (cfg.enable && registrationAvailable) {
    requirementTemplates.dbus-system-registration = {
      description = "Contributes libvirt's system-bus activation and policy artifacts.";
      interface = contributionInterface.name;
      inherit (contributionInterface) abi descriptor;
      methods = ["observe"];
      guarantees = [];
      strength = "required";
      fallback = null;
    };

    requests.dbus-system-registration = {
      requirement = "dbus-system-registration";
      consumer = "libvirt";
      scope = ["system-bus"];
      parameters = {
        name = "libvirt";
        activation_directories = [
          {
            inherit artifact;
            path = "share/dbus-1/system-services";
          }
        ];
        policy_directories = [
          {
            inherit artifact;
            path = "share/dbus-1/system.d";
          }
        ];
      };
    };
  };
}

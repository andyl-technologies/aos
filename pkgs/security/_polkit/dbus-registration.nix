##! Package-owned D-Bus registration supplied by polkit.
{
  config,
  lib,
  ...
}: let
  serviceEnabled = config.aos.services."polkit.polkit".enable;
  contributionInterface = {
    name = "aos.dbus.system-registration-source";
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
  config.aos.abilities = lib.mkMerge [
    (lib.mkIf registrationAvailable {
      requirementTemplates.dbus-system-registration = {
        description = "Contributes polkit's system-bus activation and policy artifacts.";
        interface = contributionInterface.name;
        inherit (contributionInterface) abi descriptor;
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
    })

    (lib.mkIf (registrationAvailable && serviceEnabled) {
      requests.dbus-system-registration = {
        requirement = "dbus-system-registration";
        consumer = "polkit";
        scope = ["system-bus"];
        parameters = {
          name = "polkit";
          activation_directories = [
            {
              inherit artifact;
              path = "share/dbus-1/system-services";
            }
          ];
          policy_directories = [];
        };
      };
    })
  ];
}

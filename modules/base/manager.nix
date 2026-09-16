##! Provider-neutral system manager requirement and selected projection.
{lib, ...}: let
  consumer = "system:manager";
  managerInterface = lib.abilities.interfaces.systemManager.interfaces.manager;
in {
  imports = [./_manager-contributions.nix];

  config.aos.abilities = {
    instances.${consumer} = {};
    requirementTemplates."system:manager" = {
      description = "Requires the system's package-owned manager implementation.";
      interface = managerInterface.identity.name;
      inherit (managerInterface.identity) abi descriptor;
    };
    requests."system:manager" = {
      requirement = "system:manager";
      inherit consumer;
      parameters = true;
    };
  };
}

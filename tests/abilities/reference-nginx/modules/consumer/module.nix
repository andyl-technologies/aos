##! Synthetic consumer for the production nginx service contract.
{lib, ...}: let
  serviceInstance = lib.abilities.interfaces.serviceManagement.interfaces.serviceInstance.identity;
in {
  config.aos.abilities.requirementTemplates.nginx = {
    description = "Requires the production service instance created for nginx.";
    interface = serviceInstance.name;
    inherit (serviceInstance) abi descriptor;
    methods = [];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
}

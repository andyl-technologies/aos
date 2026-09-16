##! Synthetic consumer for nginx and reference HTTP backend discovery.
{lib, ...}: let
  serviceInstance = lib.abilities.interfaces.serviceManagement.interfaces.serviceInstance.identity;
in {
  config.aos.abilities.requirementTemplates = {
    nginx = {
      description = "Requires the production service instance created for nginx.";
      interface = serviceInstance.name;
      inherit (serviceInstance) abi descriptor;
      methods = [];
      guarantees = [];
      strength = "required";
      fallback = null;
    };
    backend = {
      description = "Requires the synthetic HTTP backend registry.";
      interface = "aos.test.http-backend";
      abi = 1;
      descriptor = null;
      methods = [];
      guarantees = [];
      strength = "required";
      fallback = null;
    };
  };
}

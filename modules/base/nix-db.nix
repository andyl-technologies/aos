##! Require readiness of the selected local package store.
{lib, ...}: let
  consumerInstance = "system:nix-db";
  databaseInterface = lib.abilities.interfaceSelector {
    name = "aos.nix.store-database";
    abi = 1;
  };
in {
  config.aos.abilities = {
    instances.${consumerInstance} = {};

    requirementTemplates."system:nix-store-database" =
      databaseInterface
      // {
        description = "Require the selected local package store to be ready.";
        methods = ["converge" "observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };

    requests."system:nix-store-database" = {
      requirement = "system:nix-store-database";
      consumer = consumerInstance;
      scope = ["database"];
      parameters = {
        scope = "local";
        registration = {
          path = "/aos-registration";
          required = false;
        };
        prerequisites = [];
      };
    };
  };
}

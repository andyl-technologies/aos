##! Package-owned requirement for the selected local package store.
{
  config,
  lib,
  ...
}: let
  consumerInstance = "nix-db";
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  databaseInterface = lib.abilities.interfaces.nixStoreDatabase.interface;
  database = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "nix-store-database";
    interface = databaseInterface;
    inherit (databaseInterface) methods;
    parameters = {
      scope = "local";
      registration = {
        path = "/aos-registration";
        required = false;
      };
      prerequisites = [];
    };
  };
  contribution = serviceManagement.splitContribution database;
in {
  config = lib.mkMerge [
    {aos.abilities = contribution.declarations;}
    (lib.mkIf (config.aos.abilities.environment != null) {
      aos.abilities = lib.mkMerge [
        {instances.${consumerInstance} = {};}
        contribution.configured
      ];
    })
  ];
}

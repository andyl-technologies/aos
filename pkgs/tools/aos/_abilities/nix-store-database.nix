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
in {
  config = serviceManagement.producerModule {
    inherit config lib;
    producers = [database];
    enabled = true;
  };
}

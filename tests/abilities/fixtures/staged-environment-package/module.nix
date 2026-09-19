##! Synthetic package-owned initrd consumer for stage-isolation checks.
{lib, ...}: let
  contribution = lib.abilities.interfaces.serviceManagement.forProducer {
    consumerInstance = "preparation-consumer";
    key = "fixture-preparation";
    interface = lib.abilities.interfaces.bootPreparation.interfaces.preparation;
    methods = ["observe" "prepare"];
    parameters = {
      execution = {
        artifact = lib.abilities.packageOutput {};
        entry_point = "libexec/fixture-preparation";
        arguments = [];
      };
      prerequisites = [];
    };
  };
in {
  config.aos.abilities = lib.mkMerge [
    {instances.preparation-consumer = {};}
    contribution
  ];
}

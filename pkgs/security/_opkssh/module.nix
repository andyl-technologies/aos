##! Package-owned opkssh runtime entry requirement.
{
  config,
  lib,
  ...
}: let
  enabled = lib.attrByPath ["aos" "services" "opkssh" "enable"] false config;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  runtimeEntries = serviceManagement.forProducer {
    consumerInstance = "runtime";
    key = "runtime-entries";
    interface = serviceManagement.interfaces.runtimeEntryPopulation;
    methods = ["observe"];
    parameters.entries = [
      {
        kind = "file";
        path = "/var/log/opkssh.log";
        mode = "0660";
        owner = "root";
        group = "opksshuser";
      }
    ];
  };
  contribution = serviceManagement.splitContribution runtimeEntries;
in {
  config = lib.mkMerge [
    {aos.abilities = contribution.declarations;}
    (lib.mkIf (enabled && config.aos.abilities.environment != null) {
      aos.abilities = lib.mkMerge [
        {instances.runtime = {};}
        contribution.configured
      ];
    })
  ];
}

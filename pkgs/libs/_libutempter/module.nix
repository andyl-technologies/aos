##! Package-owned privileged helper request for terminal accounting.
{
  config,
  lib,
  ...
}: let
  enabled = lib.attrByPath ["aos" "security" "utempter" "enable"] false config;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  wrapper = serviceManagement.forProducer {
    consumerInstance = "runtime";
    key = "wrapper-utempter";
    interface = serviceManagement.interfaces.filesystemEntry;
    methods = ["materialize" "observe" "release"];
    parameters = {
      name = "utempter";
      entry = {
        kind = "copied-file";
        source = {
          kind = "artifact-file";
          reference = {
            artifact = lib.abilities.packageOutput {};
            path = "lib/utempter/utempter";
          };
        };
        maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
      };
      destination = "/run/wrappers/bin/utempter";
      owner = "root";
      group = "utmp";
      mode = "2711";
      prerequisites = [(lib.abilities.resultOf "aos:wrapper-bin" "resource")];
    };
  };
  contribution = serviceManagement.splitContribution wrapper;
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

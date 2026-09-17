##! Package-owned privileged ping wrapper requests.
{
  config,
  lib,
  ...
}: let
  enabled = lib.attrByPath ["aos" "profiles" "development" "enable"] false config;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  wrapper = name:
    serviceManagement.forProducer {
      consumerInstance = "runtime";
      key = "wrapper-${name}";
      interface = serviceManagement.interfaces.filesystemEntry;
      methods = ["materialize" "observe" "release"];
      parameters = {
        inherit name;
        entry = {
          kind = "copied-file";
          source = {
            kind = "artifact-file";
            reference = {
              artifact = lib.abilities.packageOutput {};
              path = "bin/${name}";
            };
          };
          maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
        };
        destination = "/run/wrappers/bin/${name}";
        owner = "root";
        group = "root";
        mode = "4755";
        prerequisites = [(lib.abilities.resultOf "aos:wrapper-bin" "resource")];
      };
    };
  contributions = builtins.map serviceManagement.splitContribution [
    (wrapper "ping")
    (wrapper "ping6")
  ];
in {
  config = lib.mkMerge [
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);}
    (lib.mkIf (enabled && config.aos.abilities.environment != null) {
      aos.abilities = lib.mkMerge (
        [{instances.runtime = {};}]
        ++ builtins.map (entry: entry.configured) contributions
      );
    })
  ];
}

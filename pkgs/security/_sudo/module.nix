##! Package-owned sudo runtime directory requirements.
{
  config,
  lib,
  ...
}: let
  enabled = lib.attrByPath ["aos" "security" "sudo" "enable"] false config;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  runtimeEntries = serviceManagement.forProducer {
    consumerInstance = "runtime";
    key = "runtime-entries";
    interface = serviceManagement.interfaces.runtimeEntryPopulation;
    methods = ["observe"];
    parameters.entries = [
      {
        kind = "directory";
        path = "/run/sudo";
        mode = "0755";
        owner = "root";
        group = "root";
      }
      {
        kind = "directory";
        path = "/var/db/sudo";
        mode = "0700";
        owner = "root";
        group = "root";
      }
      {
        kind = "directory";
        path = "/var/log/sudo-io";
        mode = "0700";
        owner = "root";
        group = "root";
      }
    ];
  };
  wrapper = name: path: {
    key = "wrapper-${name}";
    parameters = {
      inherit name;
      entry = {
        kind = "copied-file";
        source = {
          kind = "artifact-file";
          reference = {
            artifact = lib.abilities.packageOutput {};
            inherit path;
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
  wrappers = serviceManagement.forProducers {
    consumerInstance = "runtime";
    interface = serviceManagement.interfaces.filesystemEntry;
    methods = ["materialize" "observe" "release"];
    producers = [
      (wrapper "sudo" "bin/sudo")
      (wrapper "sudoedit" "bin/sudo")
    ];
  };
  contributions = builtins.map serviceManagement.splitContribution [runtimeEntries wrappers];
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

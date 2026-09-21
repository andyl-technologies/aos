##! Package-owned privileged ping wrapper requests.
{
  config,
  lib,
  ...
}: let
  configured =
    config.aos.abilities.environment
    != null
    && config.aos.profiles.development.enable;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  wrapper = name:
    serviceManagement.forProducer {
      consumerInstance = "runtime";
      key = "wrapper-${name}";
      interface = serviceManagement.interfaces.privilegedExecutable;
      methods = ["observe"];
      parameters = {
        inherit name;
        source = {
          artifact = lib.abilities.packageOutput {};
          path = "bin/${name}";
        };
        owner = "root";
        group = "root";
        mode = "4755";
        maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
      };
    };
  contributions = builtins.map serviceManagement.splitContribution [
    (wrapper "ping")
    (wrapper "ping6")
  ];
in {
  config = lib.mkMerge [
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);}
    (lib.mkIf configured {
      aos.abilities = lib.mkMerge (
        [{instances.runtime = {};}]
        ++ builtins.map (entry: entry.configured) contributions
      );
    })
  ];
}

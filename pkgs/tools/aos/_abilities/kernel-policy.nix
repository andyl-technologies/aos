##! Package-owned kernel module and tunable policy requests.
{
  config,
  lib,
  ...
}: let
  bbr = lib.attrByPath ["aos" "kernel" "bbr"] false config;
  configuredModules = lib.attrByPath ["aos" "kernel" "modules"] [] config;
  configuredTunables = lib.attrByPath ["aos" "kernel" "sysctl"] {} config;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "kernel-policy";
  moduleNames = lib.unique (lib.optional bbr "tcp_bbr" ++ configuredModules);
  tunableValues =
    configuredTunables
    // lib.optionalAttrs bbr {
      "net.core.default_qdisc" = "fq";
      "net.ipv4.tcp_congestion_control" = "bbr";
    };
  kernelModules = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "kernel-modules";
    interface = serviceManagement.interfaces.kernelModules;
    methods = ["load" "observe"];
    parameters = {
      modules = moduleNames;
      required = false;
    };
  };
  kernelTunables = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "kernel-tunables";
    interface = {
      alias = lib.abilities.interfaces.kernelTunables.interface.alias;
      declaration = lib.abilities.interfaces.kernelTunables.interface.declaration;
    };
    methods = ["apply" "observe" "remove"];
    parameters = {
      values = tunableValues;
      dependencies = lib.optional (moduleNames != []) (
        resultOf "kernel-modules" "resource"
      );
    };
  };
  contributions = builtins.map serviceManagement.splitContribution [
    kernelModules
    kernelTunables
  ];
  configured = config.aos.abilities.environment != null;
in {
  config = lib.mkMerge [
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);}
    (lib.mkIf configured {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ lib.optional (moduleNames != []) (serviceManagement.splitContribution kernelModules).configured
        ++ lib.optional (tunableValues != {}) (serviceManagement.splitContribution kernelTunables).configured
      );
    })
  ];
}

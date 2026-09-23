##! System-owned kernel module and tunable policy requests.
{
  config,
  lib,
  ...
}: let
  inherit (config.aos.kernel) bbr;
  configuredModules = config.aos.kernel.modules;
  configuredTunables = config.aos.kernel.sysctl;
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
  definitions = builtins.map serviceManagement.splitDefinition [
    kernelModules
    kernelTunables
  ];
  configured =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
in {
  config = lib.mkMerge [
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) definitions);}
    (lib.mkIf configured {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ lib.optional (moduleNames != []) (serviceManagement.splitDefinition kernelModules).configured
        ++ lib.optional (tunableValues != {}) (serviceManagement.splitDefinition kernelTunables).configured
      );
    })
  ];
}

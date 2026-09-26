##! System-owned kernel and crash-dump hardening requirements.
{
  config,
  lib,
  ...
}: let
  hardening = config.aos.security.hardening;
  inherit (hardening) enable;
  configuredTunables = hardening.sysctl;
  coreDumpsEnabled = hardening.coreDump.enable;
  consumerInstance = "security-hardening";
  crashDumpPolicy = lib.abilities.interfaces.crashDumpPolicy.interface;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  kernelTunables = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "security-tunables";
    interface = {
      alias = lib.abilities.interfaces.kernelTunables.interface.alias;
      declaration = lib.abilities.interfaces.kernelTunables.interface.declaration;
    };
    methods = ["apply" "observe" "remove"];
    parameters = {
      values = configuredTunables;
      dependencies = [];
    };
  };
  crashDump = {
    requirementTemplates.crash-dump-policy = {
      description = "Requires the selected crash-dump policy implementation.";
      interface = crashDumpPolicy.identity.name;
      inherit (crashDumpPolicy.identity) abi descriptor;
    };
    requests.crash-dump-policy = {
      requirement = "crash-dump-policy";
      consumer = consumerInstance;
      scope = ["crash-dumps"];
      parameters.enabled = coreDumpsEnabled;
    };
  };
  configured =
    enable
    && config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
in {
  config = serviceManagement.producerModule {
    inherit config lib;
    producers = [kernelTunables crashDump];
    enabled = configured;
  };
}

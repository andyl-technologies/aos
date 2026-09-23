##! Package-owned runtime directory requirements for AOS and APM.
{
  config,
  lib,
  ...
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  runtimeEntry = consumerInstance: key: entries:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = serviceManagement.interfaces.runtimeEntryPopulation;
      methods = ["observe"];
      parameters = {inherit entries;};
    };
  abilityRuntime = runtimeEntry "ability-runtime" "ability-runtime-entries" [
    {
      kind = "directory";
      path = "/var/lib/aos/ability-runtime";
      mode = "0711";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/var/lib/aos/ability-runtime/credential-sources";
      mode = "0700";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/var/lib/aos/ability-runtime/credentials";
      mode = "0700";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/var/lib/aos/ability-runtime/endpoints";
      mode = "0700";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/var/lib/aos/ability-runtime/network-policy";
      mode = "0700";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/var/lib/aos/ability-runtime/storage";
      mode = "0711";
      owner = "root";
      group = "root";
    }
  ];
  apmRuntime = runtimeEntry "apm-runtime" "apm-runtime-entries" [
    {
      kind = "directory";
      path = "/etc/aos/packages.d";
      mode = "0755";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/run/apm";
      mode = "0700";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/run/aos-attest";
      mode = "0700";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/var/lib/apm";
      mode = "0755";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/var/lib/apm/config";
      mode = "0755";
      owner = "root";
      group = "root";
    }
    {
      kind = "directory";
      path = "/var/lib/apm/config/registries.d";
      mode = "0755";
      owner = "root";
      group = "root";
    }
  ];
  producers = [
    abilityRuntime
    apmRuntime
  ];
in {
  config = serviceManagement.producerModule {
    inherit config lib producers;
    enabled =
      config.aos.abilities.environment
      != null
      && config.aos.abilities.environment.stage == "host";
  };
}

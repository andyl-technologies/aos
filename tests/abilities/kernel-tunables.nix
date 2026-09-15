##! Checks the provider-owned kernel-tunable implementation through the fixed point.
{lib}: let
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "kernel-tunables";
            stage = "host";
          };
          bindings."test:kernel-tunables" = {
            request = "consumer:network-forwarding";
            implementation = "aos-kernel-tunable-provider:kernel-tunables";
            providerInstance = "aos-kernel-tunable-provider:manager";
            slot = "network-forwarding";
          };
        };
      }
    ];
    packageModules = [
      {
        name = "aos-kernel-tunable-provider";
        module.imports = [
          ../../pkgs/tools/_aos-kernel-tunable-provider-module.nix
          ../../pkgs/tools/_kernel-tunable-provider.nix
          {config.aos.abilities.instances.manager = {};}
        ];
      }
      {
        name = "consumer";
        module.imports = [
          {
            config.aos.abilities = lib.abilities.interfaces.serviceManagement.forProducer {
              consumerInstance = "workload";
              key = "network-forwarding";
              interface = {
                alias = "kernel-tunables";
                declaration = lib.abilities.interfaces.kernelTunables.interface.declaration;
              };
              methods = ["apply" "observe" "remove"];
              parameters = {
                values = {
                  "net.bridge.bridge-nf-call-iptables" = "1";
                  "net.ipv4.ip_forward" = "1";
                };
                dependencies = [];
              };
            };
          }
          {config.aos.abilities.instances.workload = {};}
        ];
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  output = abilities.compositionOutputs."consumer:network-forwarding".readiness-resource;
in
  assert abilities.interfaces ? "kernel-tunables";
  assert builtins.attrNames abilities.implementations == ["aos-kernel-tunable-provider:kernel-tunables"];
  assert desired.kind == "aos.kernel.tunables";
  assert desired.lifetime == "instance";
  assert desired.value.values
  == {
    "net.bridge.bridge-nf-call-iptables" = "1";
    "net.ipv4.ip_forward" = "1";
  };
  assert desired.value.dependencies == [];
  assert desired.realization == {schema = "aos.kernel.tunables-realization/v1";};
  assert output.value.resource == desired.resource;
  assert output.value.operations == ["observe"];
  assert output.phase == "planning";
  assert output.lifetime == "instance"; true

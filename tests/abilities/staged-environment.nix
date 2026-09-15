##! Checks that initrd contributions use a distinct ordinary ability fixed point.
{
  lib,
  mkSystem,
  pkgs,
}: let
  system = mkSystem {
    systemName = "staged-environment-test";
    modules = [
      {
        aos.abilities.stages.initrd = {
          packages = [pkgs.aos-boot-preparation-provider];
          modules = [
            ({config, ...}: {
              config.aos.abilities = lib.mkMerge [
                {instances."system:preparation-consumer" = {};}
                (lib.abilities.interfaces.serviceManagement.forProducer {
                  consumerInstance = "system:preparation-consumer";
                  key = "fixture-preparation";
                  interface = lib.abilities.interfaces.bootPreparation.interfaces.preparation;
                  methods = ["observe" "prepare"];
                  parameters = {
                    execution = {
                      artifact = lib.abilities.packageOutput {};
                      entry_point = "libexec/fixture-preparation";
                      arguments = [];
                    };
                    prerequisites = [];
                  };
                })
              ];
            })
          ];
        };
      }
    ];
  };
  initrd = system.config.system.build.initrdAbilityGraph;
  host = system.config.aos.abilities;
in
  assert initrd.environment == {
    authority = "system-image";
    key = "staged-environment-test";
    stage = "initrd";
  };
  assert initrd.requests ? "system:fixture-preparation";
  assert initrd.requests."system:fixture-preparation".parameters.execution.entry_point
  == "libexec/fixture-preparation";
  assert builtins.length (builtins.attrNames initrd.bindings) > 0;
  assert initrd.compositionPendingRequests == {};
  assert builtins.length (builtins.attrNames initrd.desiredResources) > 0;
  assert !(host.requests ? "system:fixture-preparation");
  assert !(builtins.any (name: lib.hasPrefix "chrony:" name) (builtins.attrNames initrd.requests));
  assert !(builtins.any (name: lib.hasPrefix "openssh:" name) (builtins.attrNames initrd.requests));
  true

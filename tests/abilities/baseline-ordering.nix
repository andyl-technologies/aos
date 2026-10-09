##! Keeps host baseline prerequisites outside portable handler arguments.
{
  lib,
  pkgs,
}: let
  evaluated = lib.evalPackageModules {
    scope = ["test" "host-ordering"];
    packages = [
      pkgs.aos-configuration-lower
      pkgs.systemd
      pkgs.aos-init-provider
      pkgs.aos-ebpf-lsm-policy
    ];
    operatorModules = [
      ../../pkgs/system/_aos-host-policy/baseline/common.nix
      {
        aos.abilities.configuration.operations.file.effects.probe.input = {
          path = "/etc/probe";
          content = "probe\n";
        };
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  effect = abilities.configuration.operations.file.effects.probe;
  generation = abilities.configurationLower.operations.install.effects.image;
  identity = value: builtins.hashString "sha256" (builtins.toJSON value.contract.identity);
  graph = evaluated.deployment.graph;
in {
  portableInput = assert !(effect.input ? configurationGeneration); true;
  declaredOrdering = assert builtins.elem generation.outputs.image effect.after; true;
  graphOrdering = assert builtins.elem (identity generation) graph.nodes.${identity effect}.dependencies; true;
}

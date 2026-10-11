##! Checks concrete domain fixture inputs and controlled removal through native modules.
{lib, ...}: let
  root = ../..;
  payload = import (root + /tests/effects/_fixture-payload.nix) "native-domain";
  package = {
    _type = "aos-package-artifact";
    name = "native-domain";
    path = payload;
    outputs.out = payload;
    outPath = payload;
    meta.mainProgram = "native-domain";
  };
  evaluate = options:
    lib.evalModules {
      inherit lib;
      specialArgs = {inherit package;};
      modules = [
        (root + /lib/effects/module.nix)
        (root + /pkgs/filesystem/_aos-filesystem-provider/module.nix)
        (root + /pkgs/system/_service-management/configuration.nix)
        (root + /pkgs/networking/_nftables/module.nix)
        (root + /tests/fleet/_native-reference-filesystem-configuration.nix)
        {
          aos.abilities.configuration.operations.file.handler.program = package;
          aos.abilities.networkPolicy.operations.ruleset.handler.program = package;
        }
        options
      ];
    };
  baseline = evaluate {};
  nodes = baseline.config.aos.activation.graph.nodes;
  directory = builtins.head (builtins.filter (node: builtins.elem "directory" node.identity) (builtins.attrValues nodes));
  removed = evaluate {aos.nativeDomainQualification.enabled.directory = false;};
  disabled = evaluate {aos.networkPolicy.enable = false;};
in
  assert builtins.length (builtins.attrNames nodes) == 6;
  assert directory.input.mode == "0750";
  assert directory.input.path == "/var/lib/aos/native-domain-qualification-directory";
  assert builtins.length (builtins.attrNames removed.config.aos.activation.graph.nodes) == 5;
  assert builtins.length (builtins.attrNames disabled.config.aos.activation.graph.nodes) == 5;
  assert builtins.all (node: node.handler.executable == "${payload}/bin/native-domain") (builtins.attrValues nodes); true

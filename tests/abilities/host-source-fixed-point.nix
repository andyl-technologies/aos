##! Forces the complete server host ability graph through source-stage projection.
{
  lib,
  pkgs,
  system,
}: let
  graph = lib.abilities.sourceStageFixedPoint system.config.aos.abilities;
  canonicalJson = builtins.toJSON graph;
in
  assert !(builtins.hasAttr "image-builder:systemd" graph.bindings);
  assert !(builtins.hasAttr "aos:image-builder" graph.compositionRequests);
  assert !(builtins.hasAttr "aos:image-builder" graph.compositionOutputs);
  assert !(builtins.hasAttr "systemd:image-builder-provider" graph.instances);
  assert builtins.all (binding:
    graph.instances.${binding.providerInstance}.package == binding.implementation.package)
  (builtins.attrValues graph.bindings);
    pkgs.writeTextFile {
      name = "aos-host-source-fixed-point-eval-check";
      destination = "/result";
      # The serialized graph is forced during evaluation. Only its bounded
      # summary enters this check derivation, avoiding a second image closure.
      text = ''
        requests=${toString (builtins.length (builtins.attrNames graph.requests))}
        bytes=${toString (builtins.stringLength canonicalJson)}
      '';
    }

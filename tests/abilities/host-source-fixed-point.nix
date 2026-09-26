##! Forces the complete server host ability graph through source-stage projection.
{
  lib,
  pkgs,
  system,
}: let
  graph = lib.abilities.sourceStageFixedPoint system.config.aos.abilities;
  canonicalJson = builtins.toJSON graph;
in
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

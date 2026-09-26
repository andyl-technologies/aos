##! Forces the complete server host ability graph through source-stage projection.
{
  lib,
  pkgs,
  system,
}: let
  graph = lib.abilities.sourceStageFixedPoint system.config.aos.abilities;
  canonicalJson = builtins.toJSON graph;
  hasRequestOutput = expression:
    if builtins.isAttrs expression
    then
      (expression.source or null)
      == "request-output"
      || builtins.any hasRequestOutput (builtins.attrValues expression)
    else if builtins.isList expression
    then builtins.any hasRequestOutput expression
    else false;
  projectedRequests = builtins.attrValues graph.requests ++ builtins.attrValues graph.compositionRequests;
  systemBusResources =
    builtins.filter (resource: resource.resource.key == "system-bus")
    (builtins.attrValues graph.resolvedResources);
in
  assert !(builtins.hasAttr "image-builder:systemd" graph.bindings);
  assert !(builtins.hasAttr "aos:image-builder" graph.compositionRequests);
  assert !(builtins.hasAttr "aos:image-builder" graph.compositionOutputs);
  assert !(builtins.hasAttr "systemd:image-builder-provider" graph.instances);
  assert builtins.all (binding:
    graph.instances.${binding.providerInstance}.package == binding.implementation.package)
  (builtins.attrValues graph.bindings);
  assert builtins.all (request: request.parameters ? source) projectedRequests;
  assert builtins.all (resource: resource.realization ? source) (builtins.attrValues graph.resolvedResources);
  assert builtins.any (request: hasRequestOutput request.parameters) projectedRequests;
  assert builtins.length systemBusResources == 1;
  assert (builtins.head systemBusResources).kind == "aos.configuration.materialization";
  assert graph.requests."systemd:dbus-system-registration".lifetime == "instance";
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

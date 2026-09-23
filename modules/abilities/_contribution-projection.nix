##! Projects producer declarations and configured requests in one module value.
{splitContribution}: {
  config,
  lib,
  fragments,
  enabled,
}: let
  contributions = builtins.map splitContribution fragments;
  consumers = lib.unique (builtins.concatMap
    (contribution:
      builtins.map
      (request: request.consumer)
      (builtins.attrValues (contribution.configured.requests or {})))
    contributions);
  instances = builtins.listToAttrs (builtins.map
    (name: {
      inherit name;
      value = {};
    })
    consumers);
in
  lib.mkMerge [
    (lib.mkMerge (builtins.map
      (contribution: {aos.abilities = contribution.declarations;})
      contributions))
    (lib.mkIf (enabled && config.aos.abilities.environment != null) {
      aos.abilities = lib.mkMerge (
        [{inherit instances;}]
        ++ builtins.map
        (contribution: contribution.configured)
        contributions
      );
    })
  ]

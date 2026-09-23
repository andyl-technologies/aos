##! Projects producer declarations and configured requests in one module value.
{splitDefinition}: {
  config,
  lib,
  producers,
  enabled,
}: let
  definitions = builtins.map splitDefinition producers;
  consumers = lib.unique (builtins.concatMap
    (definition:
      builtins.map
      (request: request.consumer)
      (builtins.attrValues (definition.configured.requests or {})))
    definitions);
  instances = builtins.listToAttrs (builtins.map
    (name: {
      inherit name;
      value = {};
    })
    consumers);
in
  lib.mkMerge [
    (lib.mkMerge (builtins.map
      (definition: {aos.abilities = definition.declarations;})
      definitions))
    (lib.mkIf (enabled && config.aos.abilities.environment != null) {
      aos.abilities = lib.mkMerge (
        [{inherit instances;}]
        ++ builtins.map
        (definition: definition.configured)
        definitions
      );
    })
  ]

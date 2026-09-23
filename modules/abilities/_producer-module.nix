##! Projects producer declarations and configured requests in one module value.
{splitDefinition}: {
  config,
  lib,
  producers,
  activeProducers ? null,
  enabled,
}: let
  # Keep declarations fixed while selecting requests from final service state.
  definitions = builtins.map splitDefinition producers;
  activeKeys =
    if activeProducers == null
    then null
    else
      builtins.concatMap
      (producer: builtins.attrNames ((splitDefinition producer).configured.requests or {}))
      activeProducers;
  configuredDefinitions =
    builtins.map
    (definition:
      if activeKeys == null
      then definition.configured
      else
        definition.configured
        // {
          requests = lib.filterAttrs (name: _: builtins.elem name activeKeys) (definition.configured.requests or {});
        })
    definitions;
  consumers = lib.unique (builtins.concatMap
    (definition:
      builtins.map
      (request: request.consumer)
      (builtins.attrValues (definition.requests or {})))
    configuredDefinitions);
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
      aos.abilities = lib.mkMerge ([{inherit instances;}] ++ configuredDefinitions);
    })
  ]

##! Provider-neutral storage readiness projected from selected abilities.
{
  config,
  lib,
  ...
}: let
  readinessList = lib.abilities.types.list {
    element = lib.abilities.types.deferredResult lib.abilities.types.resourceReference;
    maxItems = 4096;
    unique = true;
  };
  canonicalReadiness = builtins.sort (
    left: right: builtins.toJSON left < builtins.toJSON right
  ) (lib.unique (lib.concatLists (builtins.attrValues config.aos.storage.readinessContributions)));
in {
  options.aos.storage = {
    readinessContributions = lib.mkOption {
      type = lib.types.attrsOf readinessList;
      default = {};
      internal = true;
      contributable = true;
      description = ''
        Readiness resources keyed by the selected storage provider that owns
        them. Provider keys preserve authorship while the derived projection
        below supplies consumers with one canonical list.
      '';
    };

    readinessResources = lib.mkOption {
      type = lib.abilities.types.list {
        element = lib.abilities.types.deferredResult lib.abilities.types.resourceReference;
        maxItems = 4096;
        unique = true;
        canonicalOrder = true;
      };
      readOnly = true;
      internal = true;
      description = ''
        Canonical readiness resources derived from the selected storage
        providers. Consumers use these references for ordering without
        depending on a concrete storage backend's option tree.
      '';
    };
  };

  config.aos.storage.readinessResources = canonicalReadiness;
}

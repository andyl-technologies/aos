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
  canonicalMountPoints = builtins.sort builtins.lessThan (
    lib.unique (lib.concatLists (builtins.attrValues config.aos.storage.mountPointContributions))
  );
  policyContributions = builtins.attrValues config.aos.storage.policyContributions;
in {
  options.aos.storage = {
    mountPointContributions = lib.mkOption {
      type = lib.types.attrsOf (lib.abilities.types.list {
        element = lib.abilities.types.executionPath;
        maxItems = 4096;
        unique = true;
        canonicalOrder = true;
      });
      default = {};
      internal = true;
      contributable = true;
      description = "Package-owned mount points materialized by selected storage providers.";
    };

    managedMountPoints = lib.mkOption {
      type = lib.abilities.types.list {
        element = lib.abilities.types.executionPath;
        maxItems = 4096;
        unique = true;
        canonicalOrder = true;
      };
      readOnly = true;
      internal = true;
      description = "Canonical mount points materialized by selected storage providers.";
    };

    policyContributions = lib.mkOption {
      type = lib.types.attrsOf (lib.abilities.types.record {
        fields = {
          compressedSwapRecommended = lib.abilities.types.boolean;
          hardwareMonitoringRecommended = lib.abilities.types.boolean;
        };
      });
      default = {};
      internal = true;
      contributable = true;
      description = "Package-owned host policy recommendations from selected storage providers.";
    };

    compressedSwapRecommended = lib.mkOption {
      type = lib.abilities.types.boolean;
      readOnly = true;
      internal = true;
      description = "Whether a selected storage provider recommends compressed swap.";
    };

    hardwareMonitoringRecommended = lib.mkOption {
      type = lib.abilities.types.boolean;
      readOnly = true;
      internal = true;
      description = "Whether a selected storage provider recommends hardware monitoring.";
    };

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

  config.aos.storage = {
    compressedSwapRecommended = builtins.any (policy: policy.compressedSwapRecommended) policyContributions;
    hardwareMonitoringRecommended = builtins.any (policy: policy.hardwareMonitoringRecommended) policyContributions;
    managedMountPoints = canonicalMountPoints;
    readinessResources = canonicalReadiness;
  };
}

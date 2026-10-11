##! Storage readiness and policy derived from package-owned native operations.
{
  config,
  lib,
  ...
}: let
  references = lib.types.listOf (lib.types.deferred lib.types.str);
  paths = lib.types.listOf lib.types.str;
  readiness = lib.unique (lib.concatLists (builtins.attrValues config.aos.storage.readinessByProvider));
  mountPoints = builtins.sort builtins.lessThan (lib.unique (lib.concatLists (builtins.attrValues config.aos.storage.mountPointsByProvider)));
  policies = builtins.attrValues config.aos.storage.policyByProvider;
in {
  options.aos.storage = {
    mountPointsByProvider = lib.mkOption {
      type = lib.types.attrsOf paths;
      default = {};
      internal = true;
      extensible = true;
      description = "Package-owned mount points realized by selected storage handlers.";
    };
    managedMountPoints = lib.mkOption {
      type = paths;
      readOnly = true;
      internal = true;
      description = "Canonical mount points realized by selected storage handlers.";
    };
    policyByProvider = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options.compressedSwapRecommended = lib.mkOption {
          type = lib.types.bool;
          description = "Recommend compressed swap for this storage backend.";
        };
        options.hardwareMonitoringRecommended = lib.mkOption {
          type = lib.types.bool;
          description = "Recommend hardware monitoring for this storage backend.";
        };
      });
      default = {};
      internal = true;
      extensible = true;
      description = "Host policy recommendations owned by selected storage packages.";
    };
    compressedSwapRecommended = lib.mkOption {
      type = lib.types.bool;
      readOnly = true;
      internal = true;
      description = "Whether a selected storage backend recommends compressed swap.";
    };
    hardwareMonitoringRecommended = lib.mkOption {
      type = lib.types.bool;
      readOnly = true;
      internal = true;
      description = "Whether a selected storage backend recommends hardware monitoring.";
    };
    readinessByProvider = lib.mkOption {
      type = lib.types.attrsOf references;
      default = {};
      internal = true;
      extensible = true;
      description = "Typed operation results establishing storage readiness, keyed by their owning package.";
    };
    readinessResources = lib.mkOption {
      type = references;
      readOnly = true;
      internal = true;
      description = "Storage readiness results consumed by dependent host operations.";
    };
  };
  config.aos.storage = {
    compressedSwapRecommended = builtins.any (policy: policy.compressedSwapRecommended) policies;
    hardwareMonitoringRecommended = builtins.any (policy: policy.hardwareMonitoringRecommended) policies;
    managedMountPoints = mountPoints;
    readinessResources = readiness;
  };
}

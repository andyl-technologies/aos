##! Authors physical prerequisite and successor markers around each controlled operation.
{config, lib, ...}: let
  cfg = config.aos.nativeServiceQualification;
  markers = config.aos.abilities.nativeDependencyBarrier.operations.ensure.effects;
  operations = {
    service = {ability = "serviceManagement"; name = "realize";};
    group = {ability = "identity"; name = "group";};
    principal = {ability = "identity"; name = "principal";};
    membership = {ability = "identity"; name = "membership";};
  };
  requestsFor = name: operation:
    { "${name}-parent" = {name = "${name}-parent";}; }
    // lib.optionalAttrs cfg.enabled.${name} {
      "${name}-child" = {
        name = "${name}-child";
        parent = config.aos.abilities.${operation.ability}.operations.${operation.name}.effects.native-service-qualification.outputs.resource;
      };
    };
in {
  aos.nativeServiceQualification.dependencyParents = lib.mapAttrs
    (name: _: markers."${name}-parent".outputs.resource) operations;
  aos.nativeDependencyBarrier.requests = lib.mkMerge (
    [{foreign-marker = {name = "foreign-marker";};}]
    ++ builtins.attrValues (lib.mapAttrs requestsFor operations)
  );
}

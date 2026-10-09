##! Prepares immutable early manager topology before container PID 1 starts.
{
  config,
  lib,
  package,
  ...
}: let
  operations = config.aos.abilities.serviceManagement.operations;
  prepared = config.aos.abilities.systemdBootstrap.operations.prepare;
  services = import ./bootstrap-services.nix {
    inherit config lib;
    pkgs = {};
  };
  groups = import ./bootstrap-resource-groups.nix {inherit config lib;};
  enabled = config.aos.initSystem.container;
  identity = effect: builtins.hashString "sha256" (builtins.toJSON effect.contract.identity);
  program = package.handlers // {meta = (package.handlers.meta or {}) // {mainProgram = "aos-systemd-bootstrap";};};
in {
  aos.abilities.systemdBootstrap.operations.prepare = {
    input.options = {
      services = lib.mkOption {
        type = lib.types.attrsOf (lib.types.submodule operations.realize.input);
        description = "Canonical merged early service inputs, shared with ordinary realization.";
      };
      groups = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule operations.resourceGroup.input);
        description = "Canonical early group inputs, shared with ordinary realization.";
      };
      serviceRecipients = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        description = "Logical native service owners that may adopt prepared definitions.";
      };
      groupRecipients = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        description = "Logical native group owners that may adopt prepared definitions.";
      };
    };
    result.options = {
      resource = lib.mkOption {
        type = lib.types.str;
        description = "Owned early manager topology.";
      };
      storePath = lib.mkOption {
        type = lib.types.str;
        description = "Immutable canonical rendered unit tree.";
      };
      digest = lib.mkOption {
        type = lib.types.str;
        description = "NAR identity of the prepared unit tree.";
      };
    };
    handler = {
      inherit program;
      phase = "installation";
    };
    effects.container = lib.mkIf enabled {
      input = {
        # Projection is the producer: its nested renderer inputs must not
        # acquire the dependency that ordinary live consumers inherit below.
        services = lib.mapAttrs (_: service: service // {bootstrapResource = null;}) services;
        groups = builtins.map (group: group.input // {bootstrapResource = null;}) (builtins.attrValues groups);
        serviceRecipients = lib.mapAttrs (name: _: identity operations.realize.effects.${name}) services;
        groupRecipients = builtins.listToAttrs (lib.mapAttrsToList (name: group: {
            name = group.input.name;
            value = identity operations.resourceGroup.effects.${name};
          })
          groups);
      };
    };
  };
  aos.abilities.serviceManagement.operations = {
    realize.input.options.bootstrapResource = lib.mkOption {
      type = lib.types.nullOr (lib.types.deferred lib.types.str);
      default =
        if enabled
        then prepared.effects.container.outputs.resource
        else null;
      internal = true;
      description = "Installation preparation required before live systemd realization.";
    };
    resourceGroup.input.options.bootstrapResource = lib.mkOption {
      type = lib.types.nullOr (lib.types.deferred lib.types.str);
      default =
        if enabled
        then prepared.effects.container.outputs.resource
        else null;
      internal = true;
      description = "Installation preparation required before live systemd group realization.";
    };
  };
}

##! Projects merged early services without changing their native lifecycle owner.
{
  config,
  lib,
  pkgs,
}: let
  services = lib.filterAttrs (_: service: service.enable && (service.bootstrap || (service.retain_image_definition or false) || service.activationOwner != "ability")) config.aos.services;
  groups = import ./bootstrap-resource-groups.nix {inherit config lib;};
  resourceReference = import ./bootstrap-resource-reference.nix {inherit config lib;};
  projectValue = value:
    if lib.types.effectOutput.check value
    then resourceReference value
    else if builtins.isAttrs value
    then lib.mapAttrs (_: projectValue) value
    else if builtins.isList value
    then builtins.map projectValue value
    else value;
  project = name: _: let
    input = config.aos.abilities.serviceManagement.operations.realize.effects.${name}.input;
    group = (input.resources or {}).resource_group or null;
    relationships = ["after" "before" "requires" "wants" "requisite" "conflicts" "binds_to" "part_of" "upholds"];
    dependencies =
      if input.dependencies == null
      then null
      else
        lib.mapAttrs (field: values:
          if builtins.elem field relationships
          then builtins.map resourceReference values
          else values)
        input.dependencies;
    # Readiness and allocation prerequisites stay deferred in the activation
    # graph. Only fields that contribute immutable unit bytes need addresses.
    projected =
      (lib.mapAttrs (field: value:
        if builtins.elem field ["lifecycle" "configuration" "directories" "identity" "instantiation" "activation"]
        then projectValue value
        else value)
      input)
      // {inherit dependencies;};
  in
    if !builtins.isAttrs group
    then projected
    else projected // {resources = input.resources // {resource_group = groups.${lib.last group.identity}.input.name;};};
in
  lib.mapAttrs project services

##! Projects merged early services without changing their native lifecycle owner.
{
  config,
  lib,
  pkgs,
}: let
  services = lib.filterAttrs (_: service: service.enable && (service.bootstrap || service.activationOwner != "ability")) config.aos.services;
  groups = import ./bootstrap-resource-groups.nix {inherit config lib;};
  project = name: _: let
    input = config.aos.abilities.serviceManagement.operations.realize.effects.${name}.input;
    group = (input.resources or {}).resource_group or null;
  in
    if !builtins.isAttrs group
    then input
    else input // {resources = input.resources // {resource_group = groups.${lib.last group.identity}.input.name;};};
in
  lib.mapAttrs project services

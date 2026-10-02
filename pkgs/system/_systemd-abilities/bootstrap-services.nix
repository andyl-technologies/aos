##! Projects merged early services without changing their native lifecycle owner.
{
  config,
  lib,
  pkgs,
}: let
  services = lib.filterAttrs (_: service: service.enable && (service.bootstrap || service.activationOwner != "ability")) config.aos.services;
in
  lib.mapAttrs (name: _: config.aos.abilities.serviceManagement.operations.realize.effects.${name}.input) services

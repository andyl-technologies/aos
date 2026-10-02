##! Projects merged early services without changing their native lifecycle owner.
{
  config,
  lib,
  pkgs,
}: let
  services = config.aos.services;
in
  lib.filterAttrs (_: service: service.enable && (service.bootstrap || service.activationOwner != "ability")) services

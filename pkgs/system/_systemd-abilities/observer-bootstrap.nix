##! Renders the same native manager-owned definitions adopted after bootstrap.
{
  config,
  lib,
  pkgs,
}: let
  services = config.aos.services;
in
  lib.filterAttrs (_: service: service.enable && service.activationOwner != "ability") services

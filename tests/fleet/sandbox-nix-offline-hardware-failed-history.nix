# Exports actual failed-job DATA without granting generic-root journal access.
{
  lib,
  pkgs,
  systems,
  ...
}:
import ./sandbox-nix-offline-hardware-provisioning.nix {
  inherit lib pkgs systems;
  rejectHierarchyAuthorization = true;
}

{
  pkgs,
  lib,
  src ? import ../../pkgs/tools/crucible/_source.nix {inherit lib;},
}:
# Test recipes share the exact pinned vendor used by the packaged controller.
pkgs.crucible-controller.passthru.cargoDeps

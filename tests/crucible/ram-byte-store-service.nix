# Reuses the unchanged byte-service guest, seeds, caps, and deadlines for STORE.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-byte-service.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  store = true;
}

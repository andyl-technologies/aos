{
  pkgs,
  lib,
  image,
}:
import ./local-collection-reconciliation.nix {
  inherit pkgs lib image;
  suite = "preownership-restore";
}

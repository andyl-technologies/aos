# Shares compilation while exact routing cases run in a fresh AOS guest.
{
  pkgs,
  lib,
  image,
}:
import ./local-collection-reconciliation.nix {
  inherit pkgs lib image;
  suite = "scoped-indexed-presence";
}

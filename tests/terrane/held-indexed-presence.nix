# Shares compilation while genuine held-index cases run in a fresh AOS guest.
{
  pkgs,
  lib,
  image,
}:
import ./local-collection-reconciliation.nix {
  inherit pkgs lib image;
  suite = "held-indexed-presence";
}

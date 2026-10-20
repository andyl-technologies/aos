# A bounded real nginx/curl exchange through the public packaged runtime.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  twoNodeHttp = true;
}

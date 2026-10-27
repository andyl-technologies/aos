# Two real guests exchange an authenticated HTTP response through World routing.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  twoNodeHttp = true;
  twoNodeHttpServer = "envoy-direct";
}

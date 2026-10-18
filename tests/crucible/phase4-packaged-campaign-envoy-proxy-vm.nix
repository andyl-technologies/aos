# Three real guests retain a World-routed Envoy proxy and nginx upstream.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  twoNodeHttp = true;
  twoNodeHttpServer = "envoy-proxy";
}

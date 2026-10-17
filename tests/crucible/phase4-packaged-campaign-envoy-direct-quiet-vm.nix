# Separate quiet-kernel flight; the original verbose Envoy flight is retained.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  twoNodeHttp = true;
  twoNodeHttpServer = "envoy-direct";
  quietKernelBoot = true;
}

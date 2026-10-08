# Five routed guest VMs run inside one quota-enforced packaged campaign host.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  envoyNetwork = true;
}

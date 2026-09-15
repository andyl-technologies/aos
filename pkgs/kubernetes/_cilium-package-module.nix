##! Complete package module for Cilium configuration and abilities.
{lib, ...}: {
  imports = [
    ./_cilium-config/module.nix
    ((import ./_ability-contracts.nix {inherit lib;}).contributorPackage)
  ];
}

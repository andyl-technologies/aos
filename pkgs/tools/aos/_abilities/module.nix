##! Composes the package-owned AOS ability modules.
{
  imports = [
    ./configuration-provider/module.nix
    ./release-coordinator/module.nix
  ];
}

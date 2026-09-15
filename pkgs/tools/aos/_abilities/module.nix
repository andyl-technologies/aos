##! Composes the package-owned AOS ability modules.
{
  imports = [
    ../_configuration-provider/module.nix
    ../_release-coordinator/module.nix
  ];
}

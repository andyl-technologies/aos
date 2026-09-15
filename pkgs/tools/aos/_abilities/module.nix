##! Composes the package-owned AOS ability modules.
{
  imports = [
    ./attestation-verifier.nix
    ./configuration-provider/module.nix
    ./release-coordinator/module.nix
  ];
}

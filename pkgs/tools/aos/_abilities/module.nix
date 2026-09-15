##! Composes the package-owned AOS ability modules.
{
  imports = [
    ./attestation-verifier.nix
    ./configuration-provider/module.nix
    ./ebpf-lsm-policy-loader.nix
    ./release-coordinator/module.nix
  ];
}

##! Composes the package-owned AOS ability modules.
{
  imports = [
    ./attestation-verifier.nix
    ./configuration-provider/module.nix
    ./credential-recovery.nix
    ./ebpf-lsm-policy-loader.nix
    ./package-attestation-quote.nix
    ./package-profile-convergence.nix
    ./release-coordinator/module.nix
  ];
}

##! Composes the package-owned AOS ability modules.
{
  imports = [
    ./attestation-verifier.nix
    ./configuration-evaluation.nix
    ./configuration-provider/module.nix
    ./control-plane/module.nix
    ./ebpf-lsm-policy-loader.nix
    ./package-attestation-quote.nix
    ./package-profile-convergence.nix
    ./provisioning-metadata.nix
    ./provisioning-metadata-services.nix
    ./registry-snapshot.nix
    ./release-coordinator/module.nix
  ];
}

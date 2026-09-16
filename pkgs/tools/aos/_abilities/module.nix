##! Composes the package-owned AOS ability modules.
{
  imports = [
    ./attestation-verifier.nix
    ./configuration-evaluation.nix
    ./configuration-provider/module.nix
    ./credential-recovery.nix
    ./control-plane/module.nix
    ./ebpf-lsm-policy-loader.nix
    ./package-attestation-quote.nix
    ./provisioning-metadata.nix
    ./registry-snapshot.nix
    ./release-coordinator/module.nix
  ];
}

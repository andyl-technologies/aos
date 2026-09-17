##! Composes the package-owned AOS ability modules.
{
  imports = [
    ./artifact-backend.nix
    ./attestation-verifier.nix
    ./configuration-evaluation.nix
    ./configuration-provider/module.nix
    ./control-plane/module.nix
    ./event-log-policy.nix
    ./hardening-policy.nix
    ./hardware-monitoring.nix
    ./image-builder.nix
    ./kernel-policy.nix
    ./nix-store-database.nix
    ./networking-policy.nix
    ./package-attestation-quote.nix
    ./package-profile-convergence.nix
    ./platform-selection.nix
    ./provisioning-configuration-evaluator.nix
    ./registry-snapshot.nix
    ./release-coordinator/module.nix
    ./runtime-layout.nix
  ];
}

##! Composes the package-owned AOS ability modules.
{
  imports = [
    ./artifact-backend.nix
    ./attestation-verifier.nix
    ./configuration-evaluation.nix
    ./configuration-provider/module.nix
    ./control-plane/module.nix
    ./image-builder.nix
    ./nix-store-database.nix
    ./package-attestation-quote.nix
    ./package-profile-convergence.nix
    ./platform-selection.nix
    ./privileged-executable.nix
    ./provisioning-configuration-evaluator.nix
    ./registry-snapshot.nix
    ./release-coordinator/module.nix
    ./runtime-layout.nix
  ];
}

##! Composes the package-owned AOS ability modules.
{lib, ...}: {
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
    ./privileged-executable.nix
    ./provisioning-configuration-evaluator.nix
    ./registry-snapshot.nix
    ./release-coordinator/module.nix
    ./runtime-layout.nix
  ];

  options.aos.packageRuntime.artifacts.apm = lib.mkOption {
    type = lib.abilities.types.packageOutputSelector;
    readOnly = true;
    internal = true;
    description = "The package-owned apm executable artifact.";
  };

  config.aos.packageRuntime.artifacts.apm = lib.abilities.packageOutput {output = "apm";};
}

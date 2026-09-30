##! Composes the package-owned AOS ability modules.
{lib, package, ...}: {
  imports = [
    ./attestation-verifier.nix
    ./configuration-evaluation.nix
    ./configuration-provider/module.nix
    ./control-plane/module.nix
    ./nix-store-database.nix
    ./package-attestation-quote.nix
    ./package-profile-convergence.nix
    ./release-coordinator/module.nix
    ./runtime-layout.nix
  ];

  options.aos.packageRuntime.artifacts.apm = lib.mkOption {
    type = lib.types.pathInStore;
    readOnly = true;
    internal = true;
    description = "The package-owned apm executable artifact.";
  };

  config.aos.packageRuntime.artifacts.apm = builtins.toString package.apm;
}

##! Pure evaluation regressions for fixed-output source identity metadata.
##!
##! Fixture derivations are evaluated only; their tools and sources are inert
##! store files, so these checks never fetch dependencies or compile packages.
{lib}: let
  sourceFile = builtins.toFile "fixed-output-source-input-fixture" "source fixture";
  source = builtins.toPath sourceFile;
  localTarball = builtins.toFile "fixed-output-local-tarball-fixture" "archive fixture";
  builders = import ../derivations.nix {
    inherit (lib) system;
    bash = sourceFile;
  };

  common = {
    src = source;
    hash = lib.fakeHash;
    bootstrapTools = sourceFile;
  };

  fixtures = {
    cargoDeps = builders.fetchCargoDeps (common // {cargo = sourceFile;});
    cargoVendor = builders.fetchCargoVendor (common
      // {
        cargo = sourceFile;
        python3 = sourceFile;
        git = sourceFile;
        caCertificates = sourceFile;
      });
    goModules = builders.fetchGoModules (common // {go = sourceFile;});
    npmDeps = builders.fetchNpmDeps (common
      // {
        nodejs = sourceFile;
        python3 = sourceFile;
        caCertificates = sourceFile;
        requiresGit = false;
        localTarballs = [
          {
            name = "fixture.tgz";
            path = localTarball;
          }
        ];
      });
    bazelDeps = builders.fetchBazelDeps (common
      // {
        bazel = sourceFile;
        jdk = sourceFile;
        caCertificates = sourceFile;
        bazelTarget = "//:fixture";
      });
  };

  contracts = builtins.mapAttrs (name: derivation: let
    contract = derivation.passthru.aos.fixedOutput;
    expectedSources =
      [(builtins.toString source)]
      ++ lib.optionals (name == "npmDeps") [localTarball];
    serialized = builtins.toJSON contract;
    # JSON consumers receive detached text; Nix's parser rejects store context.
    decoded = builtins.fromJSON (builtins.unsafeDiscardStringContext serialized);
  in
    lib.throwIfNot
    (builtins.all builtins.isString contract.sourceInputs && contract.sourceInputs == expectedSources)
    "${name}: fixed-output source inputs must contain exactly the source identity strings"
    (lib.throwIfNot
      (decoded == contract)
      "${name}: complete fixed-output metadata must round-trip through JSON"
      decoded))
  fixtures;

  identities =
    builtins.mapAttrs (_: derivation: {
      derivationPath = derivation.drvPath;
      outputPath = derivation.outPath;
      outputDerivation = derivation.passthru.aos.fixedOutput.outputDerivation;
    })
    fixtures;
in {
  inherit contracts identities;
}

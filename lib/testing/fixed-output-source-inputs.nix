##! Pure evaluation regressions for fixed-output source identity metadata.
##!
##! Fixture derivations are evaluated only; their tools and sources are inert
##! store files, so these checks never fetch dependencies or compile packages.
{lib}: let
  sourceFile = builtins.toFile "fixed-output-source-input-fixture" "source fixture";
  source = builtins.toPath sourceFile;
  localTarball = builtins.toFile "fixed-output-local-tarball-fixture" "archive fixture";
  registryPatch = builtins.toFile "fixed-output-registry-patch-fixture" "inert patch fixture";
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
    # Evaluation-only provenance: these inert files/tools are never executed.
    cargoVendorPatched = builders.fetchCargoVendor (common
      // {
        cargo = sourceFile;
        python3 = sourceFile;
        git = sourceFile;
        caCertificates = sourceFile;
        patchTool = sourceFile;
        registryPatches = [
          {
            source = "registry+https://github.com/rust-lang/crates.io-index";
            name = "registry-fixture";
            version = "1.0.0";
            archiveSha256 = builtins.hashString "sha256" "inert archive fixture";
            patch = builtins.toPath registryPatch;
            patchSha256 = builtins.hashString "sha256" "inert patch fixture";
            files = [
              {
                path = "src/lib.rs";
                beforeSha256 = builtins.hashString "sha256" "inert before fixture";
                afterSha256 = builtins.hashString "sha256" "inert after fixture";
              }
            ];
          }
        ];
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
      ++ lib.optionals (name == "npmDeps") [localTarball]
      ++ lib.optionals (name == "cargoVendorPatched") [
        contract.registrySourcePatches.normalizedRecipe
        registryPatch
      ];
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
  registryPatchContract = let
    contract = contracts.cargoVendorPatched;
    original = contracts.cargoVendor;
    provenance = contract.registrySourcePatches;
    retainedProvenance = fixtures.cargoVendorPatched.passthru.aos.fixedOutput.registrySourcePatches;
    patchInputFixture = rewritePatch: builders.fetchCargoVendor (common
      // {
        cargo = sourceFile;
        python3 = sourceFile;
        git = sourceFile;
        caCertificates = sourceFile;
        patchTool = sourceFile;
        registryPatches = builtins.map (record:
          record
          // {
            patch = rewritePatch record.patch;
          })
        retainedProvenance.patches;
      });
    contextFreePatch = patchInputFixture builtins.unsafeDiscardStringContext;
    unrelatedContextPatch = patchInputFixture (patch:
      builtins.appendContext
      (builtins.unsafeDiscardStringContext patch)
      (builtins.getContext sourceFile));
    rejectedContextFreePatch =
      builtins.tryEval contextFreePatch.passthru.aos.fixedOutput.registrySourcePatches.normalizedRecipe;
    rejectedUnrelatedContextPatch =
      builtins.tryEval unrelatedContextPatch.passthru.aos.fixedOutput.registrySourcePatches.normalizedRecipe;
  in
    lib.throwIfNot
    (provenance.upstreamStagingDerivation == original.outputDerivation
      && provenance.patchedVendorDerivation == fixtures.cargoVendorPatched.drvPath
      && provenance.patchExecutable == "${sourceFile}/bin/patch"
      && builtins.length provenance.patches == 1
      && builtins.hasContext (builtins.head retainedProvenance.patches).patch
      && (builtins.head retainedProvenance.patches).patch == registryPatch
      && !rejectedContextFreePatch.success
      && !rejectedUnrelatedContextPatch.success
      && !(original ? registrySourcePatches))
    "registry patch provenance must distinguish unchanged upstream staging and patched final vendor"
    provenance;
}

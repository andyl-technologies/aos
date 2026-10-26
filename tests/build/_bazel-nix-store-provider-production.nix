##! Qualifies the installed Nix store handler and its release test profile.
{pkgs}: let
  ordinary = pkgs.aos-nix-store-provider;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/tools/_aos-nix-store-provider-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/tools/aos-nix-store-provider.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel Nix store provider evaluated its Cargo constructor";
    mkCargoArtifacts = _: throw "Bazel Nix store provider evaluated Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel Nix store provider evaluated Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel Nix store provider evaluated its Cargo vendor";
  };
  triple = pkgs.stdenv.hostPlatform.config;
  flagsVariable = "CARGO_TARGET_${pkgs.lib.toUpper (builtins.replaceStrings ["-"] ["_"] triple)}_RUSTFLAGS";
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-nix-store-provider-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit ordinary candidate compilation;
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-nix-store-provider-release-cargo-oracle";
    packages = ["aos-activation-nix-store"];
    captureCompilerArguments = true;
    cargoFlags = ["--release"];
    cargoSetup = ''
      export CARGO_BUILD_TARGET=${pkgs.lib.escapeShellArg triple}
      export ${flagsVariable}="-C target-feature=+crt-static -C relocation-model=static -L ${compilation.libraries}/static/lib"
      export AOS_TEST_NIX_STORE="${pkgs.nix}/bin/nix-store"
    '';
  };
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert ordinary.platformSupport == candidate.platformSupport;
  assert ordinary.runtimeDeps == candidate.runtimeDeps;
  assert ordinary.module == candidate.module && ordinary.moduleDeps == candidate.moduleDeps;
  assert ordinary.qualification == candidate.qualification;
    pkgs.runCommand "aos-bazel-nix-store-provider-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        cargo = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_artifacts_dummy_source_and_vendor_not_evaluated = true;
        platform_runtime_and_qualification_contracts_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs cargo;
    pname = "aos-bazel-nix-store-provider-release-test-profiles";
    tests = compilation.tests;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "//crates/activation/aos-activation-nix-store:static_unit_binary" = "aos_activation_nix_store";
      "//crates/activation/aos-activation-nix-store:static_bin_binary" = "aos_nix_store_provider";
    };
    proceduralMacros = ["ref_cast_impl" "schemars_derive" "serde_derive" "thiserror_impl"];
  };
  parity =
    pkgs.runCommand "aos-bazel-nix-store-provider-installed-parity" {
      buildDeps = [pkgs.python3 pkgs.binutils];
      outputChecks.out = {};
      exportReferencesGraph = {
        ordinary_out = [ordinary];
        bazel_out = [candidate];
      };
    } ''
      mkdir -p "$out"
      cat > packages.json <<'JSON'
      ${builtins.toJSON {
        ordinary.out = toString ordinary;
        bazel.out = toString candidate;
      }}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_nix_store_provider.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --readelf ${pkgs.binutils}/bin/readelf --nix-store ${pkgs.nix}/bin/nix-store \
        --nix-tools ${pkgs.aosBazelNixTestTools} \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-nix-store-provider-production-package-checks" {
      buildDeps = [driver-selection parity execution-profiles];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      printf 'PASS\n' > "$out/result"
    '';
}

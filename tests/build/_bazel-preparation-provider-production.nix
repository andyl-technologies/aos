##! Qualifies the no-default-features preparation provider production selector.
{pkgs}: let
  ordinary = pkgs.aos-boot-preparation-provider;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/boot/_aos-boot-preparation-provider-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/boot/aos-boot-preparation-provider.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel preparation provider evaluated its Cargo constructor";
    mkCargoArtifacts = _: throw "Bazel preparation provider evaluated Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel preparation provider evaluated Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel preparation provider evaluated its Cargo vendor";
  };
  triple = pkgs.stdenv.hostPlatform.config;
  flagsVariable = "CARGO_TARGET_${pkgs.lib.toUpper (builtins.replaceStrings ["-"] ["_"] triple)}_RUSTFLAGS";
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-preparation-provider-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit candidate compilation;
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-preparation-provider-production-cargo-oracle";
    packages = ["aos-boot-runtime"];
    cargoFlags = ["--release" "--no-default-features"];
    captureCompilerArguments = true;
    cargoSetup = ''
      export CARGO_BUILD_TARGET=${pkgs.lib.escapeShellArg triple}
      export ${flagsVariable}="-C target-feature=+crt-static -C relocation-model=static -L ${compilation.libraries}/static/lib"
    '';
  };
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert candidate.platformSupport == ordinary.platformSupport;
  assert candidate.module == ordinary.module;
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
  assert candidate.qualification == ordinary.qualification;
    pkgs.runCommand "aos-bazel-preparation-provider-production-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        ordinary = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_artifacts_dummy_source_and_vendor_not_evaluated = true;
        module_runtime_and_qualification_declarations_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs cargo;
    pname = "aos-bazel-preparation-provider-production-release-test-profiles";
    tests = compilation.tests;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "//crates/boot/aos-boot-runtime:preparation_unit_binary" = "aos_boot_runtime";
      "//crates/boot/aos-boot-runtime:preparation_bin_binary" = "aos_boot_preparation_provider";
    };
    proceduralMacros = ["ref_cast_impl" "schemars_derive" "serde_derive" "thiserror_impl"];
  };
  parity =
    pkgs.runCommand "aos-bazel-preparation-provider-production-installed-parity" {
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
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_preparation_provider.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --libraries ${compilation.libraries} --readelf ${pkgs.binutils}/bin/readelf \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-preparation-provider-production-package-checks" {
      buildDeps = [driver-selection parity execution-profiles];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      printf 'PASS\n' > "$out/result"
    '';
}

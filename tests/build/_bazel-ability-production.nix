##! Qualifies the installed static ability adapter and its production rollback.
{pkgs}: let
  ordinary = pkgs.aos-ability-crucible;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  guarded = pkgs.callPackage ../../pkgs/tools/aos-ability-crucible.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel ability package evaluated its Cargo constructor";
    mkCargoArtifacts = _: throw "Bazel ability package evaluated Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel ability package evaluated Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel ability package evaluated its Cargo vendor";
  };
  family = import ./_bazel-activation-crucible.nix {inherit pkgs;};
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-ability-production-verifiers";
    filter = path: type:
      type
      == "regular"
      && builtins.elem (baseNameOf path) [
        "installed_package.py"
        "verify_ability_package.py"
        "verify_pilot.py"
        "verify_protocol.py"
        "verify_cache.py"
        "verify_static_runtime.py"
        "verify_activation_crucible.py"
      ];
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit candidate;
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs;
    pname = "aos-bazel-ability-production-release-test-profiles";
    tests = candidate.passthru.bazelTests;
    cargo = family.cargo;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "//crates/activation/aos-activation-crucible:unit_binary" = "aos_activation_crucible";
      "//crates/activation/aos-activation-crucible:bin_aos-ability-crucible_binary" = "aos_ability_crucible";
    };
    proceduralMacros = ["curve25519_dalek_derive" "ref_cast_impl" "schemars_derive" "serde_derive" "thiserror_impl" "tracing_attributes" "zerocopy_derive"];
  };
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert candidate.platformSupport == ordinary.platformSupport;
  assert candidate.module == ordinary.module;
  assert candidate.moduleDeps == ordinary.moduleDeps;
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
  assert candidate.qualification == ordinary.qualification;
    pkgs.runCommand "aos-bazel-ability-production-driver-selection" {} ''
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
  parity =
    pkgs.runCommand "aos-bazel-ability-production-installed-parity" {
      buildDeps = [pkgs.python3 pkgs.binutils];
      outputChecks.out = {};
      exportReferencesGraph = {
        ordinary_out = [ordinary];
        bazel_out = [candidate];
        package = [candidate];
      };
    } ''
      mkdir -p "$out"
      cat > packages.json <<'JSON'
      ${builtins.toJSON {
        ordinary.out = toString ordinary;
        bazel.out = toString candidate;
      }}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_ability_package.py \
        --packages packages.json --build ${candidate.passthru.bazelBuild} \
        --tests ${candidate.passthru.bazelTests} --oracle ${family.cargo} \
        --workspace ${candidate.passthru.bazelWorkspace.source} \
        --libraries ${candidate.passthru.bazelLibraries} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all = pkgs.runCommand "aos-bazel-ability-production-package-checks" {buildDeps = [driver-selection parity execution-profiles];} ''
    mkdir -p "$out"
    cp ${driver-selection}/report.json "$out/driver-selection.json"
    cp ${parity}/report.json "$out/report.json"
    cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
    printf 'PASS\n' > "$out/result"
  '';
}

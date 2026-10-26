##! Qualifies the five-output CLI package and its explicit Cargo rollback.
{pkgs}: let
  ordinary = pkgs.aos;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
  rejects = package: !(builtins.tryEval package.drvPath).success;
  unsupportedTests = pkgs.callPackage ../../pkgs/tools/aos/aos.nix {
    buildDriver = "bazel";
    withTests = true;
  };
  rejectCargoBuilder = _: throw "CLI production selection invoked the Cargo constructor";
  withoutCargoBuilder = driver:
    pkgs.callPackage ../../pkgs/tools/aos/aos.nix {
      buildDriver = driver;
      mkAosCargoPackage = rejectCargoBuilder;
    };
  outputs = ["out" "apm" "apr" "packageRuntime" "testSupport"];
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-cli-package-verifiers";
    filter = path: type:
      type == "directory" || builtins.elem (baseNameOf path) ["verify_cli_package.py" "installed_package.py"];
  };
  packages = {
    inherit ordinary;
    bazel = candidate;
  };
  closureEntries = driver:
    map (name: {
      name = "${driver}_${name}";
      value = [packages.${driver}.${name}];
    })
    outputs;
  paths = package:
    builtins.listToAttrs (map (name: {
        inherit name;
        value = toString package.${name};
      })
      outputs);
in rec {
  inherit candidate;
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert rejects (ordinary.passthru.withBuildDriver "invalid");
  assert rejects unsupportedTests;
  assert rejects (withoutCargoBuilder "cargo");
  assert (withoutCargoBuilder "bazel").drvPath == candidate.drvPath;
  assert candidate.outputs == ordinary.outputs;
  assert candidate.platformSupport == ordinary.platformSupport;
  assert candidate.module == ordinary.module;
  assert candidate.moduleDeps == ordinary.moduleDeps;
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
    pkgs.runCommand "aos-bazel-cli-production-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        ordinary = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        bazel_identity_unchanged_with_rejecting_cargo_constructor = true;
        ordinary_rejected_by_the_same_constructor_guard = true;
        unsupported_bazel_full_test_request_rejected = true;
        invalid_driver_rejected = true;
        output_and_module_and_runtime_declarations_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  runtime-module-library = pkgs.callPackage ../../pkgs/tools/aos/_runtime-library-check.nix {
    package = candidate;
    moduleLibrary = pkgs.lib.packageModuleLibrary;
  };
  parity =
    pkgs.runCommand "aos-bazel-cli-production-package-parity" {
      buildDeps = [pkgs.python3 pkgs.binutils];
      outputChecks.out = {};
      exportReferencesGraph = builtins.listToAttrs (pkgs.lib.concatMap closureEntries ["ordinary" "bazel"]);
    } ''
      mkdir -p "$out"
      cat > packages.json <<'JSON'
      ${builtins.toJSON {
        ordinary = paths ordinary;
        bazel = paths candidate;
      }}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
        ${scripts}/verify_cli_package.py \
        --packages packages.json --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" \
        --bazel-build ${candidate.passthru.bazelBuild} \
        --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-cli-production-package-checks" {
      buildDeps = [driver-selection runtime-module-library parity];
    } ''
      mkdir -p "$out"
      cp ${parity}/report.json "$out/"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      printf 'PASS\n' > "$out/result"
    '';
}

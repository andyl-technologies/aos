##! Qualifies the embedded GPL gateway selector and mandatory release assertions.
{pkgs}: let
  ordinary = pkgs.crucible.passthru.debugGateway;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  guarded = pkgs.callPackage ../../pkgs/tools/crucible/_debug-gateway.nix {
    buildDriver = "bazel";
    mkCargoPackage = _: throw "Bazel gateway evaluated Cargo package";
    mkCargoArtifacts = _: throw "Bazel gateway evaluated Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel gateway evaluated Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel gateway evaluated Cargo vendor";
  };
  releaseChecks = import ./_bazel-qemu-gateway-tests.nix {
    inherit pkgs;
    release = true;
  };
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-qemu-gateway-package-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit ordinary candidate;
  release-tests = releaseChecks;
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert (ordinary.platformSupport or null) == (candidate.platformSupport or null);
  assert ordinary.runtimeDeps == candidate.runtimeDeps;
  assert ordinary.meta == candidate.meta;
  assert candidate.passthru.bazelTests.drvPath == releaseChecks.tests.drvPath;
    pkgs.runCommand "aos-bazel-qemu-gateway-public-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        cargo = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructors_and_vendor_not_evaluated = true;
        platform_runtime_and_metadata_contracts_preserved = true;
        release_tests = identity candidate.passthru.bazelTests;
        independent_apache_oracle = identity candidate.passthru.bazelOracle;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  parity =
    pkgs.runCommand "aos-bazel-qemu-gateway-public-package-parity" {
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
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_qemu_gateway_package.py \
        --packages packages.json --closure-attributes "$NIX_ATTRS_JSON_FILE" \
        --build ${candidate.passthru.bazelBuild} --tests ${candidate.passthru.bazelTests} \
        --oracle-build ${candidate.passthru.bazelOracleBuild} \
        --workspace ${candidate.passthru.bazelWorkspace.source} \
        --test-workspace ${candidate.passthru.bazelTestWorkspace.source} \
        --oracle-workspace ${candidate.passthru.bazelOracleWorkspace.source} \
        --gpl ${../../LICENSES/GPL-2.0-only.txt} --mit ${../../LICENSES/MIT.txt} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-qemu-gateway-public-production-checks" {
      buildDeps = [driver-selection parity releaseChecks.parity releaseChecks.codecTests];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp -R ${releaseChecks.parity} "$out/release-tests"
      ln -s ${releaseChecks.codecTests} "$out/codec-tests"
      printf 'PASS\n' > "$out/result"
    '';
}

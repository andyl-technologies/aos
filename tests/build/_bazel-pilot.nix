##! Real Rust targets retain Cargo/production recipes as migration oracles.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/boot-pilot-inventory.json,
}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "crates/aos/boot/aos-boot-identity" "crates/aos/boot/aos-recovery"];
    analysisTargets = ["//crates/aos/boot/aos-boot-identity:package" "//crates/aos/boot/aos-recovery:package"];
  };
  package = name: build:
    pkgs.mkAosBazelPackage {
      pname = name;
      version = "0.1.0";
      inherit build;
      packageLabel = "//crates/aos/boot/${name}:package";
      runtimeDeps = [pkgs.gcc-libs];
    };
in rec {
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-boot-pilot";
    inherit workspace;
    targets = ["//crates/aos/boot/aos-boot-identity:package" "//crates/aos/boot/aos-recovery:package" "//crates/aos/boot/aos-recovery:test_artifacts"];
  };
  unit = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-boot-pilot-tests";
    inherit workspace;
    targets = ["//crates/aos/boot/aos-boot-identity:unit" "//crates/aos/boot/aos-boot-identity:uki_cli" "//crates/aos/boot/aos-boot-identity:doc" "//crates/aos/boot/aos-recovery:unit" "//crates/aos/boot/aos-recovery:doc"];
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-boot-developer-tools";
    inherit workspace;
    targets = ["//crates/aos/boot/aos-boot-identity:clippy" "//crates/aos/boot/aos-recovery:clippy" "//crates/aos/boot/aos-boot-identity:documentation" "//crates/aos/boot/aos-recovery:documentation"];
  };
  developer-tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-boot-format";
    inherit workspace;
    targets = ["//crates/aos/boot/aos-boot-identity:format" "//crates/aos/boot/aos-recovery:format"];
  };
  identity = package "aos-boot-identity" build;
  recovery = package "aos-recovery" build;
  test-artifacts = pkgs.mkAosBazelPackage {
    pname = "aos-recovery-tests";
    version = "0.1.0";
    inherit build;
    packageLabel = "//crates/aos/boot/aos-recovery:test_artifacts";
    runtimeDeps = [pkgs.gcc-libs];
  };
  native-manifest = pkgs.runCommand "aos-bazel-pilot-native-manifest" {} ''
    mkdir -p "$out"
    AOS_RECOVERY_TEST_JQ=${pkgs.jq}/bin/jq ${test-artifacts}/bin/aos-recovery-tests \
      --ignored --exact restore::tests::native_manifest_filter_accepts_current_producer_and_rejects_legacy_or_malformed_abi \
      > "$out/test.log"
    grep -F '1 passed; 0 failed' "$out/test.log"
    printf 'PASS\n' > "$out/result"
  '';
  parity = pkgs.runCommand "aos-bazel-boot-pilot-test-parity" {buildDeps = [pkgs.rust pkgs.python3];} ''
    rustc --edition=2024 --crate-name aos_boot_identity --crate-type rlib \
      ${../../crates/aos/boot/aos-boot-identity}/src/lib.rs -o libaos_boot_identity.rlib
    rustc --edition=2024 --test ${../../crates/aos/boot/aos-boot-identity}/src/lib.rs -o identity-tests
    env CARGO_BIN_EXE_aos-boot-identity=${pkgs.aos-boot-identity}/bin/aos-boot-identity \
      rustc --edition=2024 --test ${../../crates/aos/boot/aos-boot-identity}/tests/uki_cli.rs \
        --extern aos_boot_identity=libaos_boot_identity.rlib -o cli-tests
    rustc --edition=2024 --test ${../../crates/aos/boot/aos-recovery}/src/lib.rs \
      --extern aos_boot_identity=libaos_boot_identity.rlib -o recovery-tests
    # Run the integration oracle against the existing packaged command too.
    ./cli-tests
    ${pkgs.python3}/bin/python3 - <<'PY'
    import json
    from pathlib import Path

    oracles = {
        "//crates/aos/boot/aos-boot-identity:unit": str(Path("identity-tests").resolve()),
        "//crates/aos/boot/aos-boot-identity:uki_cli": str(Path("cli-tests").resolve()),
        "//crates/aos/boot/aos-recovery:unit": str(Path("recovery-tests").resolve()),
    }
    Path("oracles.json").write_text(json.dumps(oracles))
    PY
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_pilot.py} \
      --tests ${unit}/evidence/tests --oracles oracles.json --output "$out/inventory.json"
  '';
  all = pkgs.runCommand "aos-bazel-boot-pilot-checks" {buildDeps = [identity recovery unit native-manifest parity developer-build developer-tests];} ''
    mkdir -p "$out"
    cp -r ${unit}/evidence/tests "$out/tests"
    cp ${build}/inventory.json "$out/inventory.json"
    cp ${parity}/inventory.json "$out/test-parity.json"
  '';
}

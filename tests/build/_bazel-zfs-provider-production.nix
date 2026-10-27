##! Qualifies the static OpenZFS provider production selector.
{pkgs}: let
  ordinary = pkgs.aos-zfs-provider;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/filesystem/_aos-zfs-provider-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/filesystem/aos-zfs-provider.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel OpenZFS provider evaluated its Cargo constructor";
    mkCargoArtifacts = _: throw "Bazel OpenZFS provider evaluated Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel OpenZFS provider evaluated Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel OpenZFS provider evaluated its Cargo vendor";
  };
  triple = pkgs.stdenv.hostPlatform.config;
  flagsVariable = "CARGO_TARGET_${pkgs.lib.toUpper (builtins.replaceStrings ["-"] ["_"] triple)}_RUSTFLAGS";
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-zfs-provider-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit candidate compilation;
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-zfs-provider-production-cargo-oracle";
    packages = ["aos-activation-storage"];
    cargoFlags = ["--release"];
    captureCompilerArguments = true;
    cargoSetup = ''
      export AOS_ZFS_VERSION=${pkgs.lib.escapeShellArg pkgs.zfs.version}
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
  assert candidate.moduleDeps == ordinary.moduleDeps;
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
  assert candidate.qualification == ordinary.qualification;
    pkgs.runCommand "aos-bazel-zfs-provider-production-driver-selection" {} ''
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
    pname = "aos-bazel-zfs-provider-production-release-test-profiles";
    tests = compilation.tests;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "//crates/activation/aos-activation-storage:boot_transaction_unit_binary" = "aos_activation_storage";
      "//crates/activation/aos-activation-storage:static_zfs_pool_bin_binary" = "aos_zfs_pool_provider";
      "//crates/activation/aos-activation-storage:static_zfs_dataset_bin_binary" = "aos_zfs_dataset_provider";
      "//crates/activation/aos-activation-storage:static_zfs_memory_policy_bin_binary" = "aos_zfs_memory_policy";
      "//crates/activation/aos-activation-storage:static_zfs_maintenance_bin_binary" = "aos_zfs_maintenance";
    };
    proceduralMacros = ["ref_cast_impl" "schemars_derive" "serde_derive" "thiserror_impl"];
  };
  parity =
    pkgs.runCommand "aos-bazel-zfs-provider-production-installed-parity" {
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
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_zfs_provider.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --libraries ${compilation.libraries} --runtime ${compilation.runtime} \
        --zfs-version ${pkgs.lib.escapeShellArg pkgs.zfs.version} --readelf ${pkgs.binutils}/bin/readelf \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-zfs-provider-production-package-checks" {
      buildDeps = [driver-selection parity execution-profiles];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      printf 'PASS\n' > "$out/result"
    '';
}

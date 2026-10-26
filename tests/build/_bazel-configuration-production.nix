##! Qualifies static configuration commands through their production selector.
{pkgs}: let
  ordinary = pkgs.aos-configuration-lower;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/boot/_aos-configuration-lower-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/boot/aos-configuration-lower.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel configuration package evaluated its Cargo constructor";
    mkCargoArtifacts = _: throw "Bazel configuration package evaluated Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel configuration package evaluated Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel configuration package evaluated its Cargo vendor";
  };
  guardedTools = import ../../pkgs/build-support/_bazel/configuration-tools.nix {
    pkgs =
      pkgs
      // {
        aos-configuration-lower = throw "configuration tools depend on their own consuming package";
      };
    inherit (pkgs) lib;
  };
  cargoEnvironment = import ../../pkgs/boot/_aos-configuration-lower/cargo-env.nix {
    inherit (pkgs) erofs-utils util-linux;
    packageRuntime = pkgs.aos.packageRuntime;
  };
  triple = pkgs.stdenv.hostPlatform.config;
  flagsVariable = "CARGO_TARGET_${pkgs.lib.toUpper (builtins.replaceStrings ["-"] ["_"] triple)}_RUSTFLAGS";
  prefix = "//crates/boot/aos-configuration-image:";
  commands = ["aos-certificate-bundle" "aos-configuration-boot" "aos-configuration-lower" "aos-configuration-mount"];
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-configuration-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit candidate compilation;
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-configuration-production-cargo-oracle";
    packages = ["aos-configuration-image"];
    cargoFlags = ["--release"];
    captureCompilerArguments = true;
    cargoSetup = ''
      export CARGO_BUILD_TARGET=${pkgs.lib.escapeShellArg triple}
      export ${flagsVariable}="-C target-feature=+crt-static -C relocation-model=static -L ${compilation.libraries}/static/lib"
      ${pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList (name: value: "export ${name}=${pkgs.lib.escapeShellArg value}") cargoEnvironment)}
    '';
  };
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert guardedTools.drvPath == compilation.tools.drvPath;
  assert candidate.platformSupport == ordinary.platformSupport;
  assert candidate.module == ordinary.module;
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
  assert candidate.qualification == ordinary.qualification;
    pkgs.runCommand "aos-bazel-configuration-production-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        ordinary = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_artifacts_dummy_source_and_vendor_not_evaluated = true;
        tools_do_not_depend_on_consuming_configuration_package = true;
        module_runtime_and_qualification_declarations_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs cargo;
    pname = "aos-bazel-configuration-production-release-test-profiles";
    tests = compilation.tests;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests =
      {"${prefix}static_unit_binary" = "aos_configuration_image";}
      // builtins.listToAttrs (map (name: {
          name = "${prefix}static_bin_${name}_binary";
          value = builtins.replaceStrings ["-"] ["_"] name;
        })
        commands);
    proceduralMacros = ["ref_cast_impl" "schemars_derive" "serde_derive" "thiserror_impl"];
  };
  parity =
    pkgs.runCommand "aos-bazel-configuration-production-installed-parity" {
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
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_configuration_package.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --libraries ${compilation.libraries} --tools ${compilation.tools} \
        --readelf ${pkgs.binutils}/bin/readelf --closure-attributes "$NIX_ATTRS_JSON_FILE" \
        --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-configuration-production-package-checks" {
      buildDeps = [driver-selection parity execution-profiles];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      printf 'PASS\n' > "$out/result"
    '';
}

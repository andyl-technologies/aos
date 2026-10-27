##! Qualifies the installed file signer and its externally verified signing protocol.
{pkgs}: let
  ordinary = pkgs.aos-release-signer;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/tools/_aos-release-signer-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/tools/aos-release-signer.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel release signer evaluated Cargo";
    aosWorkspaceVendor = throw "Bazel release signer evaluated Cargo vendor";
  };
  packagePaths = {
    aos-core = "crates/core/aos-core";
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-registry-format = "crates/registry/aos-registry-format";
    aos-module-format = "crates/modules/aos-module-format";
    aos-release-format = "crates/release/aos-release-format";
    aos-release-signer = "crates/release/aos-release-signer";
  };
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-release-signer-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;};
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit ordinary candidate compilation;
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-release-signer-release-cargo-oracle";
    packages = ["aos-release-signer"];
    cargoFlags = ["--release" "--bin" "aos-release-signer"];
    captureCompilerArguments = true;
    # BUILD declarations are not inputs to this temporary Cargo oracle. Keep
    # its source identity stable while adding installed Bazel package roots.
    cargoSource = builtins.path {
      path = cargoSource;
      name = "aos-release-signer-cargo-oracle-source";
      filter = path: _: baseNameOf path != "BUILD.bazel";
    };
    cargoSetup = ''
      export CARGO_BUILD_TARGET=${pkgs.lib.escapeShellArg pkgs.stdenv.hostPlatform.config}
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
  assert ordinary.qualification == candidate.qualification;
    pkgs.runCommand "aos-bazel-release-signer-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        cargo = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_and_vendor_not_evaluated = true;
        platform_runtime_and_qualification_contracts_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  parity =
    pkgs.runCommand "aos-bazel-release-signer-installed-parity" {
      buildDeps = [pkgs.python3 pkgs.binutils pkgs.openssl pkgs.openssh pkgs.sbsigntools pkgs.llvm];
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
      cat > package-paths.json <<'JSON'
      ${builtins.toJSON packagePaths}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_release_signer.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --package-paths package-paths.json \
        --openssl ${pkgs.openssl}/bin/openssl --ssh-keygen ${pkgs.openssh}/bin/ssh-keygen \
        --sbsign ${pkgs.sbsigntools}/bin/sbsign --sbverify ${pkgs.sbsigntools}/bin/sbverify \
        --clang ${pkgs.llvm}/bin/clang --lld-link ${pkgs.llvm}/bin/lld-link \
        --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-release-signer-production-checks" {
      buildDeps = [driver-selection parity];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
}

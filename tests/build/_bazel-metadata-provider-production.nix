##! Qualifies dynamic metadata providers and their immutable Nix companion.
{pkgs}: let
  ordinary = pkgs.aos-metadata-provider;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/tools/_aos-metadata-provider-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/tools/aos-metadata-provider.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel metadata provider evaluated its Cargo constructor";
    mkCargoArtifacts = _: throw "Bazel metadata provider evaluated its Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel metadata provider evaluated its Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel metadata provider evaluated its Cargo vendor";
  };
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-metadata-provider-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
  library = pkgs.runCommand "aos-bazel-metadata-provider-library-fixture" {} ''
    mkdir -p "$out"
    printf '{ qualification = true; }\n' > "$out/default.nix"
  '';
  fixtures = pkgs.runCommand "aos-bazel-metadata-provider-evaluation-fixtures" {buildDeps = [pkgs.python3 pkgs.nix];} ''
    mkdir -p "$out"
    ${pkgs.nix}/bin/nix-store --dump ${library} > library.nar
    ${pkgs.python3}/bin/python3 - "$out" ${library} <<'PYTHON'
    import hashlib
    import json
    from pathlib import Path
    import sys

    descriptor = {"schema": "aos.package.evaluation-input", "library": sys.argv[2],
                  "libraryNarHash": "sha256:" + hashlib.sha256(Path("library.nar").read_bytes()).hexdigest()}
    output = Path(sys.argv[1])
    (output / "descriptor.json").write_text(json.dumps(descriptor) + "\n")
    descriptor["libraryNarHash"] = "sha256:" + "00" * 32
    (output / "wrong-hash.json").write_text(json.dumps(descriptor) + "\n")
    PYTHON
  '';
  inputs =
    import ../../lib/build/closure-info.nix {
      inherit pkgs;
      inherit (pkgs) lib;
    } {
      pname = "aos-bazel-metadata-provider-evaluation-inputs";
      rootPaths = [fixtures];
    };
in rec {
  inherit candidate compilation;
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-metadata-provider-production-cargo-oracle";
    packages = ["aos-platform-metadata"];
    cargoFlags = ["--release"];
    captureCompilerArguments = true;
    nativeLibraries = [pkgs.openssl pkgs.libssh2 pkgs.zlib pkgs.nix];
    nativeTools = [pkgs.cmake pkgs.pkg-config];
    cargoSetup = ''
      export AOS_LIBSSH2_PREFIX="${pkgs.libssh2}"
      export OPENSSL_DIR="${pkgs.openssl}"
      export OPENSSL_LIB_DIR="${pkgs.openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${pkgs.openssl}/include"
      export OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0
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
    pkgs.runCommand "aos-bazel-metadata-provider-production-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        ordinary = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_artifacts_dummy_source_and_vendor_not_evaluated = true;
        module_qualification_and_runtime_declarations_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs cargo;
    pname = "aos-bazel-metadata-provider-production-release-test-profiles";
    tests = compilation.tests;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "//crates/boot/aos-platform-metadata:unit_binary" = "aos_platform_metadata";
      "//crates/boot/aos-platform-metadata:bin_aos-metadata-acquisition-provider_binary" = "aos_metadata_acquisition_provider";
      "//crates/boot/aos-platform-metadata:bin_aos-metadata-policy-provider_binary" = "aos_metadata_policy_provider";
    };
    proceduralMacros = [
      "async_trait"
      "aws_smithy_runtime_api_macros"
      "curve25519_dalek_derive"
      "displaydoc"
      "futures_macro"
      "ref_cast_impl"
      "rustversion"
      "schemars_derive"
      "serde_derive"
      "thiserror_impl"
      "tokio_macros"
      "tracing_attributes"
      "yoke_derive"
      "zerofrom_derive"
      "zerovec_derive"
    ];
  };
  parity =
    pkgs.runCommand "aos-bazel-metadata-provider-production-installed-parity" {
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
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_metadata_provider.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"

      printf 'PASS\n' > "$out/result"
    '';
  effects =
    pkgs.runCommand "aos-bazel-metadata-provider-production-effects" {
      buildDeps = [pkgs.python3 pkgs.nix inputs];
      outputChecks.out = {};
    } ''
      mkdir -p "$out"
      cat > packages.json <<'JSON'
      ${builtins.toJSON {
        ordinary.out = toString ordinary;
        bazel.out = toString candidate;
      }}
      JSON
      evaluation_store_root="$TMPDIR/evaluation-store"
      evaluation_store="local?root=$evaluation_store_root"
      mkdir -p "$evaluation_store_root/nix/store"
      while IFS= read -r store_path; do
        cp -a --no-preserve=ownership "$store_path" "$evaluation_store_root/nix/store/"
      done < ${inputs}/store-paths
      ${pkgs.nix}/bin/nix-store --store "$evaluation_store" --init
      ${pkgs.nix}/bin/nix-store --store "$evaluation_store" --load-db < ${inputs}/registration
      export AOS_NIX_STORE_DIR=/nix/store
      export AOS_NIX_EVAL_STORE="$evaluation_store"
      PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 - \
        packages.json ${fixtures} "$out/effects.json" <<'PYTHON'
      import json
      from pathlib import Path
      import sys

      from metadata_provider_effects import compare

      packages = json.loads(Path(sys.argv[1]).read_text())
      result = compare(packages, Path(sys.argv[2]))
      Path(sys.argv[3]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
      PYTHON
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-metadata-provider-production-package-checks" {
      buildDeps = [driver-selection parity execution-profiles effects];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp ${effects}/effects.json "$out/effects.json"
      cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      printf 'PASS\n' > "$out/result"
    '';
}

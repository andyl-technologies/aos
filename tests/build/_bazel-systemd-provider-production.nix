##! Qualifies the six installed systemd commands and complete package tests.
{pkgs}: let
  ordinary = pkgs.aos-systemd-provider;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/system/_aos-systemd-provider-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/system/aos-systemd-provider.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel systemd provider evaluated its Cargo constructor";
    aosWorkspaceVendor = throw "Bazel systemd provider evaluated its Cargo vendor";
  };
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-systemd-provider-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit candidate compilation;
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-systemd-provider-production-cargo-oracle";
    packages = ["aos-activation-systemd" "aos-boot-runtime"];
    cargoFlags = ["--release"];
    captureCompilerArguments = true;
    nativeLibraries = [pkgs.libssh2 pkgs.openssl pkgs.sqlite pkgs.tpm2-tools pkgs.zlib];
    nativeTools = [pkgs.cmake pkgs.perl pkgs.pkg-config pkgs.protobuf];
    cargoSetup = ''
      export AOS_LIBSSH2_PREFIX="${pkgs.libssh2}"
      export OPENSSL_DIR="${pkgs.openssl}"
      export OPENSSL_LIB_DIR="${pkgs.openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${pkgs.openssl}/include"
      export OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0 LIBSQLITE3_SYS_USE_PKG_CONFIG=1
      export PROTOC="${pkgs.protobuf}/bin/protoc"
      export AOS_NIX_STORE="${pkgs.nix}/bin/nix-store"
      export AOS_TPM2_CREATEEK="${pkgs.tpm2-tools}/bin/tpm2_createek"
      export AOS_TPM2_CREATEAK="${pkgs.tpm2-tools}/bin/tpm2_createak"
      export AOS_TPM2_READPUBLIC="${pkgs.tpm2-tools}/bin/tpm2_readpublic"
      export AOS_TPM2_QUOTE="${pkgs.tpm2-tools}/bin/tpm2_quote"
      export AOS_TPM2_PCRREAD="${pkgs.tpm2-tools}/bin/tpm2_pcrread"
      export AOS_TPM2_CHECKQUOTE="${pkgs.tpm2-tools}/bin/tpm2_checkquote"
      export AOS_TPM2_FLUSHCONTEXT="${pkgs.tpm2-tools}/bin/tpm2_flushcontext"
    '';
  };
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert candidate.platformSupport == ordinary.platformSupport;
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
  assert candidate.qualification == ordinary.qualification;
    pkgs.runCommand "aos-bazel-systemd-provider-production-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        ordinary = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_and_vendor_not_evaluated = true;
        qualification_and_runtime_declarations_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs cargo;
    pname = "aos-bazel-systemd-provider-production-release-test-profiles";
    tests = compilation.tests;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "//crates/activation/aos-activation-systemd:bin_aos-systemd-native-resource-provider_binary" = "aos_systemd_native_resource_provider";
      "//crates/activation/aos-activation-systemd:bin_aos-systemd-credential-encrypt_binary" = "aos_systemd_credential_encrypt";
      "//crates/boot/aos-boot-runtime:unit_binary" = "aos_boot_runtime";
      "//crates/boot/aos-boot-runtime:bin_aos-systemd-boot-platform_binary" = "aos_systemd_boot_platform";
      "//crates/boot/aos-boot-runtime:bin_aos-systemd-image-stage_binary" = "aos_systemd_image_stage";
      "//crates/boot/aos-boot-runtime:bin_aos-systemd-image-evidence_binary" = "aos_systemd_image_evidence";
      "//crates/boot/aos-boot-runtime:bin_aos-systemd-initrd-store_binary" = "aos_systemd_initrd_store";
      "//crates/boot/aos-boot-runtime:bin_aos-boot-preparation-provider_binary" = "aos_boot_preparation_provider";
    };
    proceduralMacros = [
      "async_recursion"
      "async_trait"
      "curve25519_dalek_derive"
      "enumflags2_derive"
      "futures_macro"
      "ref_cast_impl"
      "schemars_derive"
      "serde_derive"
      "serde_repr"
      "thiserror_impl"
      "tokio_macros"
      "tracing_attributes"
      "zbus_macros"
      "zvariant_derive"
    ];
  };
  parity =
    pkgs.runCommand "aos-bazel-systemd-provider-production-installed-parity" {
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
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_systemd_provider.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --test-tools ${compilation.testTools} --bash ${pkgs.bash}/bin/bash --python ${pkgs.python3}/bin/python3 \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  effects =
    pkgs.runCommand "aos-bazel-systemd-provider-production-effects" {
      buildDeps = [pkgs.python3 pkgs.nix];
      outputChecks.out = {};
    } ''
      mkdir -p "$out"
      cat > packages.json <<'JSON'
      ${builtins.toJSON {
        ordinary.out = toString ordinary;
        bazel.out = toString candidate;
      }}
      JSON
      PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 - \
        packages.json ${pkgs.nix}/bin/nix-store "$out/effects.json" <<'PYTHON'
      import json
      from pathlib import Path
      import sys
      from systemd_provider_effects import compare

      result = compare(json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2]))
      Path(sys.argv[3]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
      PYTHON
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-systemd-provider-production-package-checks" {
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

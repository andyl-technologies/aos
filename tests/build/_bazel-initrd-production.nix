##! Qualifies standalone initrd compilation, installed helpers, and rollback.
{pkgs}: let
  ordinary = pkgs.aos-boot-preparations;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  build = candidate.passthru.bazelBuild;
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-initrd-package-verifiers";
    filter = path: type:
      type == "directory" || builtins.elem (baseNameOf path) ["installed_package.py" "verify_initrd_package.py" "verify_pilot.py" "verify_cache.py"];
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit candidate;
  driver-selection = assert ordinary.passthru.buildDriver == "rustc";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.rustcFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "rustc").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert candidate.platformSupport == ordinary.platformSupport;
  assert candidate.module == ordinary.module;
  assert candidate.moduleDeps == ordinary.moduleDeps;
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
    pkgs.runCommand "aos-bazel-initrd-preparation-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        ordinary = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.rustcFallback;
        invalid_driver_rejected = true;
        module_and_runtime_declarations_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  parity =
    pkgs.runCommand "aos-bazel-initrd-preparation-production-parity" {
      buildDeps = [pkgs.rust pkgs.python3 pkgs.binutils];
      outputChecks.out = {};
      exportReferencesGraph = {
        ordinary_out = [ordinary];
        bazel_out = [candidate];
      };
    } ''
      mkdir -p "$out"
      export AOS_PACKAGE_RUNTIME=${pkgs.aos.packageRuntime}/bin/aos-package-runtime
      export AOS_BOOT_CONFIGURATION=${pkgs.aos.packageRuntime}/bin/aos-boot-configuration
      export AOS_CONFIGURATION_BOOT=${pkgs.aos-configuration-lower}/bin/aos-configuration-boot
      rustc --edition=2024 --crate-name aos_initrd_preparation --test \
        ${../../crates/boot/aos-boot-runtime/standalone/initrd_preparation.rs} -o unit-tests
      ./unit-tests > "$out/ordinary-unit.log"
      cat > packages.json <<'JSON'
      ${builtins.toJSON {
        ordinary.out = toString ordinary;
        bazel.out = toString candidate;
      }}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_initrd_package.py \
        --packages packages.json --build ${build} --oracle "$PWD/unit-tests" \
        --workspace ${candidate.passthru.bazelWorkspace.source} \
        --source-inventory ${../../tools/bazel/metadata/initrd-preparation-inventory.json} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all = pkgs.runCommand "aos-bazel-initrd-preparation-production-checks" {buildDeps = [driver-selection parity];} ''
    mkdir -p "$out"
    cp ${driver-selection}/report.json "$out/driver-selection.json"
    cp ${parity}/report.json "$out/report.json"
    printf 'PASS\n' > "$out/result"
  '';
}

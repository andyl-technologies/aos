##! Qualifies the installed release libtest and real boot admission fixtures.
{pkgs}: let
  ordinary = pkgs.aos-boot-configuration-test-driver;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/tools/_aos-boot-configuration-driver-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/tools/aos-boot-configuration-test-driver.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel boot driver evaluated its Cargo constructor";
    aosWorkspaceVendor = throw "Bazel boot driver evaluated its Cargo vendor";
  };
  family = import ./_bazel-package-manager.nix {inherit pkgs;};
  packagePaths = family.packages // family.dependencyPackages;
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-boot-configuration-driver-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  fixture = driver:
    import ../../lib/testing/boot-configuration.nix {
      pkgs = pkgs // {aos-boot-configuration-test-driver = driver;};
      inherit (pkgs) lib;
      mkSystem = _: throw "boot fixture must not construct a system";
    };
  installedTests = driver:
    pkgs.runCommand "aos-bazel-boot-driver-installed-unit-tests" {
      buildDeps = [pkgs.python3 pkgs.coreutils pkgs.aosBazelRegistryTestTools];
    } ''
      mkdir -p "$out" "$TMPDIR/test-runtime"
      export TEST_TMPDIR="$TMPDIR/test-runtime"
      export XML_OUTPUT_FILE="$out/unit.xml"
      export SSL_CERT_FILE=${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt
      export AOS_TEST_IDENTITY_PRELOAD="$TMPDIR/aos-test-identity.so"
      cc -shared -fPIC -O2 -Wall -Wextra -Werror \
        -o "$AOS_TEST_IDENTITY_PRELOAD" ${../../crates/hub/aos-hub-native/tests/nix_builder_identity.c}
      set -- ${driver}/bin/aos_package_manager-*
      test "$#" -eq 1
      ${pkgs.aosBazelRegistryTestTools}/setup ${pkgs.python3}/bin/python3 \
        ${../../tools/bazel/testing/runner.py} --binary "$1" --package aos-package-manager \
        --policy ${../../tools/bazel/testing/policy.json} --jobs 2 > "$out/unit.log" 2>&1 || {
        cat "$out/unit.log" >&2
        exit 1
      }
      printf 'PASS\n' > "$out/result"
    '';
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit ordinary candidate compilation;
  workflows = {
    ordinary = fixture ordinary;
    bazel = fixture candidate;
  };
  ordinary-tests = installedTests ordinary;
  bazel-installed-tests = installedTests candidate;
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert ordinary.platformSupport == candidate.platformSupport;
  assert ordinary.runtimeDeps == candidate.runtimeDeps;
    pkgs.runCommand "aos-bazel-boot-configuration-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        cargo = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_and_vendor_not_evaluated = true;
        platform_and_runtime_contracts_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  parity =
    pkgs.runCommand "aos-bazel-boot-configuration-driver-installed-parity" {
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
      cat > package-paths.json <<'JSON'
      ${builtins.toJSON packagePaths}
      JSON
      cat > workflows.json <<'JSON'
      ${builtins.toJSON (builtins.mapAttrs (_: toString) workflows)}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_boot_configuration_driver.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --workspace ${compilation.workspace.source} --package-paths package-paths.json \
        --ordinary-tests ${ordinary-tests} --bazel-installed-tests ${bazel-installed-tests} --workflows workflows.json \
        --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-boot-configuration-driver-production-checks" {
      buildDeps = [driver-selection parity];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
}

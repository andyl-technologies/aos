##! Qualifies installed required-live SQL contracts against real PostgreSQL and MariaDB.
{pkgs}: let
  ordinary = pkgs.aos-hub-dialect-tests;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/tools/_aos-hub-dialect-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/tools/aos-hub-dialect-tests.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel Hub dialect driver evaluated Cargo";
    aosWorkspaceVendor = throw "Bazel Hub dialect driver evaluated Cargo vendor";
  };
  testing = import ../../lib/testing {
    inherit pkgs;
    inherit (pkgs) lib;
  };
  observe = package: let
    recipe =
      (package.checks {
        inherit pkgs;
        self = package;
        testing.mkVMTest = arguments: arguments;
      }).live-dialects;
    command = "aos-hub-dialect-contract --nocapture --test-threads=1";
  in
    assert builtins.length (pkgs.lib.splitString command recipe.testScript) == 2;
      testing.mkVMTest (recipe
        // {
          name = recipe.name + "-baseline-observation";
          # Preserve the public fail-closed check. This separate observation
          # retains its real exit status so parity can compare known failures.
          testScript =
            builtins.replaceStrings [command] [
              ''
                status=0
                ${command} || status=$?
                printf 'AOS_HUB_DIALECT_OBSERVED_EXIT=%s\n' "$status"
              ''
            ]
            recipe.testScript;
        });
  # Compare the original public check's behavior as well as running it below.
  contract = package: let
    recipe =
      (package.checks {
        inherit pkgs;
        self = package;
        testing.mkVMTest = arguments: arguments;
      }).live-dialects;
  in {
    inherit (recipe) name memory testScript;
    rootfsDependencies = map toString (builtins.tail recipe.rootfsDeps);
    selectedPackage = builtins.head recipe.rootfsDeps == package;
  };
  packagePaths = {
    aos-activation = "crates/activation/aos-activation";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-cli-ui = "crates/cli/aos-cli-ui";
    aos-core = "crates/core/aos-core";
    aos-deployment = "crates/packages/aos-deployment";
    aos-deployment-format = "crates/packages/aos-deployment-format";
    aos-hub-api = "crates/hub/aos-hub-api";
    aos-hub-client = "crates/hub/aos-hub-client";
    aos-hub-db = "crates/hub/aos-hub-db";
    aos-hub-model = "crates/hub/aos-hub-model";
    aos-hub-native = "crates/hub/aos-hub-native";
    aos-hub-service = "crates/hub/aos-hub-service";
    aos-hub-ui = "crates/hub/aos-hub-ui";
    aos-module-docs = "crates/modules/aos-module-docs";
    aos-module-format = "crates/modules/aos-module-format";
    aos-nar = "crates/artifacts/aos-nar";
    aos-nix = "crates/nix/aos-nix";
    aos-nix-cache = "crates/packages/aos-nix-cache";
    aos-oci = "crates/artifacts/aos-oci";
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-registry-authoring = "crates/registry/aos-registry-authoring";
    aos-registry-client = "crates/registry/aos-registry-client";
    aos-registry-format = "crates/registry/aos-registry-format";
    aos-release-format = "crates/release/aos-release-format";
    aos-transfer = "crates/transfer/aos-transfer";
    libssh2-sys = "crates/bindings/libssh2-sys";
  };
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-hub-dialect-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit ordinary candidate compilation;
  ordinary-vm = observe ordinary;
  bazel-vm = observe candidate;
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert ordinary.platformSupport == candidate.platformSupport;
  assert ordinary.runtimeDeps == candidate.runtimeDeps;
  assert ordinary.qualification == candidate.qualification;
  assert contract ordinary == contract candidate;
    pkgs.runCommand "aos-bazel-hub-dialect-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        cargo = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_and_vendor_not_evaluated = true;
        platform_runtime_qualification_and_live_check_contracts_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  parity =
    pkgs.runCommand "aos-bazel-hub-dialect-installed-parity" {
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
      cat > vms.json <<'JSON'
      ${builtins.toJSON {
        ordinary = toString ordinary-vm;
        bazel = toString bazel-vm;
      }}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_hub_dialect.py \
        --packages packages.json --build ${compilation.build} \
        --workspace ${compilation.workspace.source} --package-paths package-paths.json \
        --vms vms.json --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-hub-dialect-production-checks" {
      buildDeps = [driver-selection parity];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
}

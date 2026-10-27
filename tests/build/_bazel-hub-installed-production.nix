##! Qualifies installed native Hub commands, egress and public operator VMs.
{pkgs}: let
  ordinary = pkgs.aos-hub;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/tools/_aos-hub-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/tools/aos-hub/aos-hub.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel native Hub evaluated Cargo";
    mkCargoArtifacts = _: throw "Bazel native Hub evaluated Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel native Hub evaluated Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel native Hub evaluated Cargo vendor";
  };
  testing = import ../../lib/testing {
    inherit pkgs;
    inherit (pkgs) lib;
  };
  observe = package: let
    recipe = import ../vm/hub-native-operations.nix {
      testing = testing // {mkVMTest = arguments: arguments;};
      pkgs = pkgs // {aos-hub = package;};
    };
    originalScript = pkgs.writeTextFile {
      name = "hub-native-operations-original-script";
      destination = "/script.sh";
      text = recipe.testScript;
    };
  in
    testing.mkVMTest (recipe
      // {
        name = recipe.name + "-baseline-observation";
        rootfsDeps = recipe.rootfsDeps ++ [originalScript pkgs.bash];
        # A separate shell preserves the original script's errexit behavior.
        # Observe its status without repairing the pre-existing fixture.
        testScript = ''
          status=0
          ${pkgs.bash}/bin/bash ${originalScript}/script.sh || status=$?
          printf 'AOS_HUB_OPERATOR_OBSERVED_EXIT=%s\n' "$status"
        '';
      });
  packagePaths = {
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-core = "crates/core/aos-core";
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
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-registry-client = "crates/registry/aos-registry-client";
    aos-registry-format = "crates/registry/aos-registry-format";
    aos-release-format = "crates/release/aos-release-format";
    aos-transfer = "crates/transfer/aos-transfer";
    libssh2-sys = "crates/bindings/libssh2-sys";
  };
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-hub-installed-production-verifiers";
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
  assert ordinary.module == candidate.module;
  assert ordinary.moduleDeps == candidate.moduleDeps;
    pkgs.runCommand "aos-bazel-hub-installed-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        cargo = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructors_and_vendor_not_evaluated = true;
        platform_runtime_module_and_qualification_contracts_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  parity =
    pkgs.runCommand "aos-bazel-hub-installed-parity" {
      buildDeps = [pkgs.python3 pkgs.binutils pkgs.git pkgs.nix pkgs.openssh];
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
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_hub_installed.py \
        --packages packages.json --build ${compilation.build} \
        --workspace ${compilation.workspace.source} --package-paths package-paths.json \
        --vms vms.json --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-hub-installed-production-checks" {
      buildDeps = [driver-selection parity];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
}

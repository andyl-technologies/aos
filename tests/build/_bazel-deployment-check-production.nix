##! Qualifies the installed validator and the actual OCI deployment producer.
{pkgs}: let
  ordinary = pkgs.aos-deployment-check;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/tools/_aos-deployment-check-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/tools/aos-deployment-check.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel deployment validator evaluated Cargo";
    aosWorkspaceVendor = throw "Bazel deployment validator evaluated Cargo vendor";
  };
  family = import ./_bazel-package-manager.nix {inherit pkgs;};
  packagePaths = family.packages // family.dependencyPackages;
  inputs = import ./_bazel-registry-native-inputs.nix {inherit pkgs;};
  triple = pkgs.stdenv.hostPlatform.config;
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-deployment-check-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  interface = pkgs.mkDerivation {
    pname = "deployment-validator-fixture-interface";
    version = "1";
    src = null;
    module = ../effects/package-interface;
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out"'';
      }
    ];
  };
  consumer = pkgs.mkDerivation {
    pname = "deployment-validator-fixture-consumer";
    version = "1";
    src = null;
    module = ../effects/package-consumer;
    moduleDeps = [interface];
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out"'';
      }
    ];
  };
  handler =
    (pkgs.writeShellScriptBin "handler" ''
      case "$1" in
        apply) exec ${pkgs.jq}/bin/jq '{message: .input.message}' ;;
        remove) exec ${pkgs.jq}/bin/jq '{}' ;;
        observe) exec ${pkgs.jq}/bin/jq '{status: "retry-safe"}' ;;
        *) exit 1 ;;
      esac
    '').overrideAttrs (_: {
      catalogName = "deployment-validator-fixture-handler";
      version = "1";
      module = ../effects/package-handler;
      moduleDeps = [interface];
    });
  producer = driver: let
    tools = pkgs.mkOciTools {
      buildPackages = pkgs.buildPackages // {aos-deployment-check = driver;};
    };
  in
    (tools.mkDeploymentArtifact {
      inherit pkgs;
      packages = [consumer handler];
      scope = ["profile" "integration"];
      operatorModules = [../effects/package-operator];
      platform = {
        os = "linux";
        architecture = "amd64";
      };
      pname = "bazel-deployment-validator-artifact";
    }).artifact;
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit ordinary candidate compilation;
  producers = {
    ordinary = producer ordinary;
    bazel = producer candidate;
  };
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    inherit (inputs) cargoSource nativeLibraries nativeTools;
    pname = "aos-bazel-deployment-check-release-cargo-oracle";
    packages = ["aos-package-manager"];
    cargoFlags = ["--release" "--bin" "aos-deployment-check"];
    captureCompilerArguments = true;
    cargoSetup =
      inputs.cargoSetup
      + ''
        export CARGO_BUILD_TARGET=${pkgs.lib.escapeShellArg triple}
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
    pkgs.runCommand "aos-bazel-deployment-check-driver-selection" {} ''
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
    pkgs.runCommand "aos-bazel-deployment-check-installed-parity" {
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
      cat > producers.json <<'JSON'
      ${builtins.toJSON (builtins.mapAttrs (_: toString) producers)}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_deployment_check.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --package-paths package-paths.json --producers producers.json \
        --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-deployment-check-production-checks" {
      buildDeps = [driver-selection parity];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
}

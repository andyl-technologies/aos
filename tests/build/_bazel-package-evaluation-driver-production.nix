##! Qualifies the installed evaluation example and its real isolated-store modes.
{pkgs}: let
  ordinary = pkgs.aos-package-evaluation-driver;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/tools/_aos-package-evaluation-driver-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/tools/aos-package-evaluation-driver.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel evaluation driver evaluated its Cargo constructor";
    aosWorkspaceVendor = throw "Bazel evaluation driver evaluated its Cargo vendor";
  };
  family = import ./_bazel-package-manager.nix {inherit pkgs;};
  packagePaths = family.packages // family.dependencyPackages;
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-package-evaluation-driver-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  fixture = import ../effects/deployment-fixture.nix {
    inherit pkgs;
    inherit (pkgs) lib;
  };
  inputs = pkgs.lib.build.closureInfo {inherit pkgs;} {
    pname = "bazel-evaluation-driver-activation-inputs";
    rootPaths = [fixture];
  };
  activation = driver:
    pkgs.mkDerivation {
      pname = "bazel-evaluation-driver-activation";
      version = "1";
      src = null;
      buildDeps = [driver pkgs.coreutils pkgs.nix inputs];
      phases = [
        {
          name = "check";
          script = ''
            set -eu
            mkdir -p "$out"
            isolated_root="$TMPDIR/evaluation-driver-activation-store"
            isolated_store="local?root=$isolated_root"
            mkdir -p "$isolated_root/nix/store"
            while IFS= read -r store_path; do
              cp -a --no-preserve=ownership "$store_path" "$isolated_root/nix/store/"
            done < ${inputs}/store-paths
            ${pkgs.nix}/bin/nix-store --store "$isolated_store" --init
            ${pkgs.nix}/bin/nix-store --store "$isolated_store" --load-db < ${inputs}/registration
            export AOS_NIX_STORE_DIR=/nix/store
            export AOS_NIX_EVAL_STORE="$isolated_store"
            export AOS_NIX_STORE=${pkgs.nix}/bin/nix-store
            export AOS_NIX_INSTANTIATE=${pkgs.nix}/bin/nix-instantiate
            if ! PATH=/no-evaluator-on-path ${pkgs.coreutils}/bin/timeout 180 \
              ${driver}/bin/package_deployment_check \
              ${fixture}/fixture.json ${pkgs.nix}/bin/nix-store \
              > "$out/acceptance.log" 2> "$out/acceptance.stderr"; then
              cat "$out/acceptance.stderr" >&2
              exit 1
            fi
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    };
  workflow = driver: {
    read-only = import ../../lib/testing/config-eval.nix {
      inherit pkgs driver fixture inputs;
      inherit (pkgs) lib;
      mkSystem = _: throw "evaluation fixture must not construct a system";
    };
    source-gc = import ../../lib/testing/config-source-gc.nix {
      pkgs = pkgs // {aos-package-evaluation-driver = driver;};
      inherit (pkgs) lib;
    };
    activation = activation driver;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit ordinary candidate compilation;
  workflows = {
    ordinary = workflow ordinary;
    bazel = workflow candidate;
  };
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert ordinary.platformSupport == candidate.platformSupport;
  assert ordinary.runtimeDeps == candidate.runtimeDeps;
    pkgs.runCommand "aos-bazel-package-evaluation-driver-selection" {} ''
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
    pkgs.runCommand "aos-bazel-package-evaluation-driver-installed-parity" {
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
      ${builtins.toJSON (builtins.mapAttrs (_: builtins.mapAttrs (_: toString)) workflows)}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_package_evaluation_driver.py \
        --packages packages.json --build ${compilation.build} --workspace ${compilation.workspace.source} \
        --package-paths package-paths.json --workflows workflows.json \
        --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-package-evaluation-driver-production-checks" {
      buildDeps = [driver-selection parity];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
}

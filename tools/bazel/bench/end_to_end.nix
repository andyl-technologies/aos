##! Benchmark-only boot package candidates retain the production install phases.
{
  root,
  mode,
  cacheNamespace,
  invocationNonce ? "",
}: let
  rootPath = /. + root;
  pkgs =
    (import rootPath {
      sharedBazelCacheDir =
        if mode == "bazel"
        then "/aos-build-cache/bazel"
        else null;
    }).pkgs;
  measureBuilder = derivation:
    builtins.derivation (derivation.drvAttrs
      // {
        measurementNonce = invocationNonce;
        builder = "${pkgs.python3}/bin/python3";
        args = [
          ./record_builder.py
          (pkgs.writeTextFile {
            name = "benchmark-builder-command.json";
            text = builtins.toJSON ([derivation.drvAttrs.builder] ++ derivation.drvAttrs.args);
          })
        ];
      });
  workspace = pkgs.mkAosBazelWorkspace {
    root = rootPath;
    sourceInventory = rootPath + "/tools/bazel/metadata/boot-pilot-inventory.json";
    analysisTargets = ["//crates/aos/boot/aos-boot-identity:package" "//crates/aos/boot/aos-boot-identity:unit"];
  };
  build = measureBuilder (pkgs.mkAosBazelBuild {
    pname = "aos-bazel-boot-measurement-build";
    inherit workspace cacheNamespace;
    targets = ["//crates/aos/boot/aos-boot-identity:package"];
  });
  tests = measureBuilder (pkgs.mkAosBazelCheck {
    pname = "aos-bazel-boot-measurement-tests";
    inherit workspace cacheNamespace;
    targets = ["//crates/aos/boot/aos-boot-identity:unit"];
  });
  package = pkgs.mkAosBazelPackage {
    pname = "aos-boot-identity";
    version = "0.1.0";
    inherit build;
    runtimeDeps = [pkgs.gcc-libs];
    packageLabel = "//crates/aos/boot/aos-boot-identity:package";
  };
  candidate = pkgs.aos-boot-identity.overrideAttrs (previous: {
    buildDeps = previous.buildDeps ++ [package tests pkgs.python3];
    runtimeDeps = previous.runtimeDeps ++ [pkgs.gcc-libs];
    phases = map (phase:
      if phase.name == "build"
      then {
        name = "build";
        script = ''
          cp ${package}/bin/aos-boot-identity aos-boot-identity
          mkdir -p "$out/nix-support"
          cp ${build}/nix-support/benchmark-resources.json "$out/nix-support/bazel-build-resources.json"
          cp ${tests}/nix-support/benchmark-resources.json "$out/nix-support/bazel-test-resources.json"
          ${pkgs.python3}/bin/python3 - "$out/nix-support" <<'PYTHON'
          import json
          from pathlib import Path
          import sys

          output = Path(sys.argv[1])
          # Retaining build command paths here would pull the JDK/compiler
          # into the installed runtime closure and corrupt that comparison.
          for name, source in [("build", "${build}"), ("test", "${tests}")]:
              measurements = {}
              for phase in ["metrics", "configured-discovery-metrics", "discovery-metrics"]:
                  record = json.loads((Path(source) / "evidence" / (phase + ".json")).read_text())
                  measurements[phase] = {key: record[key] for key in [
                      "wall_seconds", "user_seconds", "system_seconds", "peak_rss_kib",
                      "server_before", "server_after",
                  ]}
              (output / ("bazel-" + name + "-metrics.json")).write_text(json.dumps(measurements))
          PYTHON
        '';
      }
      else phase)
    previous.phases;
  });
in
  assert builtins.elem mode ["production" "bazel"];
    measureBuilder (
      if mode == "production"
      then pkgs.aos-boot-identity
      else candidate
    )

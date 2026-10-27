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
  rustcPackage = pkgs.aos-boot-identity.passthru.withBuildDriver "rustc";
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
  # Inject measurement at the production constructor's action boundary. Keep
  # its workspace, toolchain, targets, packaging, and runtime policy intact.
  candidate = pkgs.callPackage (rootPath + "/pkgs/security/_aos-boot-identity-bazel.nix") {
    inherit rustcPackage;
    mkAosBazelCheck = arguments:
      measureBuilder (pkgs.mkAosBazelCheck (arguments // {inherit cacheNamespace;}));
  };
  build = candidate.passthru.bazelBuild;
  measuredCandidate = candidate.overrideAttrs (previous: {
    buildDeps = previous.buildDeps ++ [pkgs.python3];
    phases = map (phase:
      if phase.name == "build"
      then
        phase
        // {
          script =
            phase.script
            + ''
              mkdir -p "$out/nix-support"
              cp ${build}/nix-support/benchmark-resources.json "$out/nix-support/bazel-action-resources.json"
              ${pkgs.python3}/bin/python3 - "$out/nix-support" <<'PYTHON'
              import json
              from pathlib import Path
              import sys

              output = Path(sys.argv[1])
              # Retaining build command paths here would pull the JDK/compiler
              # into the installed runtime closure and corrupt that comparison.
              measurements = {}
              for phase in ["metrics", "configured-discovery-metrics", "discovery-metrics"]:
                  record = json.loads((Path("${build}") / "evidence" / (phase + ".json")).read_text())
                  measurements[phase] = {key: record[key] for key in [
                      "wall_seconds", "user_seconds", "system_seconds", "peak_rss_kib",
                      "server_before", "server_after",
                  ]}
              # Compilation and all tests share one Bazel invocation. Record it
              # once, rather than presenting the same resources as two phases.
              (output / "bazel-action-metrics.json").write_text(json.dumps(measurements))
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
      then rustcPackage
      else measuredCandidate
    )

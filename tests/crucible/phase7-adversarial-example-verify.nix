{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.adversarialExampleVerify",
  taskIds ? ["T-EX-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  exampleDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" exampleDoc [
      {
        label = "T-EX-5 completion note";
        needle = "Completed by `checks.crucible.phase7.adversarialExampleVerify`";
      }
      {
        label = "adversarial verify remains documented";
        needle = "--runs N --adversarial";
      }
      {
        label = "divergence bisection remains documented";
        needle = "divergence-bisection";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "built-in scenario resolver";
        needle = "fn resolve_builtin_example_scenario";
      }
      {
        label = "built-in run scenario variant";
        needle = "RunScenarioRef::BuiltInExample";
      }
      {
        label = "fault campaign built-in verify sample";
        needle = "crucible::FAULT_CAMPAIGN_FAMILY_NAME";
      }
      {
        label = "randomized scheduler hostile profile";
        needle = "\"randomized-host-scheduler\"";
      }
      {
        label = "wall clock jitter hostile profile";
        needle = "\"wall-clock-jitter\"";
      }
      {
        label = "varied core count hostile profile";
        needle = "\"varied-core-count\"";
      }
      {
        label = "hostile profile applied to run plan";
        needle = "observer_profile: reduction.host_profile";
      }
      {
        label = "adversarial reduction expansion";
        needle = "VERIFY_HOSTILE_PROFILES";
      }
      {
        label = "built-in adversarial verify test";
        needle = "cli_verify_builtin_example_corpus_adversarial";
      }
      {
        label = "divergence report line";
        needle = "verify-divergence";
      }
      {
        label = "bisection state line";
        needle = "verify-bisect-state";
      }
      {
        label = "golden mismatch shape";
        needle = "mismatch=canonical-log+fingerprint-stream";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 adversarial example import";
        needle = "adversarialExampleVerify = import ./phase7-adversarial-example-verify.nix";
      }
      {
        label = "phase7 adversarial example attr path";
        needle = "checks.crucible.phase7.adversarialExampleVerify";
      }
      {
        label = "phase7 adversarial example task id";
        needle = "taskIds = [\"T-EX-5\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 adversarial example verify check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-adversarial-example-verify";
      version = "0";
      src = crucibleSrc;
      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];
      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-adversarial-example-verify";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-adversarial-example-verify-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-cli \
              cli_verify_builtin_example_corpus_adversarial \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-adversarial-example-verify-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-cli \
              cli_verify_workflow_localizes_divergence_and_writes_side_artifacts \
              -- --test-threads=1
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/nix-support"
            cat > "$out/nix-support/crucible-phase7-adversarial-example-verify.txt" <<REPORT
            attr=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            adversarial_profiles=${builtins.concatStringsSep "," [
              "randomized-host-scheduler"
              "wall-clock-jitter"
              "varied-core-count"
            ]}
            built_in_verify=true
            divergence_report_shape=golden-tested
            REPORT
          '';
        }
      ];
    }

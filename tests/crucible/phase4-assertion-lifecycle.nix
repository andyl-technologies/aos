{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionLifecycle",
  taskIds ? ["T-ASRT-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  lifecycleTest = builtins.readFile ../../crates/crucible/tests/assertion_lifecycle.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-12 completion note";
        needle = "Completed by `checks.crucible.phase4.assertionLifecycle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "passed terminal outcome";
        needle = "HostAssertionOutcomeKind::Passed";
      }
      {
        label = "lifecycle enum";
        needle = "pub enum PropertyLifecycleState";
      }
      {
        label = "lifecycle snapshot type";
        needle = "pub struct HostAssertionLifecycle";
      }
      {
        label = "outcome lifecycle field";
        needle = "pub lifecycle: PropertyLifecycleState";
      }
      {
        label = "lifecycle states accessor";
        needle = "pub fn lifecycle_states";
      }
      {
        label = "failing lifecycle transition";
        needle = "PropertyLifecycleState::Failing";
      }
      {
        label = "outcome lifecycle mapping";
        needle = "fn lifecycle_for_outcome_kind";
      }
      {
        label = "fail-only verdict disposition";
        needle = "HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail";
      }
      {
        label = "unified report outcomes";
        needle = ".chain(";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "public lifecycle export";
        needle = "PropertyLifecycleState";
      }
      {
        label = "public lifecycle snapshot export";
        needle = "HostAssertionLifecycle";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_lifecycle.rs" lifecycleTest [
      {
        label = "lifecycle progression test";
        needle = "lifecycle_states_progress_and_terminal_outcomes_distinguish_passed_from_satisfied";
      }
      {
        label = "edge outcome lifecycle test";
        needle = "edge_outcomes_carry_lifecycle_and_verdict_disposition";
      }
      {
        label = "never evaluated lifecycle test";
        needle = "empty_log_always_remains_declared_and_reports_never_evaluated";
      }
      {
        label = "passed outcome assertion";
        needle = "HostAssertionOutcomeKind::Passed";
      }
      {
        label = "satisfied lifecycle assertion";
        needle = "PropertyLifecycleState::Satisfied";
      }
      {
        label = "failing lifecycle assertion";
        needle = "PropertyLifecycleState::Failing";
      }
      {
        label = "declared lifecycle assertion";
        needle = "PropertyLifecycleState::Declared";
      }
      {
        label = "failure count assertion";
        needle = "only violated and fail-disposition outcomes fail the run";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 assertion lifecycle import";
        needle = "assertionLifecycle = import ./phase4-assertion-lifecycle.nix";
      }
      {
        label = "phase4 assertion lifecycle attr path";
        needle = "attrPath = \"checks.crucible.phase4.assertionLifecycle\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/assertion_lifecycle.rs" lifecycleTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 assertion-lifecycle check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-assertion-lifecycle";
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
            export CARGO_HOME="$TMPDIR/cargo"
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
          name = "run-assertion-lifecycle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-assertion-lifecycle-target" \
              -p crucible \
              --test assertion_lifecycle \
              --test host_side_assertions \
              --test guest_marker_assertions \
              --test assertion_log_fold \
              --test offline_assertion_checker \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            assertion_lifecycle=true
            RESULT
          '';
        }
      ];
    }

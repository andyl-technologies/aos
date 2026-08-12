{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionEvaluationTiming",
  taskIds ? ["T-ASRT-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  timingTest = builtins.readFile ../../crates/crucible/tests/assertion_evaluation_timing.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-10 completion note";
        needle = "Completed by `checks.crucible.phase4.assertionEvaluationTiming`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "previous real prefix tracking";
        needle = "last_prefix: Option<ConditionEventLogPrefix>";
      }
      {
        label = "deadline point insertion";
        needle = "observe_due_eventually_deadlines";
      }
      {
        label = "synthetic deadline point kind";
        needle = "AssertionDeadline";
      }
      {
        label = "deadline prefix point override";
        needle = "EventEvaluationPoint::assertion_deadline";
      }
      {
        label = "exact deadline expiry after property check";
        needle = "at.ticks >= obligation.deadline.ticks";
      }
      {
        label = "after-quiescence skipped during streaming";
        needle = "Property::AfterQuiescence { .. } => None";
      }
      {
        label = "after-quiescence finalized at terminal prefix";
        needle = "Property::AfterQuiescence { predicate }";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_evaluation_timing.rs" timingTest [
      {
        label = "synthetic deadline point test";
        needle = "eventually_evaluates_deadline_point_between_recorded_prefixes";
      }
      {
        label = "exact deadline event test";
        needle = "eventually_can_satisfy_at_exact_deadline_event_inside_later_prefix";
      }
      {
        label = "offline every-event replay test";
        needle = "offline_checker_observes_relevant_events_before_later_terminal_boundary";
      }
      {
        label = "synthetic deadline retained offset test";
        needle = "synthetic_deadline_prefix_preserves_retained_event_log_offset";
      }
      {
        label = "after-quiescence once test";
        needle = "after_quiescence_evaluates_once_at_terminal_prefix";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 assertion evaluation timing import";
        needle = "assertionEvaluationTiming = import ./phase4-assertion-evaluation-timing.nix";
      }
      {
        label = "phase4 assertion evaluation timing attr path";
        needle = "attrPath = \"checks.crucible.phase4.assertionEvaluationTiming\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/assertion_evaluation_timing.rs" timingTest [
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
  then throw "crucible phase4 assertion-evaluation-timing check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-assertion-evaluation-timing";
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
          name = "run-assertion-evaluation-timing";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-assertion-evaluation-timing-target" \
              -p crucible \
              --test assertion_evaluation_timing \
              --test host_side_assertions \
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
            assertion_evaluation_timing=true
            RESULT
          '';
        }
      ];
    }

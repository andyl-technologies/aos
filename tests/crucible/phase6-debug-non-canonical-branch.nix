{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.debugNonCanonicalBranch",
  taskIds ? ["T-DBG-6"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  debugDoc = builtins.readFile ../../docs/rfcs/0010-crucible/36-time-travel-debugging.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  branchTest = builtins.readFile ../../crates/crucible/tests/gate_debug_non_canonical_branch.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/36-time-travel-debugging.md" debugDoc [
      {
        label = "T-DBG-6 completion note";
        needle = "Completed by `checks.crucible.phase6.debugNonCanonicalBranch`";
      }
      {
        label = "debug-edit script wording";
        needle = "debug-edit script";
      }
      {
        label = "non-canonical branch wording";
        needle = "non-canonical debug branch";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-DBG-6 plan summary";
        needle = "`T-DBG-6` is green through `checks.crucible.phase6.debugNonCanonicalBranch`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "non-canonical branch API";
        needle = "pub fn debug_non_canonical_branch";
      }
      {
        label = "branch metadata map";
        needle = "non_canonical_debug_branches";
      }
      {
        label = "branch request";
        needle = "pub struct DebugNonCanonicalBranchRequest";
      }
      {
        label = "branch report";
        needle = "pub struct DebugNonCanonicalBranchReport";
      }
      {
        label = "branch action";
        needle = "pub enum DebugNonCanonicalBranchAction";
      }
      {
        label = "guest edit script";
        needle = "pub struct DebugEditScript";
      }
      {
        label = "fork marker";
        needle = "DebugNonCanonicalForkMarker";
      }
      {
        label = "live status";
        needle = "DebugNonCanonicalLiveStatus";
      }
      {
        label = "canonical identity proof";
        needle = "canonical_run_bit_identical";
      }
      {
        label = "oracle exclusion proof";
        needle = "excluded_from_oracles_and_artifacts";
      }
      {
        label = "single path proof";
        needle = "inside_virtual_time_single_execution_path";
      }
      {
        label = "ordinary fork shape proof";
        needle = "ordinary_fork_shape";
      }
      {
        label = "canonical projection filter";
        needle = "canonical_run_event_log_projection_without_debug_branches";
      }
      {
        label = "first action matching";
        needle = "matches_first_action";
      }
      {
        label = "missing trigger error";
        needle = "DebugNonCanonicalBranchMissingTriggerEvidence";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "catalog fork marker constructor";
        needle = "pub(crate) fn fork_marker";
      }
      {
        label = "catalog fork event payload";
        needle = "EventPayload::new(\"fork\"";
      }
      {
        label = "causal fork marker class";
        needle = "SchedulerEventLogClass::Causal";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "branch request export";
        needle = "DebugNonCanonicalBranchRequest";
      }
      {
        label = "branch report export";
        needle = "DebugNonCanonicalBranchReport";
      }
      {
        label = "branch trigger export";
        needle = "DebugNonCanonicalBranchTrigger";
      }
      {
        label = "guest edit export";
        needle = "DebugGuestEdit";
      }
      {
        label = "operator control export";
        needle = "DebugOperatorControlKind";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_debug_non_canonical_branch.rs" branchTest [
      {
        label = "main branch test";
        needle = "non_canonical_debug_branch_marks_and_preserves_canonical_run";
      }
      {
        label = "invalid trigger test";
        needle = "non_canonical_debug_branch_requires_matching_trigger_evidence";
      }
      {
        label = "operator continue branch test";
        needle = "operator_controlled_continue_branches_without_guest_edit_script";
      }
      {
        label = "replay unchanged assertion";
        needle = "assert_eq!(replay_before, replay_after)";
      }
      {
        label = "non-zero sequence assertion";
        needle = "Some(8)";
      }
      {
        label = "causal marker assertion";
        needle = "Some(SchedulerEventLogClass::Causal)";
      }
      {
        label = "fork kind assertion";
        needle = "Some(\"fork\")";
      }
      {
        label = "canonical proof assertion";
        needle = "proves_non_canonical_debug_branch";
      }
      {
        label = "script assertion";
        needle = "records_arbitrary_guest_edits_as_debug_script";
      }
      {
        label = "visible marker assertion";
        needle = "visibly_marks_non_canonical_fork";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green non-canonical debug branch gate";
        needle = "debugNonCanonicalBranch = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-DBG-6\"]";
      }
      {
        label = "scoped time-travel raw dependency";
        needle = "phase6.debugScopedTimeTravel.rawGate";
      }
      {
        label = "scoped time-travel green dependency";
        needle = "phase6.debugScopedTimeTravel";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_debug_non_canonical_branch.rs" branchTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 debug-non-canonical-branch check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-debug-non-canonical-branch";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

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
            : "$DEPENDENCIES"
            export CARGO_HOME="$TMPDIR/cargo-home"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-debug-non-canonical-branch";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-non-canonical-branch-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_debug_non_canonical_branch \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            open_tasks=${openTaskList}
            gate=gate:debug-non-canonical-branch
            branch=non-canonical-visible
            replay_oracle=excluded
            artifacts=not-seed-scenario-schedule
            script=debug-edit-script
            RESULT
          '';
        }
      ];
    }

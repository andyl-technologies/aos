{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.readOnlyDebugInspection",
  taskIds ? ["T-DBG-2"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  debugDoc = builtins.readFile ../../docs/rfcs/0010-crucible/36-time-travel-debugging.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  inspectionTest = builtins.readFile ../../crates/crucible/tests/gate_read_only_debug_inspection.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

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
        label = "T-DBG-2 checklist complete";
        needle = "- [x] **T-DBG-2**";
      }
      {
        label = "T-DBG-2 partial-evidence note";
        needle = "Completed under `checks.crucible.phase6.readOnlyDebugInspection`";
      }
      {
        label = "canonical causal byte identity";
        needle = "canonical causal subsequence is byte-identical";
      }
      {
        label = "observational debug entries";
        needle = "attach/inspect/detach are recorded only as observational entries";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "read-only inspection request";
        needle = "pub struct DebugReadOnlyInspectionRequest";
      }
      {
        label = "read-only inspection kind";
        needle = "pub enum DebugReadOnlyInspectionKind";
      }
      {
        label = "read-only inspection report";
        needle = "pub struct DebugReadOnlyInspectionReport";
      }
      {
        label = "read-only graph footprint";
        needle = "pub struct DebugReadOnlyInspectionFootprint";
      }
      {
        label = "checkpoint footprint";
        needle = "pub struct DebugReadOnlyCheckpointFootprint";
      }
      {
        label = "debug inspection API";
        needle = "pub fn read_only_debug_inspection";
      }
      {
        label = "immutable graph receiver";
        needle = "&self,\n        attach: &DebugAttachReport";
      }
      {
        label = "causal projection before";
        needle = "let causal_event_log_before = event_log_causal_projection(event_log);";
      }
      {
        label = "causal projection after";
        needle = "let causal_event_log_after = event_log_causal_projection(&event_log_with_observations);";
      }
      {
        label = "observational diagnostic generation";
        needle = "SchedulerEventLogEntry::diagnostic";
      }
      {
        label = "non-causal assertion helper";
        needle = "observational_entries_are_non_causal";
      }
      {
        label = "read-only proof helper";
        needle = "proves_read_only";
      }
      {
        label = "graph footprint before";
        needle = "let footprint_before =";
      }
      {
        label = "graph footprint after";
        needle = "let footprint_after =";
      }
      {
        label = "debugged event-log view";
        needle = "event_log_with_observations";
      }
      {
        label = "runtime icount footprint";
        needle = "attached_runtime_node_icounts";
      }
      {
        label = "runtime scheduler footprint";
        needle = "attached_runtime_scheduler";
      }
      {
        label = "requested time guard";
        needle = "requested_virtual_time_matches_checkpoint";
      }
      {
        label = "graph-derived observation time";
        needle = "let observation_time = footprint_before.virtual_time;";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "inspection request export";
        needle = "DebugReadOnlyInspectionRequest";
      }
      {
        label = "inspection kind export";
        needle = "DebugReadOnlyInspectionKind";
      }
      {
        label = "inspection report export";
        needle = "DebugReadOnlyInspectionReport";
      }
      {
        label = "inspection footprint export";
        needle = "DebugReadOnlyInspectionFootprint";
      }
      {
        label = "inspection checkpoint footprint export";
        needle = "DebugReadOnlyCheckpointFootprint";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_read_only_debug_inspection.rs" inspectionTest [
      {
        label = "read-only debug gate";
        needle = "debug_read_only_inspection_preserves_causal_log_and_virtual_time";
      }
      {
        label = "all inspection kinds covered";
        needle = "DebugReadOnlyInspectionKind::WatchpointValueRead";
      }
      {
        label = "read-only proof assertion";
        needle = "report.proves_read_only()";
      }
      {
        label = "virtual time unchanged assertion";
        needle = "report.virtual_time_unchanged()";
      }
      {
        label = "requested time matches checkpoint assertion";
        needle = "report.requested_virtual_time_matches_checkpoint()";
      }
      {
        label = "graph unchanged assertion";
        needle = "report.graph_unchanged()";
      }
      {
        label = "checkpoint recorded assertion";
        needle = "attached_checkpoint_recorded";
      }
      {
        label = "observational class assertion";
        needle = "entry.class() == EventClass::Observational";
      }
      {
        label = "diagnostic names assertion";
        needle = "\"debug.detach\"";
      }
      {
        label = "determinism comparison";
        needle = "compare_event_log_determinism(&no_debug_log, &report.event_log_with_observations)";
      }
      {
        label = "API-generated debugged log assertion";
        needle = "report.event_log_with_observations.len()";
      }
      {
        label = "observation timestamps use footprint time";
        needle = "entry.at() == report.footprint_before.virtual_time";
      }
      {
        label = "mismatched requested time is rejected";
        needle = "!mismatched_report.proves_read_only()";
      }
      {
        label = "mismatched requested time differs from entry time";
        needle = "entry.at() != mismatched_report.requested_virtual_time";
      }
      {
        label = "canonical byte equality assertion";
        needle = "comparison.expected().canonical_bytes()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "red read-only debug inspection gate";
        needle = "readOnlyDebugInspection = redBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "openTaskIds = [\"T-DBG-2\"]";
      }
      {
        label = "debug attach raw dependency";
        needle = "phase6.debugAttach.rawGate";
      }
      {
        label = "debug attach blocker dependency";
        needle = "phase6.debugAttach";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_read_only_debug_inspection.rs" inspectionTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
      {
        label = "causal debug entry assertion";
        needle = "EventClass::Causal";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 read-only-debug-inspection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-read-only-debug-inspection";
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
          name = "run-read-only-debug-inspection";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-read-only-debug-inspection-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_read_only_debug_inspection \
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
            status=complete
            evidence_scope=read-only-debug-model
            gate=gate:read-only-debug-inspection
            causal_subsequence=byte-identical
            debugger_entries=observational
            virtual_time=unchanged
            RESULT
          '';
        }
      ];
    }

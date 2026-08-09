{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogDivergenceBisect",
  taskIds ? ["T-OBS-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  determinismTest = builtins.readFile ../../crates/crucible/tests/event_log_determinism.rs;
  reproductionTest = builtins.readFile ../../crates/crucible/tests/assertion_violation_reproduction.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-8 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogDivergenceBisect`";
      }
      {
        label = "first causal entry completion note";
        needle = "node/icount, source, and kind directly from the log";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "causal divergence point type";
        needle = "pub struct EventLogCausalDivergencePoint";
      }
      {
        label = "divergence point raw index";
        needle = "pub raw_index: usize";
      }
      {
        label = "divergence point icount stamp";
        needle = "pub at: EventLogIcountStamp";
      }
      {
        label = "divergence point source";
        needle = "pub source: EventSource";
      }
      {
        label = "divergence point kind";
        needle = "pub kind: String";
      }
      {
        label = "expected-side localization field";
        needle = "pub expected_location: Option<EventLogCausalDivergencePoint>";
      }
      {
        label = "reproduced-side localization field";
        needle = "pub reproduced_location: Option<EventLogCausalDivergencePoint>";
      }
      {
        label = "mismatch first location helper";
        needle = "pub fn first_location(&self) -> Option<&EventLogCausalDivergencePoint>";
      }
      {
        label = "localization builds from event-log time";
        needle = "at: entry.entry.time().icount.clone()";
      }
      {
        label = "localization builds from source";
        needle = "source: entry.entry.source().clone()";
      }
      {
        label = "localization builds from kind";
        needle = "kind: entry.entry.event_payload().kind().to_owned()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "causal divergence point export";
        needle = "EventLogCausalDivergencePoint";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "bisection request localization field";
        needle = "pub first_different_causal_entry: Option<EventLogCausalDivergencePoint>";
      }
      {
        label = "divergence localization field";
        needle = "pub first_different_causal_entry: Option<EventLogCausalDivergencePoint>";
      }
      {
        label = "divergence uses comparator mismatch";
        needle = "let event_mismatch = event_log_comparison.mismatch().cloned();";
      }
      {
        label = "divergence uses first location";
        needle = ".and_then(|mismatch| mismatch.first_location().cloned())";
      }
      {
        label = "expected event selected by raw index";
        needle = ".and_then(|mismatch| mismatch.expected_raw_index)";
      }
      {
        label = "reproduced event selected by raw index";
        needle = ".and_then(|mismatch| mismatch.reproduced_raw_index)";
      }
      {
        label = "first icount comes from causal entry";
        needle = ".map(|entry| entry.at.icount)";
      }
      {
        label = "bisection request carries causal entry";
        needle = "first_different_causal_entry: first_different_causal_entry.clone()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_determinism.rs" determinismTest [
      {
        label = "node-local causal localization test";
        needle = "causal_mismatch_reports_first_differing_entry_coordinate";
      }
      {
        label = "test asserts node";
        needle = "expected_location.at.node.as_ref()";
      }
      {
        label = "test asserts icount";
        needle = "expected_location.at.icount";
      }
      {
        label = "test asserts source";
        needle = "expected_location.source";
      }
      {
        label = "test asserts kind";
        needle = "expected_location.kind.as_str()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_violation_reproduction.rs" reproductionTest [
      {
        label = "replay bisection localization test";
        needle = "violation_reproduction_bisection_reports_first_differing_causal_entry";
      }
      {
        label = "divergence exposes first causal entry";
        needle = ".first_different_causal_entry";
      }
      {
        label = "bisection request exposes first causal entry";
        needle = "bisection\n        .first_different_causal_entry";
      }
      {
        label = "replay path asserts first prefix";
        needle = "assert_eq!(divergence.first_different_prefix_len, 1)";
      }
      {
        label = "replay path asserts event icount";
        needle = "assert_eq!(divergence.first_different_icount, Some(icount(0)))";
      }
      {
        label = "replay path rejects smoothing";
        needle = "should not smooth the first causal mismatch";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 event log divergence bisect import";
        needle = "eventLogDivergenceBisect = import ./phase4-event-log-divergence-bisect.nix";
      }
      {
        label = "phase4 event log divergence bisect attr path";
        needle = "checks.crucible.phase4.eventLogDivergenceBisect";
      }
      {
        label = "phase4 event log divergence bisect task id";
        needle = "taskIds = [\"T-OBS-8\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_determinism.rs" determinismTest [
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
    ]
    ++ forbiddenFor "crates/crucible/tests/assertion_violation_reproduction.rs" reproductionTest [
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
  then throw "crucible phase4 event-log divergence-bisect check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-divergence-bisect";
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
          name = "run-event-log-divergence-bisect";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-divergence-bisect-target" \
              -p crucible \
              --test event_log_determinism \
              --test assertion_violation_reproduction \
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
            event_log_divergence_bisect=true
            first_differing_causal_entry=node-icount-source-kind
            bisection_input=event-log
            RESULT
          '';
        }
      ];
    }

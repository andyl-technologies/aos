{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostMarkerObservability",
  taskIds ? [],
  openTaskIds ? ["T-GHC-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  markerObservabilityTest = builtins.readFile ../../crates/crucible/tests/guest_host_marker_observability.rs;
  eventLogDeterminismTest = builtins.readFile ../../crates/crucible/tests/event_log_determinism.rs;
  pluginWhitebox = builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  defaultChecks = builtins.readFile ./default.nix;

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

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-9 remains open";
        needle = "- [ ] **T-GHC-9**";
      }
      {
        label = "T-GHC-9 partial-evidence note";
        needle = "Partial model evidence is provided by";
      }
      {
        label = "marker observability implementation note";
        needle = "`guest_host_marker_observability`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "whitebox marker semantic mapper";
        needle = "pub fn observable_event_from_whitebox_marker_payload";
      }
      {
        label = "assertion marker maps to guest assertion event";
        needle = "ObservableEvent::guest_assertion_marker";
      }
      {
        label = "coverage marker maps to coverage observation";
        needle = "ObservableEvent::coverage_marker";
      }
      {
        label = "random request excluded from observational markers";
        needle = "WhiteboxMarkerPayload::RandomRequest(_) => None";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "guest marker icount stamp";
        needle = "ObservableEventPayload::GuestMarker {\n            retired_icount,\n            node,\n            ..\n        }";
      }
      {
        label = "guest assertion marker icount stamp";
        needle = "ObservableEventPayload::GuestAssertionMarker {\n            retired_icount,\n            node,\n            ..\n        }";
      }
      {
        label = "coverage marker icount stamp";
        needle = "ObservableEventPayload::CoverageMarker {\n            retired_icount: execution_icount,\n            node,\n            ..\n        }";
      }
      {
        label = "observational event class";
        needle = "SchedulerEventLogClass::Observational";
      }
      {
        label = "causal projection strips observational entries";
        needle = "entry.class == SchedulerEventLogClass::Causal";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "plugin stamps marker with trap icount";
        needle = "marker_icount: event.current_icount()";
      }
      {
        label = "plugin keeps decoded marker payload";
        needle = "decoded_payload: WhiteboxMarkerPayload";
      }
      {
        label = "plugin records through marker sink";
        needle = "sink.record_whitebox_marker(&marker)";
      }
      {
        label = "plugin engine event-log sink test";
        needle = "whitebox_doorbell_records_decoded_marker_into_engine_event_log_sink";
      }
      {
        label = "engine-backed marker sink";
        needle = "struct EngineEventLogMarkerSink";
      }
      {
        label = "plugin sink maps decoded marker payload";
        needle = "crucible::observable_event_from_whitebox_marker_payload";
      }
      {
        label = "plugin sink appends to event log";
        needle = "append_entries(vec![entry])";
      }
      {
        label = "plugin sink causal projection empty";
        needle = "event_log_causal_projection(&sink.entries).is_empty()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_host_marker_observability.rs" markerObservabilityTest [
      {
        label = "observational icount stamp test";
        needle = "whitebox_marker_payloads_append_as_observational_icount_stamped_entries";
      }
      {
        label = "fingerprint neutrality test";
        needle = "whitebox_marker_entries_do_not_move_determinism_or_backend_fingerprint";
      }
      {
        label = "event-log append path";
        needle = "EventLog::new()";
      }
      {
        label = "observational class assertion";
        needle = "EventClass::Observational";
      }
      {
        label = "exact icount assertion";
        needle = "EventLogIcountStamp";
      }
      {
        label = "causal projection empty for markers";
        needle = "event_log_causal_projection(&append).is_empty()";
      }
      {
        label = "determinism comparison excludes markers";
        needle = "compare_event_log_determinism(&baseline_log, &marked_log)";
      }
      {
        label = "backend fingerprint neutrality witness";
        needle = "struct RunMaterial";
      }
      {
        label = "marker-neutral run material projection";
        needle = "causal_event_log_fingerprint";
      }
      {
        label = "changed backend material still moves fingerprint";
        needle = "changed-workload";
      }
      {
        label = "random request excluded from marker path";
        needle = "WhiteboxRandomRequestBody";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_determinism.rs" eventLogDeterminismTest [
      {
        label = "existing observational comparison proof";
        needle = "observational_verbosity_changes_do_not_change_causal_projection";
      }
      {
        label = "existing canonical bytes proof";
        needle = "comparison.expected().canonical_bytes()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 marker observability import";
        needle = "guestHostMarkerObservability = import ./phase4-guest-host-marker-observability.nix";
      }
      {
        label = "phase4 marker observability attr path";
        needle = "checks.crucible.phase4.guestHostMarkerObservability";
      }
      {
        label = "phase4 marker observability task id";
        needle = "openTaskIds = [\"T-GHC-9\"]";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host marker observability check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-marker-observability";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
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
          name = "run-guest-host-marker-observability";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-marker-observability-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_doorbell_records_decoded_marker_into_engine_event_log_sink \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-marker-observability-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test guest_host_marker_observability \
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
            open_tasks=${openTaskList}
            status=partial
            evidence_scope=marker-observation-model
            gate=gate:single-vm-fingerprint
            marker_event_log_class=observational
            marker_determinism_projection=causal-subsequence
            RESULT
          '';
        }
      ];
    }

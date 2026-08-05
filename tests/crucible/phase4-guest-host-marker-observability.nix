{
  pkgs,
  lib,
  liveWhitebox ? import ./phase2-qemu-live-whitebox-doorbell.nix {inherit pkgs lib;},
  attrPath ? "checks.crucible.phase4.guestHostMarkerObservability",
  taskIds ? ["T-GHC-9"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  markerObservabilityTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/guest_host_marker_observability.rs;
  };
  eventLogDeterminismTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/event_log_determinism.rs;
  };
  pluginWhitebox = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  };
  pluginWhiteboxTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/whitebox_doorbell/tests.rs;
  };
  pluginRuntime = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/runtime.rs;
  };
  pluginLiveWhitebox = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/runtime/live_whitebox.rs;
  };
  pluginLiveWhiteboxApi = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/runtime/live_whitebox/api.rs;
  };
  mappedQuantum = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/mapped_quantum.rs;
  };
  mappedQuantumTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/tests/mapped_quantum.rs;
  };
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-9 live completion evidence";
        needle = "`checks.crucible.phase2.qemuLiveWhiteboxDoorbell`";
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
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell/tests.rs" pluginWhiteboxTest [
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
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime.rs" pluginRuntime [
      {
        label = "mapped live marker ring binding";
        needle = "LiveWhiteboxError::MappedMarkerQueue";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime/live_whitebox.rs" pluginLiveWhitebox [
      {
        label = "live callback marker shmem enqueue";
        needle = ".enqueue_whitebox_marker(entries, entry)";
      }
      {
        label = "live callback marker producer";
        needle = "struct LiveWhiteboxMarkerShmemProducer";
      }
      {
        label = "dedicated doorbell execution callback";
        needle = "Some(crucible_qemu_plugin_live_whitebox_insn_exec_cb)";
      }
      {
        label = "x86 immediate-port instruction filter";
        needle = "WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime/live_whitebox/api.rs" pluginLiveWhiteboxApi [
      {
        label = "upstream QEMU execution callback binding";
        needle = "qemu_plugin_register_vcpu_insn_exec_cb";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/mapped_quantum.rs" mappedQuantum [
      {
        label = "host marker shmem dequeue";
        needle = ".dequeue_whitebox_marker(ring.entries)";
      }
      {
        label = "host canonical marker decode";
        needle = "decode_whitebox_marker_payload(&frame)";
      }
      {
        label = "host marker semantic mapping";
        needle = "observable_event_from_whitebox_marker_payload(";
      }
      {
        label = "host chronological observation merge";
        needle = "events.sort_by_key(ObservableEvent::at)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/mapped_quantum.rs" mappedQuantumTest [
      {
        label = "mapped marker event-log admission test";
        needle = "mapped_quantum_merges_whitebox_markers_into_the_unified_event_log";
      }
      {
        label = "mapped invalid marker rejection test";
        needle = "mapped_quantum_rejects_invalid_marker_timing_and_non_observational_kinds";
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
        needle = "taskIds = [\"T-GHC-9\"];\n      openTaskIds = [];";
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
      buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust pkgs.sed liveWhitebox];
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
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

            grep -Fxq PASS ${liveWhitebox}/result
            grep -Fxq 'marker_transport=plugin-to-host-shmem-spsc' ${liveWhitebox}/result
            grep -Fxq 'marker_host_consumer=quantum-boundary' ${liveWhitebox}/result
            grep -Fxq 'marker_event_log_admission=true' ${liveWhitebox}/result
            grep -Eq '^marker_icount=[1-9][0-9]*$' ${liveWhitebox}/result
            grep -Fxq 'off_on_fingerprint_equal=true' ${liveWhitebox}/result
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
            status=complete
            evidence_scope=marker-observation-model-and-live-production
            gate=gate:single-vm-fingerprint
            marker_event_log_class=observational
            marker_determinism_projection=causal-subsequence
            marker_transport=plugin-to-host-shmem-spsc
            marker_host_consumer=quantum-boundary
            live_off_on_fingerprint_equal=true
            RESULT
          '';
        }
      ];
    }

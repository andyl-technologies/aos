{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostChannelDeterminism",
  taskIds ? [],
  openTaskIds ? ["T-GHC-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginWhitebox = builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  channelDeterminismTest = builtins.readFile ../../crates/crucible/tests/guest_host_channel_determinism.rs;
  markerObservabilityTest = builtins.readFile ../../crates/crucible/tests/guest_host_marker_observability.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  phaseGate = builtins.readFile ./phase4-guest-host-channel-determinism.nix;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  forbiddenCallbackApis = [
    "Instant::now"
    "SystemTime::now"
    "std::time::Instant"
    "std::time::SystemTime"
    "thread::sleep"
    "park_timeout"
    "clock_gettime"
    "gettimeofday"
    "CLOCK_REALTIME"
    "CLOCK_MONOTONIC"
    "thread_rng"
    "rand::random"
    "Mutex"
    "RwLock"
    ".lock()"
  ];

  forbiddenCallbackFailures =
    lib.concatMap (
      api:
        lib.optionals (hasInfix api pluginWhitebox) [
          "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs: forbidden host-time, entropy, or lock API in white-box channel safety path: `${api}`"
        ]
    )
    forbiddenCallbackApis;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-12 remains open";
        needle = "- [ ] **T-GHC-12**";
      }
      {
        label = "T-GHC-12 partial-evidence note";
        needle = "Partial callback-core and scheduler-model evidence is provided by";
      }
      {
        label = "channel determinism implementation note";
        needle = "`guest_host_channel_determinism`";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "shared trap-icount payload reader";
        needle = "let payload = read_doorbell_payload(self, reader, event)?;";
      }
      {
        label = "payload read uses vcpu index";
        needle = "event.vcpu_index(),";
      }
      {
        label = "payload read uses current trap icount";
        needle = "event.current_icount(),";
      }
      {
        label = "payload read uses trap payload range";
        needle = "event.payload_range(),";
      }
      {
        label = "payload read length mismatch remains loud";
        needle = "GuestMemoryReadLengthMismatch";
      }
      {
        label = "snapshot-at-trap test";
        needle = "whitebox_channel_safety_reads_payload_snapshot_at_exact_trap_icount";
      }
      {
        label = "mutating reader proves snapshot";
        needle = "MutatingSnapshotGuestMemoryReader";
      }
      {
        label = "exact read call assertion";
        needle = "assert_eq!(reader.calls, vec![(3, 1234, range)])";
      }
      {
        label = "late mutation rejected by decoded marker";
        needle = "body.point == \"trap-snapshot\"";
      }
      {
        label = "host-to-guest explicit delivery test";
        needle = "whitebox_channel_safety_injects_host_to_guest_only_at_delivery_icount";
      }
      {
        label = "producer timing skew test";
        needle = "whitebox_channel_safety_ignores_producer_timing_before_delivery_icount";
      }
      {
        label = "producer timing equality assertion";
        needle = "assert_eq!(eager_writer.writes, just_in_time_writer.writes)";
      }
      {
        label = "not-ready before delivery";
        needle = "WhiteboxGuestInputOutcome::NotReady";
      }
      {
        label = "exact delivery injection";
        needle = "WhiteboxGuestInputOutcome::Delivered";
      }
      {
        label = "late delivery rejected";
        needle = "InputDeliveryAlreadyPassed";
      }
      {
        label = "app-random reply trap icount proof";
        needle = "whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_host_channel_determinism.rs" channelDeterminismTest [
      {
        label = "channel determinism test";
        needle = "whitebox_channel_fingerprints_are_identical_with_markers_on_vs_off";
      }
      {
        label = "disabled white-box policy witness";
        needle = "WhiteBoxPolicy::Disabled";
      }
      {
        label = "enabled white-box policy witness";
        needle = "WhiteBoxPolicy::Enabled";
      }
      {
        label = "scheduler-backed event log witness";
        needle = "SingleScheduler::new";
      }
      {
        label = "marker append through scheduler";
        needle = ".append_observable_events(marker_events())";
      }
      {
        label = "event-log determinism comparison";
        needle = "compare_event_log_determinism(&markers_off.event_log, &markers_on.event_log)";
      }
      {
        label = "causal event-log projection";
        needle = "event_log_causal_projection(&event_log).content_hash()";
      }
      {
        label = "backend fingerprint equality";
        needle = "markers_on.backend_fingerprint";
      }
      {
        label = "changed causal boundary still moves fingerprint";
        needle = "changed_causal";
      }
      {
        label = "changed workload still moves backend fingerprint";
        needle = "changed-workload";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_host_marker_observability.rs" markerObservabilityTest [
      {
        label = "prior marker observability fingerprint proof remains present";
        needle = "whitebox_marker_entries_do_not_move_determinism_or_backend_fingerprint";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 channel determinism import";
        needle = "guestHostChannelDeterminism = import ./phase4-guest-host-channel-determinism.nix";
      }
      {
        label = "phase4 channel determinism attr path";
        needle = "checks.crucible.phase4.guestHostChannelDeterminism";
      }
      {
        label = "phase4 channel determinism task id";
        needle = "openTaskIds = [\"T-GHC-12\"]";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-guest-host-channel-determinism.nix" phaseGate [
      {
        label = "phase gate runs plugin channel safety tests";
        needle = "--lib whitebox_channel_safety";
      }
      {
        label = "phase gate lists tests before filtered runs";
        needle = "-- --list";
      }
      {
        label = "phase gate requires listed tests";
        needle = "require_listed";
      }
      {
        label = "phase gate runs app-random trap icount proof";
        needle = "--lib whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount";
      }
      {
        label = "phase gate runs channel determinism test";
        needle = "--test guest_host_channel_determinism";
      }
      {
        label = "canonical gate wiring pointer";
        needle = "canonical_gate_wiring=checks.crucible.phase4.guestHostChannelGateWiring";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ]
    ++ forbiddenCallbackFailures;
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host channel determinism check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-channel-determinism";
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
          name = "run-guest-host-channel-determinism";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            require_listed() {
              listed="$1"
              test_name="$2"
              if [ -z "$(sed -n "/$test_name/p" "$listed")" ]; then
                printf 'missing expected test: %s\n' "$test_name" >&2
                exit 1
              fi
            }
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-channel-determinism-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib \
              -- --list > "$TMPDIR/plugin-tests"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_channel_safety_reads_payload_snapshot_at_exact_trap_icount"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_channel_safety_injects_host_to_guest_only_at_delivery_icount"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_channel_safety_ignores_producer_timing_before_delivery_icount"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-channel-determinism-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test guest_host_channel_determinism \
              -- --list > "$TMPDIR/channel-tests"
            require_listed \
              "$TMPDIR/channel-tests" \
              "whitebox_channel_fingerprints_are_identical_with_markers_on_vs_off"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-channel-determinism-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_channel_safety \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-channel-determinism-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-channel-determinism-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test guest_host_channel_determinism \
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
            evidence_scope=callback-core-and-scheduler-model
            spec_contracts=GHC-30,GHC-31,GHC-32
            payload_read=trap-icount-snapshot
            host_guest_direction=explicit-delivery-icount-producer-timing-invariant
            marker_fingerprint=scheduler-witness-identical-with-markers-on-vs-off
            canonical_gate_wiring=checks.crucible.phase4.guestHostChannelGateWiring
            RESULT
          '';
        }
      ];
    }

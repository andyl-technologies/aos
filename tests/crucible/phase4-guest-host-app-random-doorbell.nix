{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostAppRandomDoorbell",
  taskIds ? ["T-GHC-16"],
  openTaskIds ? [],
  phase0S5 ? import ./phase0-s5.nix {inherit pkgs lib;},
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  pluginWhitebox = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  };
  pluginCargo = builtins.readFile ../../crates/crucible-qemu-plugin/Cargo.toml;
  engineDecision = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/decision.rs;
  };
  engineModel = import ./_crucible-model-source.nix {inherit lib;};
  protocolDoorbellFrame = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-protocol/src/doorbell_frame.rs;
  };
  protocolDoorbellMarker = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-protocol/src/doorbell_marker.rs;
  };
  protocolAbiGate = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-protocol/tests/gate_abi_conformance.rs;
  };
  protocolGoldenTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-protocol/tests/golden_vectors.rs;
  };
  phase2AppRandomGate = builtins.readFile ./phase2-plugin-app-random-doorbell.nix;
  virtualMemorySpikeGate = builtins.readFile ./phase4-guest-host-virtual-memory-spike.nix;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  defaultChecks = builtins.readFile ./default.nix;
  virtualMemorySpike = import ./phase4-guest-host-virtual-memory-spike.nix {
    inherit pkgs lib phase0S5;
    attrPath = "checks.crucible.phase4.guestHostVirtualMemorySpike";
    taskIds = ["T-GHC-13"];
  };

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-16 callback and engine evidence";
        needle = "Callback-core and engine-model evidence is provided by";
      }
      {
        label = "random request kind table";
        needle = "5    random_request";
      }
      {
        label = "random request body";
        needle = "request_id:u32, width:u8 (<=8), lp_str stream_tag";
      }
      {
        label = "decode diagnostic and drop";
        needle = "decode diagnostic and dropped";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/doorbell_frame.rs" protocolDoorbellFrame [
      {
        label = "protocol version bumped for app-random";
        needle = "pub const WHITEBOX_DOORBELL_PROTOCOL_VERSION: u16 = 2;";
      }
      {
        label = "bounded frame decoder";
        needle = "pub fn decode_bounded(";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/doorbell_marker.rs" protocolDoorbellMarker [
      {
        label = "random request kind 5";
        needle = "pub const WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST: u16 = 5;";
      }
      {
        label = "random request width bound";
        needle = "pub const WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES: u8 = 8;";
      }
      {
        label = "random request payload variant";
        needle = "WhiteboxMarkerPayload::RandomRequest";
      }
      {
        label = "random request marker golden vector";
        needle = "name: \"random-request\"";
      }
      {
        label = "little-endian request id";
        needle = "request_id = reader.read_u32_le(\"request_id\")?;";
      }
      {
        label = "length-prefixed stream tag";
        needle = "let stream_tag = reader.read_lp_string(\"stream_tag\")?;";
      }
      {
        label = "invalid random width diagnostic";
        needle = "InvalidRandomWidth";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/gate_abi_conformance.rs" protocolAbiGate [
      {
        label = "doorbell frame golden-vector test";
        needle = "protocol_doorbell_frame_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "marker payload golden-vector test";
        needle = "protocol_doorbell_marker_payload_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "random request frame vector name";
        needle = "\"random-request-kind-5\"";
      }
      {
        label = "random request marker vector name";
        needle = "\"random-request\"";
      }
      {
        label = "random request semantic label";
        needle = "(5, \"app_random_request\")";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/golden_vectors.rs" protocolGoldenTest [
      {
        label = "golden-vector corpus includes random request frame";
        needle = "\"random-request-kind-5\"";
      }
      {
        label = "golden-vector corpus includes random request marker";
        needle = "\"random-request\"";
      }
    ]
    ++ failuresFor "crates/crucible/src/decision.rs" engineDecision [
      {
        label = "request-preserving app-random engine API";
        needle = "pub fn serve_app_random_request";
      }
      {
        label = "engine app-random records RNG draw";
        needle = "self.append_decision(Decision::RngDraw(RngDecision";
      }
      {
        label = "engine app-random records Decision::AppRandom";
        needle = "self.append_decision(Decision::AppRandom(AppRandomDecision";
      }
      {
        label = "engine app-random masks to width";
        needle = "let value = mask_to_width(raw_value, width);";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" engineModel [
      {
        label = "default name-hash stream constructor";
        needle = "pub fn from_name(name: impl Into<String>) -> Self";
      }
      {
        label = "app-random decision payload";
        needle = "pub struct AppRandomDecision";
      }
      {
        label = "app-random decision binary tag";
        needle = "Decision::AppRandom";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/Cargo.toml" pluginCargo [
      {
        label = "test-only engine dependency";
        needle = "Test-only HARN-16 cross-check";
      }
      {
        label = "production plugin deps stay L1-only";
        needle = "production plugin dependencies stay L1-only";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "app-random decision source trait";
        needle = "pub trait AppRandomDecisionSource";
      }
      {
        label = "plugin request parsed from random_request frame";
        needle = "AppRandomDoorbellRequest::from_frame";
      }
      {
        label = "shared bounded frame decoder";
        needle = "WhiteboxDoorbellFrame::decode_bounded";
      }
      {
        label = "shared random request payload decoder";
        needle = "WhiteboxMarkerPayload::RandomRequest";
      }
      {
        label = "guest memory request path";
        needle = "read_doorbell_payload";
      }
      {
        label = "trap icount reply construction";
        needle = "let reply = WhiteboxGuestInput::new(";
      }
      {
        label = "trap icount reply injection";
        needle = ".inject_guest_input(capability, writer, request.trap_icount(), &reply)";
      }
      {
        label = "malformed request dropped";
        needle = "AppRandomDoorbellOutcome::Dropped";
      }
      {
        label = "engine-backed decision source test";
        needle = "whitebox_app_random_decision_source_uses_engine_seeded_node_stream_name_hash";
      }
      {
        label = "same stream tag isolated by node";
        needle = "whitebox_app_random_decision_source_isolates_same_tag_by_node";
      }
      {
        label = "test-only engine adapter";
        needle = "struct EngineAppRandomDecisionSource";
      }
      {
        label = "engine adapter uses seeded recorder";
        needle = "crucible::DecisionRecorder::new(crucible::Configuration::genesis";
      }
      {
        label = "engine adapter uses node and stream tag";
        needle = "Self::stream_id(request.node_name(), request.stream_tag())";
      }
      {
        label = "engine stream name includes node and stream tag";
        needle = "\"app-random/node:{}:{}/stream:{}:{}\"";
      }
      {
        label = "engine adapter preserves guest request id";
        needle = "u64::from(request.guest_request_id())";
      }
      {
        label = "engine adapter records app-random";
        needle = "Some(crucible::Decision::AppRandom(decision))";
      }
      {
        label = "existing happy-path exact test";
        needle = "whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount";
      }
      {
        label = "existing malformed-drop exact test";
        needle = "whitebox_app_random_drops_malformed_request_without_decision_or_reply";
      }
      {
        label = "existing decoder diagnostics exact test";
        needle = "whitebox_app_random_decoder_rejects_bad_magic_version_kind_and_utf8";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-plugin-app-random-doorbell.nix" phase2AppRandomGate [
      {
        label = "phase2 random doorbell gate";
        needle = "doorbell_kind=random_request";
      }
      {
        label = "phase2 exact test coverage";
        needle = "whitebox_app_random_zero_requests_leave_no_decisions_or_replies";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-guest-host-virtual-memory-spike.nix" virtualMemorySpikeGate [
      {
        label = "S5 guest-memory evidence";
        needle = "check=checks.crucible.phase0.s5VirtualMemory";
      }
      {
        label = "app-random second client note";
        needle = "app-random";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 app-random doorbell import";
        needle = "guestHostAppRandomDoorbell = import ./phase4-guest-host-app-random-doorbell.nix";
      }
      {
        label = "phase4 app-random doorbell attr path";
        needle = "checks.crucible.phase4.guestHostAppRandomDoorbell";
      }
      {
        label = "phase4 app-random doorbell reuses phase0 S5 result";
        needle = "phase0S5 = phase0.s5VirtualMemory;";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "host entropy in app-random path";
        needle = "thread_rng";
      }
      {
        label = "host random in app-random path";
        needle = "rand::random";
      }
      {
        label = "wall clock in app-random path";
        needle = "SystemTime::now";
      }
      {
        label = "monotonic clock in app-random path";
        needle = "Instant::now";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 guest-host app-random doorbell check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-app-random-doorbell";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.grep
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
          name = "run-guest-host-app-random-doorbell";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            require_line() {
              result="$1"
              line="$2"
              grep -Fxq "$line" "$result" || {
                printf 'dependency missing evidence: %s\n' "$line" >&2
                cat "$result" >&2
                exit 1
              }
            }

            run_exact_test() {
              expected="$1"
              filter="$2"
              list_output=$(cargo test \
                --frozen \
                --offline \
                --target-dir "$TMPDIR/crucible-guest-host-app-random-doorbell-target" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
                -- --list 2>&1)
              exact_count=$(printf '%s\n' "$list_output" | grep -c "^$expected: test$" || true)
              if [ "$exact_count" -ne 1 ]; then
                printf '%s\n' "$list_output" >&2
                echo "expected exactly one test named $expected, found $exact_count" >&2
                exit 1
              fi

              test_output=$(cargo test \
                --frozen \
                --offline \
                --target-dir "$TMPDIR/crucible-guest-host-app-random-doorbell-target" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
                -- --exact --nocapture 2>&1)
              printf '%s\n' "$test_output"
              if ! printf '%s\n' "$test_output" | grep -F "test result: ok. 1 passed;" >/dev/null; then
                echo "exact test $expected did not report one passed test" >&2
                exit 1
              fi
            }

            virtual_memory_result="${virtualMemorySpike}/result"
            require_line "$virtual_memory_result" "PASS"
            require_line "$virtual_memory_result" "spike_dependency=checks.crucible.phase0.s5VirtualMemory"
            require_line "$virtual_memory_result" "app_random_reply_addressing=same-resolution-as-payload"

            run_exact_test \
              whitebox_doorbell::tests::whitebox_app_random_decision_source_uses_engine_seeded_node_stream_name_hash \
              whitebox_doorbell::tests::whitebox_app_random_decision_source_uses_engine_seeded_node_stream_name_hash
            run_exact_test \
              whitebox_doorbell::tests::whitebox_app_random_decision_source_isolates_same_tag_by_node \
              whitebox_doorbell::tests::whitebox_app_random_decision_source_isolates_same_tag_by_node
            run_exact_test \
              whitebox_doorbell::tests::whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount \
              whitebox_doorbell::tests::whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount
            run_exact_test \
              whitebox_doorbell::tests::whitebox_app_random_drops_malformed_request_without_decision_or_reply \
              whitebox_doorbell::tests::whitebox_app_random_drops_malformed_request_without_decision_or_reply
            run_exact_test \
              whitebox_doorbell::tests::whitebox_app_random_decoder_rejects_bad_magic_version_kind_and_utf8 \
              whitebox_doorbell::tests::whitebox_app_random_decoder_rejects_bad_magic_version_kind_and_utf8
            run_exact_test \
              whitebox_doorbell::tests::whitebox_app_random_rejects_request_id_mismatch_without_reply \
              whitebox_doorbell::tests::whitebox_app_random_rejects_request_id_mismatch_without_reply
            run_exact_test \
              whitebox_doorbell::tests::whitebox_guest_memory_addressing_app_random_reply_range_tracks_payload_resolution \
              whitebox_doorbell::tests::whitebox_guest_memory_addressing_app_random_reply_range_tracks_payload_resolution
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-doorbell-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_abi_conformance \
              protocol_doorbell_frame_golden_vectors_match_live_codec_bytes \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-doorbell-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_abi_conformance \
              protocol_doorbell_marker_payload_golden_vectors_match_live_codec_bytes \
              -- --exact --test-threads=1
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
            gate=gate:abi-conformance
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=partial
            evidence_scope=callback-core-and-engine-model
            doorbell_kind=random_request
            protocol_version=2
            kind=5
            max_width_bytes=8
            golden_vectors=random-request-kind-5,random-request
            decision=Decision::AppRandom
            decision_source=engine-seeded-name-hash-stream
            request_stream=RngStreamId::from_name(node-stream_tag-composite)
            reply=trap-icount-host-to-guest-injection
            malformed=decode-diagnostic-and-drop
            guest_memory_path=reuses-s5-addressing-decision
            RESULT
          '';
        }
      ];
    }

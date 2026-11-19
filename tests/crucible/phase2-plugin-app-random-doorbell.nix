{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginAppRandomDoorbell",
  taskIds ? [],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  pluginLib = builtins.readFile ../../crates/crucible/crucible-qemu-plugin/src/lib.rs;
  pluginWhitebox = builtins.readFile ../../crates/crucible/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  pluginWhiteboxTests = builtins.readFile ../../crates/crucible/crucible-qemu-plugin/src/whitebox_doorbell/tests.rs;
  protocolDoorbellFrame = builtins.readFile ../../crates/crucible/crucible-qemu-protocol/src/doorbell_frame.rs;
  protocolDoorbellMarker = builtins.readFile ../../crates/crucible/crucible-qemu-protocol/src/doorbell_marker.rs;
  determinismSpec = builtins.readFile ../../docs/engineering/crucible/determinism.md;
  pluginSpec = builtins.readFile ../../docs/engineering/crucible/qemu-plugin.md;
  ghcSpec = builtins.readFile ../../docs/engineering/crucible/guest-host-channel.md;
  execSpec = builtins.readFile ../../docs/engineering/crucible/execution-model.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

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
          "crates/crucible/crucible-qemu-plugin/src/whitebox_doorbell.rs: forbidden host-time, entropy, or lock API in app-random doorbell path: `${api}`"
        ]
    )
    forbiddenCallbackApis;

  failures =
    failuresFor "docs/engineering/crucible/determinism.md" determinismSpec [
      {
        label = "app-random doorbell check listed";
        needle = "`checks.crucible.phase2.qemuPluginAppRandomDoorbell`";
      }
      {
        label = "ambient fw_cfg entropy distinguished";
        needle = "`fw_cfg` entropy derived from the scenario seed";
      }
    ]
    ++ failuresFor "docs/engineering/crucible/qemu-plugin.md" pluginSpec [
      {
        label = "app-controlled random reply";
        needle = "app-controlled random value drawn from the seeded decision";
      }
      {
        label = "reply written at the trap count";
        needle = "`qemu_plugin_crucible_write_memory_vaddr` at the";
      }
      {
        label = "doorbell-free node behaves as black-box";
        needle = "A node that never rings the doorbell behaves exactly";
      }
    ]
    ++ failuresFor "docs/engineering/crucible/guest-host-channel.md" ghcSpec [
      {
        label = "random request kind table";
        needle = "5    random_request";
      }
      {
        label = "random request body";
        needle = "request_id:u32, width:u8 (<=8), lp_str stream_tag";
      }
      {
        label = "BackendRngEvidence requirement";
        needle = "BackendRngEvidence";
      }
      {
        label = "decode diagnostic and drop";
        needle = "decode diagnostic and dropped";
      }
    ]
    ++ failuresFor "docs/engineering/crucible/execution-model.md" execSpec [
      {
        label = "app-random decision payload";
        needle = "BackendRngEvidence { node, stream, request_id, width, value }";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "app-random handler exported";
        needle = "handle_whitebox_app_random_callback";
      }
      {
        label = "app-random decision source exported";
        needle = "BackendRngEvidenceSource";
      }
      {
        label = "app-random request exported";
        needle = "AppRandomDoorbellRequest";
      }
      {
        label = "app-random decision record exported";
        needle = "BackendRngEvidenceRecord";
      }
      {
        label = "app-random decode diagnostic exported";
        needle = "AppRandomDecodeDiagnostic";
      }
      {
        label = "app-random width constant exported";
        needle = "WHITEBOX_APP_RANDOM_MAX_WIDTH_BYTES";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "random request kind constant";
        needle = "WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST";
      }
      {
        label = "protocol version bump constant";
        needle = "WHITEBOX_DOORBELL_PROTOCOL_VERSION";
      }
      {
        label = "random request width bound";
        needle = "WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES";
      }
      {
        label = "shared marker decoder";
        needle = "decode_whitebox_marker_payload(&frame)";
      }
      {
        label = "shared random request payload";
        needle = "WhiteboxMarkerPayload::RandomRequest";
      }
      {
        label = "utf8 stream tag validation";
        needle = "InvalidUtf8StreamTag";
      }
      {
        label = "decision source trait";
        needle = "pub(crate) trait BackendRngEvidenceSource";
      }
      {
        label = "decision source records app-controlled randomness";
        needle = "Source that records and serves app-controlled randomness decisions.";
      }
      {
        label = "reads through guest memory API";
        needle = "read_guest_memory(";
      }
      {
        label = "reply at trap icount";
        needle = "request.trap_icount()";
      }
      {
        label = "host-to-guest input reuse";
        needle = "WhiteboxGuestInput::new(";
      }
      {
        label = "writes through delivery gate";
        needle = "inject_guest_input";
      }
      {
        label = "malformed frames dropped";
        needle = "AppRandomDoorbellOutcome::Dropped";
      }
      {
        label = "unmasked decision rejected";
        needle = "DecisionValueOutOfRange";
      }
      {
        label = "request id mismatch rejected";
        needle = "DecisionRequestIdMismatch";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-plugin/src/whitebox_doorbell/tests.rs" pluginWhiteboxTests [
      {
        label = "happy path exact test";
        needle = "whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount";
      }
      {
        label = "malformed drop exact test";
        needle = "whitebox_app_random_drops_malformed_request_without_decision_or_reply";
      }
      {
        label = "decode diagnostics exact test";
        needle = "whitebox_app_random_decoder_rejects_bad_magic_version_kind_and_utf8";
      }
      {
        label = "bad decision exact test";
        needle = "whitebox_app_random_rejects_unmasked_decision_value_without_reply";
      }
      {
        label = "request id mismatch exact test";
        needle = "whitebox_app_random_rejects_request_id_mismatch_without_reply";
      }
      {
        label = "zero request exact test";
        needle = "whitebox_app_random_zero_requests_leave_no_decisions_or_replies";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-protocol/src/doorbell_frame.rs" protocolDoorbellFrame [
      {
        label = "shared frame decoder";
        needle = "pub fn decode(bytes: &[u8])";
      }
      {
        label = "shared protocol version constant";
        needle = "pub const WHITEBOX_DOORBELL_PROTOCOL_VERSION: u16 = 3;";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-protocol/src/doorbell_marker.rs" protocolDoorbellMarker [
      {
        label = "protocol random request width bound";
        needle = "WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES";
      }
      {
        label = "protocol little endian request id";
        needle = "request_id = reader.read_u32_le(\"request_id\")?;";
      }
      {
        label = "protocol length-prefixed stream tag";
        needle = "let stream_tag = reader.read_lp_string(\"stream_tag\")?;";
      }
      {
        label = "protocol invalid random width diagnostic";
        needle = "InvalidRandomWidth";
      }
      {
        label = "protocol utf8 diagnostic";
        needle = "InvalidUtf8";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin app-random doorbell check";
        needle = "qemuPluginAppRandomDoorbell = import ./phase2-plugin-app-random-doorbell.nix";
      }
    ]
    ++ forbiddenCallbackFailures;
in
  if failures != []
  then throw "crucible phase2 plugin app-random doorbell check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-app-random-doorbell";
      version = "0";
      src = crucibleSrc;

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sqlite
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
          name = "run-plugin-app-random-doorbell";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            run_exact_test() {
              expected="$1"
              filter="$2"
              list_output=$(cargo test \
                --frozen \
                --offline \
                --target-dir "$TMPDIR/crucible-plugin-app-random-doorbell-target" \
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
                --target-dir "$TMPDIR/crucible-plugin-app-random-doorbell-target" \
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
              whitebox_doorbell::tests::whitebox_app_random_rejects_unmasked_decision_value_without_reply \
              whitebox_doorbell::tests::whitebox_app_random_rejects_unmasked_decision_value_without_reply
            run_exact_test \
              whitebox_doorbell::tests::whitebox_app_random_rejects_request_id_mismatch_without_reply \
              whitebox_doorbell::tests::whitebox_app_random_rejects_request_id_mismatch_without_reply
            run_exact_test \
              whitebox_doorbell::tests::whitebox_app_random_zero_requests_leave_no_decisions_or_replies \
              whitebox_doorbell::tests::whitebox_app_random_zero_requests_leave_no_decisions_or_replies
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
            gate=gate:layer0-determinism
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=complete
            doorbell_kind=random_request
            whitebox_opt_in=required
            decision=BackendRngEvidence
            source=seeded-decision-source-trait
            reply=trap-icount-host-to-guest-injection
            malformed=decode-diagnostic-and-drop
            zero_requests=no-decisions-no-replies
            zero_requests_byte_identical=true
            ambient_fw_cfg_entropy=not-app-random-source
            RESULT
          '';
        }
      ];
    }

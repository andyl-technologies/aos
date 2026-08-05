{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostAppRandomCap",
  taskIds ? ["T-GHC-17"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  engineModel = import ./_crucible-model-source.nix {inherit lib;};
  engineDecision = builtins.readFile ../../crates/crucible/src/decision.rs;
  channelDeterminismTest = builtins.readFile ../../crates/crucible/tests/guest_host_channel_determinism.rs;
  guestLib = builtins.readFile ../../crates/crucible-guest/src/lib.rs;
  guestMain = builtins.readFile ../../crates/crucible-guest/src/main.rs;
  guestAbiGate = builtins.readFile ../../crates/crucible-guest/tests/gate_abi_conformance.rs;
  phase2AppRandomGate = builtins.readFile ./phase2-plugin-app-random-doorbell.nix;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-17 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostAppRandomCap`";
      }
      {
        label = "scenario hash includes app-random cap";
        needle = "app-random draw cap into the scenario definition hash";
      }
      {
        label = "zero-request fingerprint proof documented";
        needle = "zero-request compiled-in-unused";
      }
      {
        label = "guest get-random verb documented";
        needle = "`crucible-guest get-random <width> [tag]`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" engineModel [
      {
        label = "default cap constant";
        needle = "pub const DEFAULT_APP_RANDOM_DRAW_CAP: u64 = u64::MAX;";
      }
      {
        label = "scenario cap field";
        needle = "app_random_draw_cap: u64";
      }
      {
        label = "scenario cap accessor";
        needle = "pub fn app_random_draw_cap(&self) -> u64";
      }
      {
        label = "cap-aware canonical constructor";
        needle = "from_canonical_material_with_seed_and_app_random_draw_cap";
      }
      {
        label = "cap-aware world helper";
        needle = "scenario_def_with_seed_and_app_random_draw_cap";
      }
      {
        label = "cap-aware scenario form constructor";
        needle = "from_components_with_app_random_draw_cap";
      }
      {
        label = "cap material helper";
        needle = "fn app_random_draw_cap_material";
      }
      {
        label = "cap material label";
        needle = "app_random_draw_cap={app_random_draw_cap}";
      }
      {
        label = "TOML serializes app-random cap";
        needle = "app_random_draw_cap: form.app_random_draw_cap";
      }
      {
        label = "binary serializes app-random cap";
        needle = "writer.write_u64(form.app_random_draw_cap);";
      }
      {
        label = "binary reads app-random cap";
        needle = "let app_random_draw_cap = reader.read_u64()?;";
      }
      {
        label = "checked step API";
        needle = "pub fn try_step(config: &Configuration, decision: Decision) -> Result<Configuration, EngineError>";
      }
      {
        label = "reduce validates app-random cap";
        needle = "validate_app_random_draw_cap(def, schedule)?;";
      }
      {
        label = "engine cap validation helper";
        needle = "fn validate_app_random_draw_cap";
      }
    ]
    ++ failuresFor "crates/crucible/src/decision.rs" engineDecision [
      {
        label = "app-random draw counter";
        needle = "app_random_draws: u64";
      }
      {
        label = "existing schedule count";
        needle = "count_app_random_draws(configuration.schedule.decisions())";
      }
      {
        label = "cap reservation helper";
        needle = "fn reserve_app_random_draw";
      }
      {
        label = "typed cap error";
        needle = "AppRandomDrawCapExceeded";
      }
      {
        label = "cap exceeded diagnostic";
        needle = "app-random draw {attempted} exceeds scenario cap {cap}";
      }
      {
        label = "request cap test";
        needle = "decision_recorder_enforces_app_random_draw_cap";
      }
      {
        label = "resume cap test";
        needle = "decision_recorder_counts_existing_app_random_decisions_against_cap";
      }
      {
        label = "override cap test";
        needle = "decision_recorder_app_random_override_obeys_draw_cap";
      }
      {
        label = "cap scenario hash test";
        needle = "app_random_draw_cap_is_scenario_hash_material";
      }
      {
        label = "cap scenario form serialization test";
        needle = "app_random_draw_cap_round_trips_through_scenario_form_serialization";
      }
      {
        label = "checked step and reduce cap test";
        needle = "app_random_draw_cap_fails_loud_in_checked_step_and_reduce";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_host_channel_determinism.rs" channelDeterminismTest [
      {
        label = "zero request test";
        needle = "app_random_compiled_in_zero_requests_is_fingerprint_identical";
      }
      {
        label = "disabled white-box witness";
        needle = "let disabled = run_channel_material";
      }
      {
        label = "compiled-in zero request witness";
        needle = "let compiled_in_zero = run_channel_material";
      }
      {
        label = "zero request marker mode";
        needle = "MarkerMode::Off";
      }
      {
        label = "zero request determinism material equality";
        needle = "disabled.determinism_material()";
      }
    ]
    ++ failuresFor "crates/crucible-guest/src/lib.rs" guestLib [
      {
        label = "usage exposes get-random";
        needle = "get-random <width> [tag]";
      }
      {
        label = "default random stream tag";
        needle = "CRUCIBLE_GUEST_DEFAULT_RANDOM_STREAM_TAG";
      }
      {
        label = "default request id";
        needle = "CRUCIBLE_GUEST_DEFAULT_RANDOM_REQUEST_ID";
      }
      {
        label = "typed get-random command";
        needle = "pub fn get_random";
      }
      {
        label = "get-random parser";
        needle = "fn parse_get_random";
      }
      {
        label = "single-source random payload";
        needle = "WhiteboxMarkerPayload::RandomRequest";
      }
      {
        label = "reply-bearing command outcome";
        needle = "GuestCommandOutcome::Random";
      }
    ]
    ++ failuresFor "crates/crucible-guest/src/main.rs" guestMain [
      {
        label = "main prints random reply";
        needle = "GuestCommandOutcome::Random";
      }
      {
        label = "random reply output";
        needle = "println!(\"{}\", hex_lower(&reply));";
      }
    ]
    ++ failuresFor "crates/crucible-guest/tests/gate_abi_conformance.rs" guestAbiGate [
      {
        label = "guest CLI shared payload test includes get-random";
        needle = "guest_cli_verbs_encode_shared_marker_payloads";
      }
      {
        label = "explicit tag get-random test";
        needle = "payload_from_args(&[\"get-random\", \"4\", \"workload\"])";
      }
      {
        label = "default tag get-random test";
        needle = "payload_from_args(&[\"get-random\", \"1\"])";
      }
      {
        label = "reply round-trip test";
        needle = "guest_get_random_round_trip_reads_reply_from_payload_range";
      }
      {
        label = "malformed width rejection";
        needle = "WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES + 1";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-plugin-app-random-doorbell.nix" phase2AppRandomGate [
      {
        label = "zero requests do not record decisions";
        needle = "zero_requests=no-decisions-no-replies";
      }
      {
        label = "zero requests byte-identical result";
        needle = "zero_requests_byte_identical=true";
      }
      {
        label = "plugin zero request test";
        needle = "whitebox_app_random_zero_requests_leave_no_decisions_or_replies";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 app-random cap import";
        needle = "guestHostAppRandomCap = import ./phase4-guest-host-app-random-cap.nix";
      }
      {
        label = "phase4 app-random cap attr path";
        needle = "checks.crucible.phase4.guestHostAppRandomCap";
      }
      {
        label = "phase4 app-random cap task id";
        needle = "taskIds = [\"T-GHC-17\"]";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host app-random cap check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-app-random-cap";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-app-random-cap";
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
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              -- --list > "$TMPDIR/crucible-lib-tests"
            require_listed \
              "$TMPDIR/crucible-lib-tests" \
              "decision::tests::decision_recorder_enforces_app_random_draw_cap"
            require_listed \
              "$TMPDIR/crucible-lib-tests" \
              "decision::tests::decision_recorder_counts_existing_app_random_decisions_against_cap"
            require_listed \
              "$TMPDIR/crucible-lib-tests" \
              "decision::tests::decision_recorder_app_random_override_obeys_draw_cap"
            require_listed \
              "$TMPDIR/crucible-lib-tests" \
              "decision::tests::app_random_draw_cap_is_scenario_hash_material"
            require_listed \
              "$TMPDIR/crucible-lib-tests" \
              "decision::tests::app_random_draw_cap_round_trips_through_scenario_form_serialization"
            require_listed \
              "$TMPDIR/crucible-lib-tests" \
              "decision::tests::app_random_draw_cap_fails_loud_in_checked_step_and_reduce"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test guest_host_channel_determinism \
              -- --list > "$TMPDIR/channel-tests"
            require_listed \
              "$TMPDIR/channel-tests" \
              "app_random_compiled_in_zero_requests_is_fingerprint_identical"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-guest \
              --test gate_abi_conformance \
              -- --list > "$TMPDIR/guest-abi-tests"
            require_listed \
              "$TMPDIR/guest-abi-tests" \
              "guest_cli_verbs_encode_shared_marker_payloads"
            require_listed \
              "$TMPDIR/guest-abi-tests" \
              "guest_get_random_round_trip_reads_reply_from_payload_range"
            require_listed \
              "$TMPDIR/guest-abi-tests" \
              "guest_cli_rejects_malformed_inputs"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib decision::tests::decision_recorder_enforces_app_random_draw_cap \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib decision::tests::decision_recorder_counts_existing_app_random_decisions_against_cap \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib decision::tests::decision_recorder_app_random_override_obeys_draw_cap \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib decision::tests::app_random_draw_cap_is_scenario_hash_material \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib decision::tests::app_random_draw_cap_round_trips_through_scenario_form_serialization \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib decision::tests::app_random_draw_cap_fails_loud_in_checked_step_and_reduce \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test guest_host_channel_determinism \
              app_random_compiled_in_zero_requests_is_fingerprint_identical \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-guest \
              --test gate_abi_conformance \
              guest_cli_verbs_encode_shared_marker_payloads \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-guest \
              --test gate_abi_conformance \
              guest_get_random_round_trip_reads_reply_from_payload_range \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-app-random-cap-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-guest \
              --test gate_abi_conformance \
              guest_cli_rejects_malformed_inputs \
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
            tasks=${taskList}
            app_random_draw_cap=scenario-hash-material
            cap_exceeded=typed-error
            zero_requests=disabled-vs-compiled-in-unused-fingerprint-identical
            guest_verb=get-random
            guest_abi=single-source-doorbell
            RESULT
          '';
        }
      ];
    }

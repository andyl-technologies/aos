{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiEpochGuards",
  taskIds ? ["T-API-8"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  apiDoc = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  lifecycle = builtins.readFile ../../crates/crucible-api/src/lifecycle.rs;
  streaming = builtins.readFile ../../crates/crucible-api/src/streaming.rs;
  client = builtins.readFile ../../crates/crucible-api/src/client.rs;
  epochGuardTest = builtins.readFile ../../crates/crucible-api/tests/gate_epoch_guards.rs;
  controlClientTest = builtins.readFile ../../crates/crucible-api/tests/gate_control_client.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-8 completion note";
        needle = "Completed by `checks.crucible.phase5.apiEpochGuards`";
      }
      {
        label = "T-API-9 completion note";
        needle = "Completed by `checks.crucible.phase5.apiReproductionContext`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API epoch guard status note";
        needle = "`T-API-8` is green through `checks.crucible.phase5.apiEpochGuards`";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lifecycle.rs" lifecycle [
      {
        label = "DestroySession expected epoch field";
        needle = "pub expected_epoch: Option<u64>";
      }
      {
        label = "DestroySession expected epoch builder";
        needle = "with_expected_epoch";
      }
      {
        label = "server-monotonic epoch allocator";
        needle = "self.next_epoch = self.next_epoch.saturating_add(1)";
      }
      {
        label = "lifecycle epoch mismatch error";
        needle = "LifecycleApiError::EpochMismatch";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/streaming.rs" streaming [
      {
        label = "AttachRequest expected epoch";
        needle = "pub expected_epoch: Option<u64>";
      }
      {
        label = "SendRequest expected epoch";
        needle = "pub expected_epoch: Option<u64>";
      }
      {
        label = "streaming expected epoch validation";
        needle = "expected != self.session.epoch";
      }
      {
        label = "streaming epoch mismatch error";
        needle = "StreamingApiError::EpochMismatch";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" client [
      {
        label = "typed RPC error decoder";
        needle = "decode_error_response";
      }
      {
        label = "typed invalid-state RPC status";
        needle = "RpcStatusCode::InvalidState";
      }
      {
        label = "streaming epoch mismatch reason";
        needle = ''"streaming-epoch-mismatch"'';
      }
      {
        label = "DestroySession RPC expected epoch encoding";
        needle = "encode_destroy_session_request";
      }
      {
        label = "DestroySession RPC expected epoch wire field";
        needle = ''"expected-epoch"'';
      }
      {
        label = "Attach RPC expected epoch encoding";
        needle = "request.expected_epoch";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_epoch_guards.rs" epochGuardTest [
      {
        label = "fast-fail mutation test";
        needle = "epoch_guards_fast_fail_without_state_or_event_log_mutation";
      }
      {
        label = "stale SessionRef test";
        needle = "stale_session_ref_epoch_detects_recycled_identity_before_dispatch";
      }
      {
        label = "server-monotonic epoch test";
        needle = "session_epoch_is_server_monotonic_and_closed_protocol_identity";
      }
      {
        label = "event-log cursor unchanged proof";
        needle = "streaming.event_log().current_cursor(), before_cursor";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" controlClientTest [
      {
        label = "RPC destroy expected epoch coverage";
        needle = "with_expected_epoch(inline_created.session.epoch)";
      }
      {
        label = "RPC Watch stale epoch typed error";
        needle = "RPC Watch attach stale epoch should be typed";
      }
      {
        label = "RPC Send stale epoch typed error";
        needle = "RPC Send stale epoch should be typed";
      }
      {
        label = "RPC Destroy stale epoch typed error";
        needle = "RPC DestroySession stale epoch should be typed";
      }
      {
        label = "RPC lifecycle typed precondition encoder";
        needle = "lifecycle_epoch_mismatch_response";
      }
      {
        label = "RPC streaming typed session closed encoder";
        needle = "streaming_epoch_mismatch_response";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API epoch guards check";
        needle = "apiEpochGuards = import ./phase5-api-epoch-guards.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-epoch-guards";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_8_FAILURES = failureText;
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;
    DEPENDENCY_COUNT = toString (builtins.length dependencies);
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
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
        name = "run-phase5-api-epoch-guards";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_8_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_8_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-epoch-guards-target" \
            -p crucible-api \
            --test gate_epoch_guards \
            -- --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 API epoch guard gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }

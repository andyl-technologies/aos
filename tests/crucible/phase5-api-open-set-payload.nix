{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiOpenSetPayload",
  taskIds ? ["T-API-5"],
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
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  apiClient = builtins.readFile ../../crates/crucible-api/src/client.rs;
  openSet = builtins.readFile ../../crates/crucible-api/src/open_set.rs;
  rpcAbi = builtins.readFile ../../crates/crucible-api/src/rpc_abi.rs;
  abiTest = builtins.readFile ../../crates/crucible-api/tests/gate_abi_conformance.rs;
  openSetTest = builtins.readFile ../../crates/crucible-api/tests/gate_open_set_payload.rs;
  controlClientTest = builtins.readFile ../../crates/crucible-api/tests/gate_control_client.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-5 completion note";
        needle = "Completed by `checks.crucible.phase5.apiOpenSetPayload`";
      }
      {
        label = "T-API-6 completion note";
        needle = "Completed by `checks.crucible.phase5.apiStreamingCursor`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API open-set status note";
        needle = "`T-API-5` is green through `checks.crucible.phase5.apiOpenSetPayload`";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "open-set module exported";
        needle = "pub mod open_set";
      }
      {
        label = "open-set capability re-exported";
        needle = "current_open_set_capabilities";
      }
      {
        label = "open-set validator re-exported";
        needle = "validate_open_set_send_payload";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/open_set.rs" openSet [
      {
        label = "open-set payload type";
        needle = "pub struct OpenSetPayload";
      }
      {
        label = "typed attribute map";
        needle = "pub enum OpenSetAttributeValue";
      }
      {
        label = "event-log catalog reuse";
        needle = "event_kind_catalog()";
      }
      {
        label = "opaque unknown event handling";
        needle = "ReceivedOpenSetEventPayload::Opaque";
      }
      {
        label = "typed unsupported send error";
        needle = "UnsupportedKind";
      }
      {
        label = "typed invalid argument send error";
        needle = "InvalidArgument";
      }
      {
        label = "event envelope conversion";
        needle = "open_set_event_envelope_from_entry";
      }
      {
        label = "dotted command parser";
        needle = "session_command_for_open_set_command_kind";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" apiClient [
      {
        label = "RPC send emits open-set command kind";
        needle = "open_set_command_kind(command_kind)";
      }
      {
        label = "RPC send parses open-set command kind";
        needle = "session_command_for_open_set_command_kind(command_kind)";
      }
      {
        label = "RPC capabilities parse open-set command kind";
        needle = "command_name_from_open_set_kind";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/rpc_abi.rs" rpcAbi [
      {
        label = "Hello advertises command category";
        needle = "crucible.cmd.*";
      }
      {
        label = "Hello advertises event category";
        needle = "crucible.event.*";
      }
      {
        label = "golden command kind is dotted";
        needle = "crucible.cmd.continue";
      }
      {
        label = "golden event kind uses catalog namespace";
        needle = "crucible.event.fault_activated";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_abi_conformance.rs" abiTest [
      {
        label = "ABI test expects open-set categories";
        needle = "crucible.fault.*";
      }
      {
        label = "ABI test expects catalog event kind";
        needle = "event-fault-activated";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_open_set_payload.rs" openSetTest [
      {
        label = "capability coverage";
        needle = "assert_capabilities_advertise_dotted_categories_and_kinds";
      }
      {
        label = "event catalog reuse coverage";
        needle = "assert_event_payload_conversion_reuses_event_log_catalog";
      }
      {
        label = "opaque unknown event coverage";
        needle = "assert_unknown_event_kinds_are_opaque";
      }
      {
        label = "send rejection coverage";
        needle = "assert_send_validation_uses_typed_unsupported_and_invalid_argument";
      }
      {
        label = "open-set command parse coverage";
        needle = "session_command_for_open_set_command_kind(\"crucible.cmd.continue\")";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" controlClientTest [
      {
        label = "test server emits open-set command kinds";
        needle = "open_set_command_kind(capability.command_kind)";
      }
      {
        label = "test server parses open-set command kinds";
        needle = "session_command_for_open_set_command_kind(command_kind_wire)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API open-set payload check";
        needle = "apiOpenSetPayload = import ./phase5-api-open-set-payload.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-open-set-payload";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_5_FAILURES = failureText;
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
        name = "run-phase5-api-open-set-payload";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_5_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_5_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-open-set-payload-target" \
            -p crucible-api \
            --test gate_open_set_payload \
            -- --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 API open-set payload gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }

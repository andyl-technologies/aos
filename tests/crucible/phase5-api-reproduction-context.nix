{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiReproductionContext",
  taskIds ? ["T-API-9"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  apiDoc = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  lifecycle = builtins.readFile ../../crates/crucible-api/src/lifecycle.rs;
  streaming = builtins.readFile ../../crates/crucible-api/src/streaming.rs;
  client = builtins.readFile ../../crates/crucible-api/src/client.rs;
  session = builtins.readFile ../../crates/crucible-session/src/lib.rs;
  reproductionTest = builtins.readFile ../../crates/crucible-api/tests/gate_reproduction_context.rs;
  controlClientTest = builtins.readFile ../../crates/crucible-api/tests/gate_control_client.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-9 checked off";
        needle = "- [x] **T-API-9**";
      }
      {
        label = "T-API-9 completion note";
        needle = "Completed by `checks.crucible.phase5.apiReproductionContext`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API reproduction context status note";
        needle = "`T-API-9` is green through `checks.crucible.phase5.apiReproductionContext`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "session reproduction log";
        needle = "pub struct SessionReproductionLog";
      }
      {
        label = "session control payload";
        needle = "pub enum SessionControlPayload";
      }
      {
        label = "event-log sequence before command";
        needle = "event_log_sequence_before";
      }
      {
        label = "recorded command result";
        needle = "pub enum SessionControlResult";
      }
      {
        label = "actor reproduction publication";
        needle = "sync_reproduction_log";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lifecycle.rs" lifecycle [
      {
        label = "GetReproduction request";
        needle = "pub struct GetReproductionRequest";
      }
      {
        label = "GetReproduction response";
        needle = "pub struct GetReproductionResponse";
      }
      {
        label = "API reproduction record";
        needle = "pub struct ReproductionCommandRecord";
      }
      {
        label = "API command payload field";
        needle = "pub command_payload: String";
      }
      {
        label = "API scheduler control payload material";
        needle = "pub scheduler_control: Option<String>";
      }
      {
        label = "at-sequence field";
        needle = "pub at_sequence: u64";
      }
      {
        label = "observational ordering aid";
        needle = "pub observational_order: u64";
      }
      {
        label = "lifecycle GetReproduction method";
        needle = "pub fn get_reproduction";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/streaming.rs" streaming [
      {
        label = "attach snapshot reproduction stream";
        needle = "pub reproduction: Vec<ReproductionCommandRecord>";
      }
      {
        label = "streaming reproduction log handle";
        needle = "reproduction_log: SessionReproductionLog";
      }
      {
        label = "snapshot copies reproduction context";
        needle = "map(ReproductionCommandRecord::from)";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" client [
      {
        label = "ControlClient GetReproduction method";
        needle = "fn get_reproduction";
      }
      {
        label = "RPC GetReproduction path";
        needle = "GET_REPRODUCTION_RPC_PATH";
      }
      {
        label = "RPC GetReproduction request encoder";
        needle = "encode_get_reproduction_request";
      }
      {
        label = "RPC GetReproduction response decoder";
        needle = "decode_get_reproduction_response";
      }
      {
        label = "attach reproduction wire field";
        needle = ''"reproduction="'';
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "GetReproduction request re-export";
        needle = "GetReproductionRequest";
      }
      {
        label = "reproduction record re-export";
        needle = "ReproductionCommandRecord";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_reproduction_context.rs" reproductionTest [
      {
        label = "read-only attach snapshot test";
        needle = "reproduction_context_is_read_only_and_visible_on_attach_snapshot";
      }
      {
        label = "interactive scripted equivalence test";
        needle = "interactive_and_scripted_same_schedule_reproduce_equivalently";
      }
      {
        label = "virtual-time key assertion";
        needle = "record.virtual_time";
      }
      {
        label = "at-sequence assertion";
        needle = "record.at_sequence";
      }
      {
        label = "command payload assertion";
        needle = "record.payload.command_payload";
      }
      {
        label = "observational ordering aid assertion";
        needle = "record.observational_order";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" controlClientTest [
      {
        label = "RPC GetReproduction coverage";
        needle = "RPC GetReproduction should decode";
      }
      {
        label = "RPC attach reproduction snapshot coverage";
        needle = "snapshot.reproduction.clone";
      }
      {
        label = "RPC stale GetReproduction typed error";
        needle = "RPC GetReproduction stale epoch should be typed";
      }
      {
        label = "RPC fault reproduction payload coverage";
        needle = "RPC fault reproduction should decode";
      }
      {
        label = "RPC command payload wire encoder";
        needle = "command_payload_material_wire";
      }
      {
        label = "HTTP/2 GetReproduction handler";
        needle = "handle_get_reproduction";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "at-sequence regression test";
        needle = "boundary_control_at_sequence_is_before_scheduler_control_events";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API reproduction context check";
        needle = "apiReproductionContext = import ./phase5-api-reproduction-context.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-reproduction-context";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_9_FAILURES = failureText;
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
        name = "run-phase5-api-reproduction-context";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_9_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_9_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-reproduction-context-target" \
            -p crucible-api \
            --test gate_reproduction_context \
            -- --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 API reproduction-context gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }

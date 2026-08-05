{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiSessionCommandMapping",
  taskIds ? ["T-API-2"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  apiDoc = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  sessionMapping = builtins.readFile ../../crates/crucible-api/src/session_mapping.rs;
  sessionMappingTest = builtins.readFile ../../crates/crucible-api/tests/gate_session_mapping.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-2 completion note";
        needle = "Completed by `checks.crucible.phase5.apiSessionCommandMapping`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API session mapping status note";
        needle = "`T-API-2` is green through `checks.crucible.phase5.apiSessionCommandMapping`";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "session mapping module exported";
        needle = "pub mod session_mapping";
      }
      {
        label = "session mapping validator re-exported";
        needle = "validate_thin_api_mapping";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/session_mapping.rs" sessionMapping [
      {
        label = "API method enum";
        needle = "pub enum ApiMethod";
      }
      {
        label = "API method mapping table";
        needle = "pub const API_METHOD_MAPPINGS";
      }
      {
        label = "API command mapping table";
        needle = "pub const API_COMMAND_MAPPINGS";
      }
      {
        label = "typed programmatic request shape";
        needle = "ApiRequestShape::TypedProgrammatic";
      }
      {
        label = "no browser-shaped request acceptance";
        needle = "is_browser_shaped";
      }
      {
        label = "create maps to Start";
        needle = "startup: SessionCommandKind::Start";
      }
      {
        label = "list sessions maps to mirror";
        needle = "query: LiveQueryKind::Status";
      }
      {
        label = "destroy maps to Stop";
        needle = "command: SessionCommandKind::Stop";
      }
      {
        label = "control stream one command per envelope";
        needle = "ApiDispatch::ControlStream";
      }
      {
        label = "send one command per envelope";
        needle = "ApiDispatch::SendEnvelope";
      }
      {
        label = "complete session command coverage";
        needle = "for command in SessionCommandKind::ALL";
      }
      {
        label = "thin validator";
        needle = "pub fn validate_thin_api_mapping";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_session_mapping.rs" sessionMappingTest [
      {
        label = "thin wrapper validation test";
        needle = "api_session_mapping_validates_thin_wrapper_contract";
      }
      {
        label = "command coverage test";
        needle = "api_mapping_covers_every_session_command_kind_exactly_once";
      }
      {
        label = "method mapping test";
        needle = "api_methods_are_thin_programmatic_mappings";
      }
      {
        label = "representative command roundtrip";
        needle = "representative_session_commands_round_trip_through_existing_session_set";
      }
      {
        label = "control/send cardinality test";
        needle = "control_and_send_dispatch_one_session_command_per_envelope";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API session command mapping check";
        needle = "apiSessionCommandMapping = import ./phase5-api-session-command-mapping.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-session-command-mapping";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_2_FAILURES = failureText;
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
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
        '';
      }
      {
        name = "run-phase5-api-session-command-mapping";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_2_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_2_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-session-command-mapping-target" \
            -p crucible-api \
            --test gate_session_mapping \
            -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          set -eu

          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'check=%s\n' "$ATTR_PATH"
            printf 'tasks=%s\n' "$TASK_IDS"
            printf 'dependency_count=%s\n' "$DEPENDENCY_COUNT"
            printf 'method_mapping=thin_session_wrapper\n'
            printf 'request_shape=typed_programmatic\n'
            printf 'command_mapping=session_command_kind_all\n'
          } > "$out/result"
        '';
      }
    ];
  }

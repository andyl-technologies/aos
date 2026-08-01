{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliServeMaxSessions",
  taskIds ? ["T-CLI-14"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  lifecycle = builtins.readFile ../../crates/crucible-api/src/lifecycle.rs;
  apiServer = builtins.readFile ../../crates/crucible-api/src/server.rs;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-14 max-sessions completion note";
        needle = "`checks.crucible.phase5.cliServeMaxSessions`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI serve max-sessions completion note";
        needle = "`checks.crucible.phase5.cliServeMaxSessions`";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lifecycle.rs" lifecycle [
      {
        label = "session cap field";
        needle = "max_sessions: Option<usize>";
      }
      {
        label = "session cap builder";
        needle = "pub const fn with_max_sessions";
      }
      {
        label = "session limit error";
        needle = "SessionLimitReached";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/server.rs" apiServer [
      {
        label = "typed session-limit response";
        needle = "\"session-limit\"";
      }
      {
        label = "server session-limit test";
        needle = "server_create_session_limit_maps_to_typed_rpc_error";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "serve max-sessions flag";
        needle = "max_sessions: Option<usize>";
      }
      {
        label = "serve zero max-sessions rejection";
        needle = "--max-sessions must be greater than zero";
      }
      {
        label = "serve validation helper";
        needle = "fn validate_serve_invocation";
      }
      {
        label = "serve zero max-sessions production-path test";
        needle = "run_serve_invocation(&zero_max_sessions_run";
      }
      {
        label = "serve max-sessions control-plane plumbing";
        needle = "control_plane.with_max_sessions(max_sessions)";
      }
      {
        label = "serve help advertises max-sessions";
        needle = "--max-sessions <n>";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI serve max-sessions check";
        needle = "cliServeMaxSessions = import ./phase5-cli-serve-max-sessions.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI serve max-sessions check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-serve-max-sessions";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

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
          name = "run-cli-serve-max-sessions";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-serve-max-sessions-target" \
              -p crucible-api \
              create_session_respects_live_session_limit \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-serve-max-sessions-target" \
              -p crucible-api \
              server_create_session_limit \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-serve-max-sessions-target" \
              -p crucible-cli \
              cli_help \
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
            check=$ATTR_PATH
            tasks=$TASK_IDS
            open_tasks=$OPEN_TASK_IDS
            status=complete
            evidence_scope=serve-session-cap
            component=crucible-cli,crucible-api
            serve_max_sessions=live-session-cap
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }

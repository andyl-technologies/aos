{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliServeReadOnly",
  taskIds ? ["T-CLI-14"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  apiServer = builtins.readFile ../../crates/crucible-api/src/server.rs;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-14 read-only partial-evidence note";
        needle = "Completed under `checks.crucible.phase5.cliServeReadOnly`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI serve read-only completion note";
        needle = "`T-CLI-14` is completed under `checks.crucible.phase5.cliServeReadOnly`";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "server mode exported";
        needle = "LifecycleServerMode";
      }
      {
        label = "mode-aware server exported";
        needle = "serve_lifecycle_http2_with_mode";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/server.rs" apiServer [
      {
        label = "server read-only mode";
        needle = "pub struct LifecycleServerMode";
      }
      {
        label = "read-only rejection response";
        needle = "read_only_rejection_response";
      }
      {
        label = "create-session read-only rejection";
        needle = "read-only daemon rejects state-mutating API call";
      }
      {
        label = "destroy-session read-only rejection test";
        needle = "server_read_only_mode_rejects_session_destruction";
      }
      {
        label = "control attach read-only rejection test";
        needle = "server_read_only_mode_rejects_control_attach";
      }
      {
        label = "watch attach read-only allowance test";
        needle = "server_read_only_mode_allows_watch_attach";
      }
      {
        label = "mutating send read-only rejection test";
        needle = "server_read_only_mode_rejects_mutating_send_but_allows_query";
      }
      {
        label = "default read-write route test";
        needle = "server_read_write_mode_keeps_default_mutating_routes";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "serve read-only flag";
        needle = "read_only: bool";
      }
      {
        label = "serve uses mode-aware daemon";
        needle = "serve_lifecycle_http2_with_mode_until_shutdown(";
      }
      {
        label = "serve help advertises read-only";
        needle = "--read-only";
      }
      {
        label = "serve help advertises max-sessions";
        needle = "--max-sessions <n>";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI serve read-only check";
        needle = "cliServeReadOnly = import ./phase5-cli-serve-read-only.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI serve read-only check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-serve-read-only";
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
          name = "run-cli-serve-read-only";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-serve-read-only-target" \
              -p crucible-api \
              server_ \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-serve-read-only-target" \
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
            evidence_scope=serve-read-only-transport-policy
            component=crucible-cli,crucible-api
            serve_read_only=transport-policy
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }

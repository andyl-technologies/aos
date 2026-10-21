{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliServeReadOnly",
  taskIds ? ["T-CLI-14"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  apiServer = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-api/src/server.rs;
  };
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliVerifyServe = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-cli/src/cli/verify_serve.rs;
  };
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
        label = "serve help advertises read-only";
        needle = "--read-only";
      }
      {
        label = "serve help advertises max-sessions";
        needle = "--max-sessions <n>";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/cli/verify_serve.rs" cliVerifyServe [
      {
        label = "serve uses shared mode-aware daemon";
        needle = "serve_shared_lifecycle_http2_mtls_with_mode_until_shutdown(";
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
    mkCrucibleTestGate {
      pname = "crucible-phase5-cli-serve-read-only";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

      phases = [
        {
          name = "run-cli-serve-read-only";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-api \
              server_ \
              -- --test-threads=1
            crucible-cargo test \
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

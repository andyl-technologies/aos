{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliServeMultiClient",
  taskIds ? ["T-CLI-14"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  controlClientGate = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-control-client/tests/gate_control_client.rs;
  };
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-14 multi-client completion note";
        needle = "`checks.crucible.phase5.cliServeMultiClient`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI serve multi-client completion note";
        needle = "`checks.crucible.phase5.cliServeMultiClient`, and";
      }
      {
        label = "phase5 CLI serve multi-client coverage wording";
        needle = "admits concurrent";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-control-client/tests/gate_control_client.rs" controlClientGate [
      {
        label = "production HTTP/2 multi-client test";
        needle = "production_http2_lifecycle_server_admits_concurrent_watch_and_query_clients";
      }
      {
        label = "concurrent watch/query join";
        needle = "tokio::join!(watch_a, watch_b, paused_query)";
      }
      {
        label = "watch clients attach";
        needle = "watch_attach";
      }
      {
        label = "read-only query clients";
        needle = "query_state_command()";
      }
      {
        label = "live watch update assertion";
        needle = "recv_watch_state_update(&mut watch_a, LiveStateKind::Running)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI serve multi-client check";
        needle = "cliServeMultiClient = import ./phase5-cli-serve-multi-client.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI serve multi-client check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase5-cli-serve-multi-client";

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
          name = "run-cli-serve-multi-client";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-control-api \
              production_http2_lifecycle_server_admits_concurrent_watch_and_query_clients \
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
            evidence_scope=serve-multi-client-observation
            component=crucible-api
            serve_multi_client=production-http2-watch-query
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }

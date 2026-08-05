{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliServeMultiClient",
  taskIds ? ["T-CLI-14"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  controlClientGate = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-api/tests/gate_control_client.rs;
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
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" controlClientGate [
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
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-serve-multi-client";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-cli-serve-multi-client";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-serve-multi-client-target" \
              -p crucible-api \
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

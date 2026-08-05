{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliServeShutdown",
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
  apiServer = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-api/src/server.rs;
  };
  apiLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-api/src/lib.rs;
  };
  cliCargo = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  cliMain = import ./_cli-source.nix {inherit lib;};
  serveProcessTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-cli/tests/serve_process.rs;
  };
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-14 shutdown completion note";
        needle = "`checks.crucible.phase5.cliServeShutdown`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI serve shutdown completion note";
        needle = "`checks.crucible.phase5.cliServeShutdown`: the CLI advertises";
      }
      {
        label = "phase5 CLI serve process signal evidence";
        needle = "real process exits 0 after an external shutdown signal";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/server.rs" apiServer [
      {
        label = "shutdown-aware HTTP/2 server helper";
        needle = "serve_lifecycle_http2_with_mode_until_shutdown";
      }
      {
        label = "graceful shutdown wiring";
        needle = ".with_graceful_shutdown(async move";
      }
      {
        label = "stream shutdown watch channel";
        needle = "watch::channel(false)";
      }
      {
        label = "stream shutdown receiver state";
        needle = "shutdown: watch::Receiver<bool>";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "shutdown helper public export";
        needle = "serve_lifecycle_http2_with_mode_until_shutdown";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" (import ./_rust-module-source.nix {
      inherit lib;
      entry = ../../crates/crucible-api/tests/gate_control_client.rs;
    }) [
      {
        label = "active Watch shutdown regression";
        needle = "production_http2_lifecycle_server_shutdown_completes_with_active_watch_stream";
      }
      {
        label = "active Watch shutdown timeout";
        needle = "server should finish after shutdown with active Watch";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "serve-specific error variant";
        needle = "Serve(String)";
      }
      {
        label = "serve exit code 3";
        needle = "Self::Serve(_) => 3";
      }
      {
        label = "production ctrl-c shutdown future";
        needle = "serve_shutdown_signal()";
      }
      {
        label = "unix interrupt shutdown signal";
        needle = "SignalKind::interrupt()";
      }
      {
        label = "unix terminate shutdown signal";
        needle = "SignalKind::terminate()";
      }
      {
        label = "bounded post-signal drain timeout";
        needle = "SERVE_SHUTDOWN_DRAIN_TIMEOUT";
      }
      {
        label = "graceful shutdown channel";
        needle = "tokio::sync::oneshot::channel";
      }
      {
        label = "injectable serve shutdown helper";
        needle = "run_serve_invocation_until_shutdown";
      }
      {
        label = "serve shutdown signal error mapping";
        needle = "serve shutdown signal error";
      }
      {
        label = "serve shutdown/bind test";
        needle = "cli_serve_shutdown_and_bind_errors_follow_exit_contract";
      }
      {
        label = "serve bind error mapping";
        needle = "serve bind error";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliCargo [
      {
        label = "libc dev dependency for signal harness";
        needle = "libc = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/serve_process.rs" serveProcessTest [
      {
        label = "external serve signal-process harness";
        needle = "serve_process_exits_zero_on_sigterm";
      }
      {
        label = "serve binary execution";
        needle = "CARGO_BIN_EXE_crucible";
      }
      {
        label = "serve process probes HTTP2 endpoint";
        needle = "RpcControlClient::new";
      }
      {
        label = "serve process sends terminate signal";
        needle = "libc::SIGTERM";
      }
      {
        label = "serve process asserts zero exit";
        needle = "serve should exit 0 after SIGTERM";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI serve shutdown check";
        needle = "cliServeShutdown = import ./phase5-cli-serve-shutdown.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI serve shutdown check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-serve-shutdown";
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
          name = "run-cli-serve-shutdown";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-serve-shutdown-target" \
              -p crucible-cli \
              cli_serve_shutdown \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-serve-shutdown-target" \
              -p crucible-api \
              production_http2_lifecycle_server_shutdown_completes_with_active_watch_stream \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-serve-shutdown-target" \
              -p crucible-cli \
              --test serve_process \
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
            evidence_scope=serve-shutdown-process
            component=crucible-cli,crucible-api
            serve_shutdown=graceful-shutdown-and-bind-exit
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }

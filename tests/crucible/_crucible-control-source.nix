# Reads control-plane responsibilities across their Cargo ownership boundaries.
# Source-contract gates keep checking the same implementation after API values,
# remote transports, server adapters, and VM realization become separate crates.
{
  lib,
  component,
}: let
  api = ../../crates/crucible/control/crucible-control-api;
  client = ../../crates/crucible/control/crucible-control-client;
  server = ../../crates/crucible/control/crucible-control-server;
  daemon = ../../crates/crucible/control/crucible-daemon;

  entries = {
    exports = [
      (api + "/src/lib.rs")
      (client + "/src/lib.rs")
      (server + "/src/lib.rs")
    ];
    client = [
      (client + "/src/client.rs")
      (api + "/src/wire_model.rs")
      (server + "/src/in_process.rs")
    ];
    lifecycle_values = [(api + "/src/lifecycle.rs")];
    streaming_values = [(api + "/src/streaming.rs")];
    lifecycle = [
      (api + "/src/lifecycle.rs")
      (server + "/src/lifecycle.rs")
    ];
    streaming = [
      (api + "/src/streaming.rs")
      (server + "/src/streaming.rs")
    ];
    control_responsive = [
      (api + "/src/control_responsive.rs")
      (server + "/src/control_responsive.rs")
    ];
    event_log_stream = [(server + "/src/event_log_stream.rs")];
    vm_lifecycle = [(daemon + "/src/vm_lifecycle.rs")];
    debug_relay = [
      (api + "/src/debug_relay.rs")
      (server + "/src/debug_relay.rs")
    ];
    server = [(server + "/src/server.rs")];
  };

  readModule = entry:
    import ./_rust-module-source.nix {
      inherit lib entry;
    };
in
  builtins.concatStringsSep "\n" (map (if component == "exports" then builtins.readFile else readModule) entries.${component})

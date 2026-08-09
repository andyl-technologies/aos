{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolHandshake",
  taskIds ? ["T-PROTO-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  handshakeTest = builtins.readFile ../../crates/crucible-protocol/tests/handshake.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "current protocol version";
        needle = "pub const CONTROL_PROTOCOL_VERSION";
      }
      {
        label = "minimum protocol version";
        needle = "pub const CONTROL_PROTOCOL_MIN_VERSION";
      }
      {
        label = "host handshake config";
        needle = "pub struct HostHandshakeConfig";
      }
      {
        label = "plugin handshake config";
        needle = "pub struct PluginHandshakeConfig";
      }
      {
        label = "negotiated handshake result";
        needle = "pub struct NegotiatedHandshake";
      }
      {
        label = "handshake error type";
        needle = "pub enum HandshakeError";
      }
      {
        label = "host stream handshake";
        needle = "pub fn host_accept_handshake";
      }
      {
        label = "plugin stream handshake";
        needle = "pub fn plugin_start_handshake";
      }
      {
        label = "host pure negotiation";
        needle = "pub fn host_negotiate_handshake";
      }
      {
        label = "plugin ack validation";
        needle = "pub fn plugin_validate_handshake_ack";
      }
      {
        label = "minimum-version negotiation rule";
        needle = "plugin_proto_version.min(config.proto_version)";
      }
      {
        label = "exact ABI mismatch error";
        needle = "AbiMismatch";
      }
      {
        label = "slot bounds validation";
        needle = "validate_slot_assignment";
      }
      {
        label = "no-overlap error";
        needle = "ProtocolVersionNoOverlap";
      }
      {
        label = "hello message write";
        needle = "PluginMsg::Hello";
      }
      {
        label = "hello ack message write";
        needle = "HostMsg::HelloAck";
      }
      {
        label = "frame writer flushes before blocking peer reads";
        needle = "writer.flush()";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/handshake.rs" handshakeTest [
      {
        label = "host happy path";
        needle = "host_accepts_hello_negotiates_minimum_and_writes_hello_ack";
      }
      {
        label = "plugin happy path";
        needle = "plugin_sends_hello_and_validates_hello_ack_before_setup";
      }
      {
        label = "host failure coverage";
        needle = "host_rejects_handshake_failures_without_hello_ack";
      }
      {
        label = "plugin failure coverage";
        needle = "plugin_rejects_invalid_hello_ack";
      }
      {
        label = "blocking I/O script";
        needle = "struct ScriptedIo";
      }
      {
        label = "version no-overlap assertion";
        needle = "ProtocolVersionNoOverlap";
      }
      {
        label = "ABI mismatch assertion";
        needle = "AbiMismatch";
      }
      {
        label = "slot bounds assertion";
        needle = "InvalidSlot";
      }
      {
        label = "host stream failures emit no ack";
        needle = "assert_host_stream_failure_does_not_write_ack";
      }
      {
        label = "handshake write flush assertion";
        needle = "flush_count";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes protocol handshake check";
        needle = "protocolHandshake = import ./phase2-protocol-handshake.nix";
      }
      {
        label = "canonical ABI conformance gate is implemented";
        needle = "abiConformance = import ./phase2-abi-conformance.nix";
      }
      {
        label = "canonical ABI conformance task list";
        needle = "taskIds = [\"T-HARN-17\" \"T-API-11\" \"T-API-12\" \"T-PAT-8\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 protocol handshake check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-handshake";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

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
          name = "run-protocol-handshake";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-handshake-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test handshake \
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
            check=${attrPath}
            tasks=${taskList}
            gate=gate:abi-conformance
            rust_tests=crucible-protocol::handshake
            handshake=Hello,HelloAck
            proto_negotiation=min-plugin-host
            abi_check=exact
            slot_check=slot-index-lt-node-count
            RESULT
          '';
        }
      ];
    }

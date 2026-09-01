{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolCodec",
  taskIds ? ["T-PROTO-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  codecTest = builtins.readFile ../../crates/crucible-protocol/tests/codec.rs;
  protocolAbiGate = builtins.readFile ../../crates/crucible-protocol/tests/gate_abi_conformance.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "plugin message enum";
        needle = "pub enum PluginMsg";
      }
      {
        label = "host message enum";
        needle = "pub enum HostMsg";
      }
      {
        label = "decode error enum";
        needle = "pub enum FrameDecodeError";
      }
      {
        label = "empty buffer decode error";
        needle = "EmptyFrame";
      }
      {
        label = "unknown tag decode error";
        needle = "UnknownTag";
      }
      {
        label = "short payload decode error";
        needle = "PayloadTooShort";
      }
      {
        label = "long payload decode error";
        needle = "PayloadTooLong";
      }
      {
        label = "oversize length decode error";
        needle = "LengthExceedsMax";
      }
      {
        label = "frame I/O error enum";
        needle = "pub enum FrameIoError";
      }
      {
        label = "plugin encoder";
        needle = "pub fn control_encode_plugin_msg";
      }
      {
        label = "plugin decoder";
        needle = "pub fn control_decode_plugin_msg";
      }
      {
        label = "host encoder";
        needle = "pub fn control_encode_host_msg";
      }
      {
        label = "host decoder";
        needle = "pub fn control_decode_host_msg";
      }
      {
        label = "frame read helper";
        needle = "pub fn read_control_frame";
      }
      {
        label = "frame write helper";
        needle = "pub fn write_control_frame";
      }
      {
        label = "big-endian u32 encoder";
        needle = "to_be_bytes()";
      }
      {
        label = "big-endian u32 decoder";
        needle = "u32::from_be_bytes";
      }
      {
        label = "big-endian u64 decoder";
        needle = "u64::from_be_bytes";
      }
      {
        label = "bounded read allocation";
        needle = "if length > MAX_FRAME_SIZE";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/codec.rs" codecTest [
      {
        label = "plugin message round trip";
        needle = "plugin_messages_round_trip_through_big_endian_frames";
      }
      {
        label = "host message round trip";
        needle = "host_messages_round_trip_through_big_endian_frames";
      }
      {
        label = "typed frame shape errors";
        needle = "decoder_reports_typed_frame_shape_errors";
      }
      {
        label = "direction and payload shape errors";
        needle = "decoder_reports_direction_and_payload_shape_errors";
      }
      {
        label = "truncated frame read I/O errors";
        needle = "frame_stream_helpers_reject_truncated_reads_as_io_errors";
      }
      {
        label = "frame stream read/write";
        needle = "frame_stream_helpers_read_and_write_complete_frames";
      }
      {
        label = "write error reporting";
        needle = "frame_stream_helpers_report_write_errors";
      }
      {
        label = "length prefix preservation";
        needle = "frame_read_helper_preserves_prefix_and_length_contract";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/gate_abi_conformance.rs" protocolAbiGate [
      {
        label = "canonical protocol ABI gate implemented";
        needle = "protocol_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "canonical protocol ABI gate literal byte freeze";
        needle = "protocol_golden_vectors_freeze_literal_frame_bytes";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes protocol codec check";
        needle = "protocolCodec = import ./phase2-protocol-codec.nix";
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
  then throw "crucible phase2 protocol codec check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-codec";
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
          name = "run-protocol-codec";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-codec-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test codec \
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
            rust_tests=crucible-protocol::codec
            codec=pure-owned-buffer
            frame_io=read-write-helpers
            typed_errors=empty,unknown-tag,short-payload,long-payload,oversize-length,truncated-prefix,truncated-payload
            RESULT
          '';
        }
      ];
    }

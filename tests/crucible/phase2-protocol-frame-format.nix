{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolFrameFormat",
  taskIds ? ["T-PROTO-1"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  frameFormatTest = builtins.readFile ../../crates/crucible-protocol/tests/frame_format.rs;
  protocolAbiGate = builtins.readFile ../../crates/crucible-protocol/tests/gate_abi_conformance.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "length prefix size";
        needle = "pub const FRAME_LENGTH_PREFIX_SIZE: usize = 4;";
      }
      {
        label = "tag size";
        needle = "pub const FRAME_TAG_SIZE: usize = 1;";
      }
      {
        label = "maximum frame size";
        needle = "pub const MAX_FRAME_SIZE: u32 = 64;";
      }
      {
        label = "maximum payload size";
        needle = "pub const MAX_PAYLOAD_SIZE: u32 = MAX_FRAME_SIZE - FRAME_TAG_SIZE as u32;";
      }
      {
        label = "length includes tag";
        needle = "pub const FRAME_LENGTH_INCLUDES_TAG: bool = true;";
      }
      {
        label = "big-endian payload integers";
        needle = "pub const FRAME_INTEGERS_ARE_BIG_ENDIAN: bool = true;";
      }
      {
        label = "closed control tag enum";
        needle = "pub enum ControlTag";
      }
      {
        label = "Setup tag";
        needle = "Setup = 0x01";
      }
      {
        label = "SetupAck tag";
        needle = "SetupAck = 0x02";
      }
      {
        label = "Quit tag";
        needle = "Quit = 0x12";
      }
      {
        label = "Hello tag";
        needle = "Hello = 0xF0";
      }
      {
        label = "HelloAck tag";
        needle = "HelloAck = 0xF1";
      }
      {
        label = "closed registry lookup";
        needle = "pub const fn from_wire_value(value: u8) -> Option<Self>";
      }
      {
        label = "tag direction";
        needle = "pub const fn direction(self) -> ControlDirection";
      }
      {
        label = "tag payload length";
        needle = "pub const fn payload_len(self) -> usize";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/frame_format.rs" frameFormatTest [
      {
        label = "frame format test";
        needle = "frame_format_uses_big_endian_length_tag_and_payload";
      }
      {
        label = "closed registry test";
        needle = "closed_tag_registry_matches_rfc_14_table";
      }
      {
        label = "unknown tag rejection test";
        needle = "closed_tag_registry_rejects_unregistered_wire_values";
      }
      {
        label = "direction and payload length test";
        needle = "tag_directions_and_payload_lengths_match_control_lifecycle";
      }
      {
        label = "payload length includes tag byte";
        needle = "FRAME_TAG_SIZE + tag.payload_len() <= MAX_FRAME_SIZE as usize";
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
        label = "phase2 exposes protocol frame-format check";
        needle = "protocolFrameFormat = import ./phase2-protocol-frame-format.nix";
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
  then throw "crucible phase2 protocol frame-format check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase2-protocol-frame-format";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-protocol-frame-format";
          script = ''
            set -eu
            crucible-cargo test \
              -p crucible-protocol \
              --test frame_format \
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
            rust_tests=crucible-protocol::frame_format
            frame=[u32-be-length][u8-tag][payload]
            max_frame_size=64
            tags=Setup:0x01,SetupAck:0x02,Quit:0x12,Hello:0xF0,HelloAck:0xF1
            RESULT
          '';
        }
      ];
    }

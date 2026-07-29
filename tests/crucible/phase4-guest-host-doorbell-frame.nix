{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostDoorbellFrame",
  taskIds ? ["T-GHC-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  protocolDoorbellFrame = builtins.readFile ../../crates/crucible-protocol/src/doorbell_frame.rs;
  protocolGateAbi = builtins.readFile ../../crates/crucible-protocol/tests/gate_abi_conformance.rs;
  protocolGoldenTest = builtins.readFile ../../crates/crucible-protocol/tests/golden_vectors.rs;
  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginWhitebox = builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  appRandomGate = builtins.readFile ./phase2-plugin-app-random-doorbell.nix;
  abiConformanceGate = builtins.readFile ./phase2-abi-conformance.nix;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-7 checked off";
        needle = "- [x] **T-GHC-7**";
      }
      {
        label = "T-GHC-7 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostDoorbellFrame`";
      }
      {
        label = "shared frame owner";
        needle = "WhiteboxDoorbellFrame";
      }
      {
        label = "frame regeneration rule";
        needle = "WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE";
      }
      {
        label = "frame golden corpus";
        needle = "GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "doorbell frame module";
        needle = "mod doorbell_frame;";
      }
      {
        label = "doorbell frame exports";
        needle = "WhiteboxDoorbellFrame";
      }
      {
        label = "doorbell frame golden exports";
        needle = "GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/doorbell_frame.rs" protocolDoorbellFrame [
      {
        label = "frame magic";
        needle = "pub const WHITEBOX_DOORBELL_FRAME_MAGIC";
      }
      {
        label = "frame protocol version";
        needle = "pub const WHITEBOX_DOORBELL_PROTOCOL_VERSION: u16 = 2;";
      }
      {
        label = "frame header length";
        needle = "pub const WHITEBOX_DOORBELL_FRAME_HEADER_LEN: usize = 12;";
      }
      {
        label = "regeneration rule";
        needle = "pub const WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE";
      }
      {
        label = "frame type";
        needle = "pub struct WhiteboxDoorbellFrame";
      }
      {
        label = "frame decoder";
        needle = "pub fn decode(bytes: &[u8])";
      }
      {
        label = "frame encoder";
        needle = "pub fn encode_whitebox_doorbell_frame";
      }
      {
        label = "decode error";
        needle = "pub enum WhiteboxDoorbellFrameDecodeError";
      }
      {
        label = "little-endian magic";
        needle = "u32::from_le_bytes";
      }
      {
        label = "little-endian version";
        needle = "u16::from_le_bytes([bytes[4], bytes[5]])";
      }
      {
        label = "little-endian payload length";
        needle = "u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]])";
      }
      {
        label = "payload length mismatch";
        needle = "PayloadLengthMismatch";
      }
      {
        label = "golden vector type";
        needle = "pub struct WhiteboxDoorbellFrameGoldenVector";
      }
      {
        label = "golden vector corpus";
        needle = "pub const GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS";
      }
      {
        label = "literal marker vector";
        needle = "marker-kind-1-empty";
      }
      {
        label = "literal random request vector";
        needle = "random-request-kind-5";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/gate_abi_conformance.rs" protocolGateAbi [
      {
        label = "ABI gate doorbell test";
        needle = "protocol_doorbell_frame_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "ABI gate doorbell corpus";
        needle = "GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS";
      }
      {
        label = "ABI gate literal frame bytes";
        needle = "assert_doorbell_vector_bytes";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/golden_vectors.rs" protocolGoldenTest [
      {
        label = "golden vector doorbell test";
        needle = "doorbell_frame_golden_vectors_match_canonical_codec_bytes";
      }
      {
        label = "golden vector doorbell corpus";
        needle = "GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "plugin frame export";
        needle = "WhiteboxDoorbellFrame";
      }
      {
        label = "plugin frame decode error export";
        needle = "WhiteboxDoorbellFrameDecodeError";
      }
      {
        label = "plugin golden frame export";
        needle = "GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "plugin re-exports protocol frame";
        needle = "WhiteboxDoorbellFrameDecodeError";
      }
      {
        label = "plugin uses shared encoder in tests";
        needle = "encode_whitebox_doorbell_frame";
      }
      {
        label = "plugin maps frame decode errors";
        needle = "impl From<WhiteboxDoorbellFrameDecodeError> for AppRandomDecodeDiagnostic";
      }
      {
        label = "generic marker rejects malformed frame";
        needle = "whitebox_doorbell_rejects_malformed_frame_without_marker";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-plugin-app-random-doorbell.nix" appRandomGate [
      {
        label = "app-random gate follows shared frame";
        needle = "protocolDoorbellFrame";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-abi-conformance.nix" abiConformanceGate [
      {
        label = "phase2 ABI gate checks doorbell frame";
        needle = "protocol_doorbell_frame_golden_vectors_match_live_codec_bytes";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "guest-host phase4 task range";
        needle = "Guest↔host channel + optional agent";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 doorbell frame import";
        needle = "guestHostDoorbellFrame = import ./phase4-guest-host-doorbell-frame.nix";
      }
      {
        label = "phase4 doorbell frame attr path";
        needle = "checks.crucible.phase4.guestHostDoorbellFrame";
      }
      {
        label = "phase4 doorbell frame task id";
        needle = "taskIds = [\"T-GHC-7\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "plugin-local frame owner";
        needle = "pub struct WhiteboxDoorbellFrame";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host doorbell frame check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-doorbell-frame";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
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
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-guest-host-doorbell-frame";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-doorbell-frame-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_abi_conformance \
              protocol_doorbell_frame_golden_vectors_match_live_codec_bytes \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-doorbell-frame-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test golden_vectors \
              doorbell_frame_golden_vectors_match_canonical_codec_bytes \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-doorbell-frame-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_app_random_decoder_rejects_bad_magic_version_kind_and_utf8 \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-doorbell-frame-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_doorbell_rejects_malformed_frame_without_marker \
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
            frame=whitebox-doorbell-fixed-header-le
            version_rule=WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE
            golden_vectors=GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS
            RESULT
          '';
        }
      ];
    }

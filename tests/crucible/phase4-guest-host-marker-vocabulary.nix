{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostMarkerVocabulary",
  taskIds ? ["T-GHC-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  protocolMarker = builtins.readFile ../../crates/crucible-protocol/src/doorbell_marker.rs;
  protocolGateAbi = builtins.readFile ../../crates/crucible-protocol/tests/gate_abi_conformance.rs;
  protocolGoldenTest = builtins.readFile ../../crates/crucible-protocol/tests/golden_vectors.rs;
  protocolCodecTest = builtins.readFile ../../crates/crucible-protocol/tests/codec.rs;
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  engineTrigger = import ./_crucible-trigger-source.nix {inherit lib;};
  engineGateAbi = builtins.readFile ../../crates/crucible/tests/gate_abi_conformance.rs;
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
        label = "T-GHC-8 checked off";
        needle = "- [x] **T-GHC-8**";
      }
      {
        label = "T-GHC-8 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostMarkerVocabulary`";
      }
      {
        label = "marker module implementation note";
        needle = "`crucible-protocol::doorbell_marker`";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "doorbell marker module";
        needle = "mod doorbell_marker;";
      }
      {
        label = "doorbell marker kind export";
        needle = "WhiteboxDoorbellMarkerKind";
      }
      {
        label = "marker golden corpus export";
        needle = "GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS";
      }
      {
        label = "marker frame encoder export";
        needle = "encode_whitebox_marker_frame";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/doorbell_marker.rs" protocolMarker [
      {
        label = "assertion marker kind";
        needle = "pub const WHITEBOX_DOORBELL_KIND_ASSERTION";
      }
      {
        label = "lifecycle marker kind";
        needle = "pub const WHITEBOX_DOORBELL_KIND_LIFECYCLE";
      }
      {
        label = "event marker kind";
        needle = "pub const WHITEBOX_DOORBELL_KIND_EVENT";
      }
      {
        label = "coverage marker kind";
        needle = "pub const WHITEBOX_DOORBELL_KIND_COVERAGE";
      }
      {
        label = "random request marker kind";
        needle = "pub const WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST";
      }
      {
        label = "closed kind enum";
        needle = "pub enum WhiteboxDoorbellMarkerKind";
      }
      {
        label = "closed assertion flavor enum";
        needle = "pub enum WhiteboxAssertionMarkerFlavor";
      }
      {
        label = "closed assertion flavor order";
        needle = "pub const ALL: [Self; WHITEBOX_DOORBELL_ASSERTION_FLAVOR_COUNT]";
      }
      {
        label = "lifecycle event enum";
        needle = "pub enum WhiteboxLifecycleMarkerEvent";
      }
      {
        label = "closed lifecycle event order";
        needle = "pub const ALL: [Self; WHITEBOX_DOORBELL_LIFECYCLE_EVENT_COUNT]";
      }
      {
        label = "assertion marker body";
        needle = "pub struct WhiteboxAssertionMarkerBody";
      }
      {
        label = "assertion flavor field";
        needle = "pub flavor: WhiteboxAssertionMarkerFlavor";
      }
      {
        label = "assertion condition field";
        needle = "pub condition: bool";
      }
      {
        label = "assertion must-hit field";
        needle = "pub must_hit: bool";
      }
      {
        label = "assertion id field";
        needle = "pub id: String";
      }
      {
        label = "assertion message field";
        needle = "pub message: String";
      }
      {
        label = "assertion location field";
        needle = "pub location: String";
      }
      {
        label = "assertion details field";
        needle = "pub details: Vec<WhiteboxMarkerDetail>";
      }
      {
        label = "marker payload decoder";
        needle = "pub fn decode_whitebox_marker_payload";
      }
      {
        label = "marker frame encoder";
        needle = "pub fn encode_whitebox_marker_frame";
      }
      {
        label = "marker payload golden corpus";
        needle = "pub const GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS";
      }
      {
        label = "closed kind lookup";
        needle = "pub const fn from_wire_value(kind: u16) -> Option<Self>";
      }
      {
        label = "unknown kind diagnostic";
        needle = "UnknownKind";
      }
      {
        label = "random request remains non-observational";
        needle = "!matches!(self, Self::RandomRequest)";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/gate_abi_conformance.rs" protocolGateAbi [
      {
        label = "ABI gate marker vector test";
        needle = "protocol_doorbell_marker_payload_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "ABI gate closed vocabulary test";
        needle = "protocol_doorbell_marker_kind_vocabulary_is_closed_and_versioned";
      }
      {
        label = "ABI gate closed subvocabulary test";
        needle = "protocol_doorbell_marker_subvocabularies_are_closed_and_versioned";
      }
      {
        label = "ABI gate marker corpus";
        needle = "GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/golden_vectors.rs" protocolGoldenTest [
      {
        label = "golden marker vector test";
        needle = "marker_payload_golden_vectors_match_canonical_codec_bytes";
      }
      {
        label = "golden marker corpus";
        needle = "GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/codec.rs" protocolCodecTest [
      {
        label = "typed marker shape error test";
        needle = "marker_payload_decoder_reports_typed_shape_errors";
      }
      {
        label = "invalid random width diagnostic";
        needle = "InvalidRandomWidth";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "engine exports marker semantic mapping";
        needle = "observable_event_from_whitebox_marker_payload";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" engineTrigger [
      {
        label = "engine marker semantic mapping";
        needle = "pub fn observable_event_from_whitebox_marker_payload";
      }
      {
        label = "assertion maps to guest assertion marker";
        needle = "ObservableEvent::guest_assertion_marker";
      }
      {
        label = "coverage maps to coverage marker";
        needle = "ObservableEvent::coverage_marker";
      }
      {
        label = "random request excluded from observational mapping";
        needle = "WhiteboxMarkerPayload::RandomRequest(_) => None";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_abi_conformance.rs" engineGateAbi [
      {
        label = "engine marker semantic mapping test";
        needle = "whitebox_marker_payloads_map_to_engine_event_semantics";
      }
      {
        label = "engine mapping uses shared protocol payload";
        needle = "WhiteboxMarkerPayload::Assertion";
      }
      {
        label = "engine mapping verifies guest assertion output";
        needle = "ObservableEventPayload::GuestAssertionMarker";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "plugin marker kind export";
        needle = "WhiteboxDoorbellMarkerKind";
      }
      {
        label = "plugin marker payload export";
        needle = "WhiteboxMarkerPayload";
      }
      {
        label = "plugin marker decoder export";
        needle = "decode_whitebox_marker_payload";
      }
      {
        label = "plugin marker golden export";
        needle = "GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "plugin decodes marker payloads";
        needle = "decode_whitebox_marker_payload(&frame)";
      }
      {
        label = "plugin rejects non-observational kind";
        needle = "NonObservationalMarkerKind";
      }
      {
        label = "plugin stores decoded payload";
        needle = "decoded_payload: WhiteboxMarkerPayload";
      }
      {
        label = "random request rejected on observational path test";
        needle = "whitebox_doorbell_rejects_random_request_on_observational_marker_path";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-plugin-app-random-doorbell.nix" appRandomGate [
      {
        label = "app-random gate follows shared marker body";
        needle = "protocolDoorbellMarker";
      }
      {
        label = "app-random gate checks shared marker decoder";
        needle = "decode_whitebox_marker_payload(&frame)";
      }
      {
        label = "app-random gate checks protocol random width";
        needle = "WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-abi-conformance.nix" abiConformanceGate [
      {
        label = "phase2 ABI gate checks marker vectors";
        needle = "protocol_doorbell_marker_payload_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "phase2 ABI gate checks marker vocabulary";
        needle = "protocol_doorbell_marker_kind_vocabulary_is_closed_and_versioned";
      }
      {
        label = "phase2 ABI gate checks marker golden corpus";
        needle = "GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "guest-host phase4 task range";
        needle = "channel + optional agent";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 marker vocabulary import";
        needle = "guestHostMarkerVocabulary = import ./phase4-guest-host-marker-vocabulary.nix";
      }
      {
        label = "phase4 marker vocabulary attr path";
        needle = "checks.crucible.phase4.guestHostMarkerVocabulary";
      }
      {
        label = "phase4 marker vocabulary task id";
        needle = "taskIds = [\"T-GHC-8\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "plugin-local marker payload owner";
        needle = "pub enum WhiteboxMarkerPayload";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host marker vocabulary check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-marker-vocabulary";
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
          name = "run-guest-host-marker-vocabulary";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-marker-vocabulary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_abi_conformance \
              protocol_doorbell_marker_payload_golden_vectors_match_live_codec_bytes \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-marker-vocabulary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_abi_conformance \
              protocol_doorbell_marker_kind_vocabulary_is_closed_and_versioned \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-marker-vocabulary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_abi_conformance \
              protocol_doorbell_marker_subvocabularies_are_closed_and_versioned \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-marker-vocabulary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test golden_vectors \
              marker_payload_golden_vectors_match_canonical_codec_bytes \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-marker-vocabulary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test codec \
              marker_payload_decoder_reports_typed_shape_errors \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-marker-vocabulary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_doorbell_rejects_random_request_on_observational_marker_path \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-marker-vocabulary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test gate_abi_conformance \
              whitebox_marker_payloads_map_to_engine_event_semantics \
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
            marker_vocabulary=WHITEBOX_DOORBELL_KIND_ASSERTION..WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST
            golden_vectors=GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS
            RESULT
          '';
        }
      ];
    }

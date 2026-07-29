{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostDecoderHardening",
  taskIds ? ["T-GHC-14"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  protocolFrame = builtins.readFile ../../crates/crucible-protocol/src/doorbell_frame.rs;
  protocolCodecTest = builtins.readFile ../../crates/crucible-protocol/tests/codec.rs;
  protocolAbiTest = builtins.readFile ../../crates/crucible-protocol/tests/gate_abi_conformance.rs;
  pluginWhitebox = builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-14 checked off";
        needle = "- [x] **T-GHC-14**";
      }
      {
        label = "T-GHC-14 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostDecoderHardening`";
      }
      {
        label = "bounded declared length coverage";
        needle = "bounded declared";
      }
      {
        label = "wrong kind coverage";
        needle = "wrong-kind/unknown-kind cases";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/doorbell_frame.rs" protocolFrame [
      {
        label = "bounded frame decode API";
        needle = "pub fn decode_bounded";
      }
      {
        label = "declared payload bound checked before copy";
        needle = "if payload_len > max_payload_len";
      }
      {
        label = "declared payload bound error";
        needle = "PayloadLengthExceedsBound";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/codec.rs" protocolCodecTest [
      {
        label = "typed doorbell frame shape test";
        needle = "doorbell_frame_decoder_reports_typed_shape_errors";
      }
      {
        label = "bounded decode typed error";
        needle = "WhiteboxDoorbellFrame::decode_bounded(&oversized_declared, 8)";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/gate_abi_conformance.rs" protocolAbiTest [
      {
        label = "doorbell fuzz corpus gate";
        needle = "protocol_doorbell_decoder_fuzz_corpus_is_clean_and_bounded";
      }
      {
        label = "doorbell fuzz no-panic guard";
        needle = "catch_unwind(AssertUnwindSafe(||";
      }
      {
        label = "unknown kind stays typed";
        needle = "WhiteboxMarkerPayloadDecodeError::UnknownKind";
      }
      {
        label = "declared length exceeds bound fuzz case";
        needle = "declared-length-exceeds-bound";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "marker path uses bounded decoder";
        needle = "WhiteboxDoorbellFrame::decode_bounded(&payload, self.max_payload_len())";
      }
      {
        label = "app-random path uses bounded decoder";
        needle = "WhiteboxDoorbellFrame::decode_bounded(&payload, doorbell.max_payload_len())";
      }
      {
        label = "app-random declared length bound diagnostic";
        needle = "AppRandomDecodeDiagnosticKind::PayloadLengthExceedsBound";
      }
      {
        label = "generic decode diagnostic type";
        needle = "pub struct WhiteboxDoorbellDecodeDiagnostic";
      }
      {
        label = "marker sink diagnostic hook";
        needle = "record_whitebox_decode_diagnostic";
      }
      {
        label = "diagnostic event marker label";
        needle = "decode_diagnostic.";
      }
      {
        label = "unknown kind marker-path diagnostic test";
        needle = "whitebox_doorbell_records_unknown_kind_decode_diagnostic_without_marker";
      }
      {
        label = "malformed callback side-effect test";
        needle = "whitebox_app_random_drops_bad_magic_version_len_and_kind_without_side_effects";
      }
      {
        label = "malformed callback no decision assertion";
        needle = "must not draw a decision";
      }
      {
        label = "malformed callback no reply assertion";
        needle = "must not write a reply";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 decoder hardening import";
        needle = "guestHostDecoderHardening = import ./phase4-guest-host-decoder-hardening.nix";
      }
      {
        label = "phase4 decoder hardening attr path";
        needle = "checks.crucible.phase4.guestHostDecoderHardening";
      }
      {
        label = "phase4 decoder hardening task id";
        needle = "taskIds = [\"T-GHC-14\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host decoder hardening check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-decoder-hardening";
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
          name = "run-guest-host-decoder-hardening";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            require_listed() {
              listed="$1"
              test_name="$2"
              if [ -z "$(sed -n "/$test_name/p" "$listed")" ]; then
                printf 'missing expected test: %s\n' "$test_name" >&2
                exit 1
              fi
            }
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-decoder-hardening-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test codec \
              -- --list > "$TMPDIR/protocol-codec-tests"
            require_listed \
              "$TMPDIR/protocol-codec-tests" \
              "doorbell_frame_decoder_reports_typed_shape_errors"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-decoder-hardening-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_abi_conformance \
              -- --list > "$TMPDIR/protocol-abi-tests"
            require_listed \
              "$TMPDIR/protocol-abi-tests" \
              "protocol_doorbell_decoder_fuzz_corpus_is_clean_and_bounded"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-decoder-hardening-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib \
              -- --list > "$TMPDIR/plugin-tests"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_app_random_decoder_rejects_bad_magic_version_kind_and_utf8"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_app_random_drops_bad_magic_version_len_and_kind_without_side_effects"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_doorbell_records_unknown_kind_decode_diagnostic_without_marker"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-decoder-hardening-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test codec \
              doorbell_frame_decoder_reports_typed_shape_errors \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-decoder-hardening-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_abi_conformance \
              protocol_doorbell_decoder_fuzz_corpus_is_clean_and_bounded \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-decoder-hardening-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_app_random_decoder \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-decoder-hardening-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_app_random_drops_bad_magic \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-decoder-hardening-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_doorbell_records_unknown_kind_decode_diagnostic \
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
            bounded_decoder=WhiteboxDoorbellFrame::decode_bounded
            malformed_cases=bad-magic,bad-version,payload-length-exceeds-bound,payload-length-mismatch,wrong-kind,unknown-kind
            malformed_policy=diagnostic-and-drop
            marker_path_decode_diagnostic=true
            no_decision_on_malformed=true
            no_reply_on_malformed=true
            fuzz_gate=gate:abi-conformance
            RESULT
          '';
        }
      ];
    }

{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolCodecFuzz",
  taskIds ? ["T-PROTO-10" "T-HARN-19"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  codecFuzzLib = builtins.readFile ../../crates/crucible-protocol/src/codec_fuzz.rs;
  codecFuzzTest = builtins.readFile ../../crates/crucible-protocol/tests/codec_fuzz.rs;
  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  ioWireFuzzLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/io_wire_fuzz.rs;
  pluginBlockIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/block_io.rs;
  pluginNinePIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/ninep_io.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  harnessSpec = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "codec fuzz module";
        needle = "mod codec_fuzz;";
      }
      {
        label = "codec fuzz exports";
        needle = "run_control_codec_fuzz_target";
      }
      {
        label = "codec fuzz corpus export";
        needle = "CODEC_FUZZ_REGRESSION_CORPUS";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/codec_fuzz.rs" codecFuzzLib [
      {
        label = "fuzz target function";
        needle = "pub fn run_control_codec_fuzz_target";
      }
      {
        label = "fuzz outcome type";
        needle = "pub struct ControlCodecFuzzOutcome";
      }
      {
        label = "regression case type";
        needle = "pub struct ControlCodecFuzzCase";
      }
      {
        label = "seed regression corpus";
        needle = "pub const CODEC_FUZZ_REGRESSION_CORPUS";
      }
      {
        label = "empty regression";
        needle = "name: \"empty\"";
      }
      {
        label = "truncated prefix regression";
        needle = "name: \"truncated-length-one-byte\"";
      }
      {
        label = "oversize regression";
        needle = "name: \"oversize-length\"";
      }
      {
        label = "unknown tag regression";
        needle = "name: \"unknown-tag\"";
      }
      {
        label = "short payload regression";
        needle = "name: \"hello-short-payload\"";
      }
      {
        label = "long payload regression";
        needle = "name: \"hello-long-payload\"";
      }
      {
        label = "truncated payload regression";
        needle = "name: \"setup-ack-truncated-payload\"";
      }
      {
        label = "max sized adversarial regression";
        needle = "name: \"max-sized-quit-long-payload\"";
      }
      {
        label = "plugin decoder exercised";
        needle = "plugin: control_decode_plugin_msg(frame)";
      }
      {
        label = "host decoder exercised";
        needle = "host: control_decode_host_msg(frame)";
      }
      {
        label = "tag decoder exercised";
        needle = "tag: control_frame_tag(frame)";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/codec_fuzz.rs" codecFuzzTest [
      {
        label = "seed corpus test";
        needle = "seeded_regression_corpus_exercises_malformed_and_adversarial_frames";
      }
      {
        label = "no panic corpus test";
        needle = "fuzz_target_never_panics_on_regression_corpus";
      }
      {
        label = "structure-aware malformed generation";
        needle = "structure_aware_malformed_frames_never_panic";
      }
      {
        label = "directional adversarial generation";
        needle = "structure_aware_directional_adversarial_frames_remain_typed_errors";
      }
      {
        label = "well-formed round trip";
        needle = "well_formed_generated_messages_round_trip";
      }
      {
        label = "truncation and trailing generation";
        needle = "generated_truncations_and_trailing_bytes_stay_typed";
      }
      {
        label = "catch unwind no-panic assertion";
        needle = "catch_unwind";
      }
      {
        label = "plugin message generator";
        needle = "fn generated_plugin_messages";
      }
      {
        label = "host message generator";
        needle = "fn generated_host_messages";
      }
      {
        label = "structured frame generator";
        needle = "fn structured_frame";
      }
      {
        label = "tag constants covered";
        needle = "tag_constants_are_covered_by_structure_aware_fuzz_generation";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "I/O wire fuzz module";
        needle = "pub mod io_wire_fuzz;";
      }
      {
        label = "I/O wire fuzz target export";
        needle = "run_io_wire_fuzz_target";
      }
      {
        label = "I/O wire fuzz corpus export";
        needle = "IO_WIRE_FUZZ_REGRESSION_CORPUS";
      }
      {
        label = "9p wire handler export";
        needle = "handle_ninep_wire_fuzz_message";
      }
      {
        label = "9p wire message export";
        needle = "NinePWireMessage";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/block_io.rs" pluginBlockIo [
      {
        label = "block request encoder public";
        needle = "pub fn encode(&self, request_id: u32)";
      }
      {
        label = "block request decoder";
        needle = "pub fn decode(payload: &[u8]) -> Result<(u32, Self), BlockWireError>";
      }
      {
        label = "block operation typed rejection";
        needle = "UnknownOperation";
      }
      {
        label = "block write count typed rejection";
        needle = "RequestCountExceedsPayload";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/ninep_io.rs" pluginNinePIo [
      {
        label = "9p wire message type";
        needle = "pub struct NinePWireMessage";
      }
      {
        label = "9p wire handler outcome";
        needle = "pub struct NinePWireHandlerOutcome";
      }
      {
        label = "9p wire decode";
        needle = "pub fn decode(frame: &[u8]) -> Result<Self, NinePWireError>";
      }
      {
        label = "9p msize validation";
        needle = "pub fn decode_with_msize(frame: &[u8], msize: u32) -> Result<Self, NinePWireError>";
      }
      {
        label = "9p fuzz handler";
        needle = "pub fn handle_ninep_wire_fuzz_message";
      }
      {
        label = "9p synthetic error response";
        needle = "fn ninep_lerror";
      }
      {
        label = "9p typed wire errors";
        needle = "pub enum NinePWireError";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/io_wire_fuzz.rs" ioWireFuzzLib [
      {
        label = "I/O fuzz target function";
        needle = "pub fn run_io_wire_fuzz_target";
      }
      {
        label = "I/O fuzz outcome type";
        needle = "pub struct IoWireFuzzOutcome";
      }
      {
        label = "I/O regression case type";
        needle = "pub struct IoWireFuzzCase";
      }
      {
        label = "I/O regression corpus";
        needle = "pub const IO_WIRE_FUZZ_REGRESSION_CORPUS";
      }
      {
        label = "9p fuzz msize";
        needle = "pub const NINEP_FUZZ_MSIZE";
      }
      {
        label = "I/O fuzz target with msize";
        needle = "pub fn run_io_wire_fuzz_target_with_msize";
      }
      {
        label = "block request corpus entry";
        needle = "name: \"block-request-write-count-exceeds-payload\"";
      }
      {
        label = "block response corpus entry";
        needle = "name: \"block-response-trailing-payload\"";
      }
      {
        label = "9p corpus entry";
        needle = "name: \"9p-declared-size-exceeds-frame\"";
      }
      {
        label = "9p msize corpus entry";
        needle = "name: \"9p-msize-exceeds\"";
      }
      {
        label = "seed corpus test";
        needle = "io_wire_regression_corpus_exercises_block_and_9p_wire_cases";
      }
      {
        label = "no panic corpus test";
        needle = "io_wire_fuzz_target_never_panics_on_regression_corpus";
      }
      {
        label = "block request round trip";
        needle = "block_request_wire_messages_round_trip";
      }
      {
        label = "block response round trip";
        needle = "block_response_wire_messages_round_trip";
      }
      {
        label = "9p round trip";
        needle = "ninep_wire_messages_round_trip_and_msize_is_enforced";
      }
      {
        label = "9p error response assertion";
        needle = "assert_well_formed_9p_error_response";
      }
      {
        label = "structure-aware malformed generation";
        needle = "structure_aware_malformed_wire_frames_never_panic";
      }
      {
        label = "truncation and trailing generation";
        needle = "generated_truncations_and_trailing_bytes_stay_typed";
      }
      {
        label = "catch unwind no-panic assertion";
        needle = "catch_unwind";
      }
      {
        label = "roundtrip helper";
        needle = "assert_decode_encode_roundtrip";
      }
      {
        label = "clean rejection helper";
        needle = "assert_clean_reject_or_deterministic_decode";
      }
      {
        label = "regression corpus marker";
        needle = "regression_corpus";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
      {
        label = "T-PROTO-10 checklist complete";
        needle = "- [x] **T-PROTO-10**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessSpec [
      {
        label = "T-HARN-19 checklist complete";
        needle = "- [x] **T-HARN-19**";
      }
      {
        label = "T-HARN-19 completion note";
        needle = "Completed by `checks.crucible.phase2.protocolCodecFuzz`";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes protocol codec fuzz check";
        needle = "protocolCodecFuzz = import ./phase2-protocol-codec-fuzz.nix";
      }
      {
        label = "ABI conformance gate is implemented";
        needle = "abiConformance = import ./phase2-abi-conformance.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 protocol and I/O wire fuzz check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-codec-and-io-wire-fuzz";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
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
          name = "run-protocol-codec-fuzz";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-codec-fuzz-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test codec_fuzz \
              -- --test-threads=1
          '';
        }
        {
          name = "run-qemu-plugin-io-wire-fuzz";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-plugin-io-wire-fuzz-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              io_wire_fuzz \
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
            rust_test=crucible-protocol::codec_fuzz
            rust_test=crucible-qemu-plugin::io_wire_fuzz
            corpus=protocol-codec,block-wire,9p-wire,malformed,adversarial,regression
            property=no-panic,typed-error,deterministic-decode,well-formed-round-trip
            RESULT
          '';
        }
      ];
    }

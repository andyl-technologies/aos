{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolCodecFuzz",
  taskIds ? ["T-PROTO-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-7PIlTjQ6Cnb2k2+Qn4A49maDZSffD20krhCcwJ7od8Y=";
  };

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  codecFuzzLib = builtins.readFile ../../crates/crucible-protocol/src/codec_fuzz.rs;
  codecFuzzTest = builtins.readFile ../../crates/crucible-protocol/tests/codec_fuzz.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
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
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
      {
        label = "T-PROTO-10 checklist complete";
        needle = "- [x] **T-PROTO-10**";
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
  then throw "crucible phase2 protocol codec-fuzz check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-codec-fuzz";
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
            corpus=malformed,adversarial,regression
            property=no-panic,typed-error,well-formed-round-trip
            RESULT
          '';
        }
      ];
    }

{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolGoldenVectors",
  taskIds ? ["T-PROTO-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  goldenLib = builtins.readFile ../../crates/crucible-protocol/src/golden_vectors.rs;
  goldenTest = builtins.readFile ../../crates/crucible-protocol/tests/golden_vectors.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "golden vector module";
        needle = "mod golden_vectors;";
      }
      {
        label = "golden vector exports";
        needle = "GOLDEN_CONTROL_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/golden_vectors.rs" goldenLib [
      {
        label = "literal frozen protocol version";
        needle = "pub const GOLDEN_VECTOR_PROTOCOL_VERSION: u32 = 3;";
      }
      {
        label = "regeneration rule";
        needle = "GOLDEN_VECTOR_REGENERATION_RULE";
      }
      {
        label = "version bump compile-time guard";
        needle = "assert!(GOLDEN_VECTOR_PROTOCOL_VERSION == CONTROL_PROTOCOL_VERSION)";
      }
      {
        label = "golden vector struct";
        needle = "pub struct ControlGoldenVector";
      }
      {
        label = "golden vector message enum";
        needle = "pub enum ControlGoldenVectorMessage";
      }
      {
        label = "golden corpus";
        needle = "pub const GOLDEN_CONTROL_VECTORS";
      }
      {
        label = "Hello vector";
        needle = "name: \"hello\"";
      }
      {
        label = "HelloAck vector";
        needle = "name: \"hello-ack\"";
      }
      {
        label = "Setup payload vector";
        needle = "name: \"setup-payload\"";
      }
      {
        label = "SetupAck vector";
        needle = "name: \"setup-ack\"";
      }
      {
        label = "Quit vector";
        needle = "name: \"quit\"";
      }
      {
        label = "current version in Hello bytes";
        needle = "frame: &[0, 0, 0, 9, 0xF0, 0, 0, 0, 3, 0, 0, 0, 1]";
      }
      {
        label = "Setup payload bytes";
        needle = "frame: &[0, 0, 0, 9, 0x01, 0, 0, 0, 0, 0, 6, 0xE0, 0]";
      }
      {
        label = "Quit bytes";
        needle = "frame: &[0, 0, 0, 1, 0x12]";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/golden_vectors.rs" goldenTest [
      {
        label = "version bump regeneration test";
        needle = "golden_vector_protocol_version_matches_current_protocol_version";
      }
      {
        label = "stable order coverage test";
        needle = "golden_vectors_cover_required_protocol_messages_in_stable_order";
      }
      {
        label = "codec byte match test";
        needle = "golden_vectors_match_canonical_codec_bytes";
      }
      {
        label = "literal byte freeze test";
        needle = "golden_vectors_freeze_literal_wire_bytes";
      }
      {
        label = "setup payload no fd sidecar test";
        needle = "setup_vector_freezes_payload_without_descriptor_sidecar";
      }
      {
        label = "Hello covered";
        needle = "\"hello\"";
      }
      {
        label = "HelloAck covered";
        needle = "\"hello-ack\"";
      }
      {
        label = "Setup payload covered";
        needle = "\"setup-payload\"";
      }
      {
        label = "SetupAck covered";
        needle = "\"setup-ack\"";
      }
      {
        label = "Quit covered";
        needle = "\"quit\"";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes protocol golden-vector check";
        needle = "protocolGoldenVectors = import ./phase2-protocol-golden-vectors.nix";
      }
      {
        label = "ABI conformance gate is implemented";
        needle = "abiConformance = import ./phase2-abi-conformance.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 protocol golden-vectors check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-golden-vectors";
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
          name = "run-protocol-golden-vectors";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-golden-vectors-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test golden_vectors \
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
            rust_test=crucible-protocol::golden_vectors
            corpus=hello,hello-ack,setup-payload,setup-ack,quit
            version_bump_rule=GOLDEN_VECTOR_PROTOCOL_VERSION==CONTROL_PROTOCOL_VERSION
            RESULT
          '';
        }
      ];
    }

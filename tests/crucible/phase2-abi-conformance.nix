{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.abiConformance",
  taskIds ? ["T-HARN-17" "T-API-11" "T-API-12" "T-PAT-8"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  harnessLib = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  harnessGateTest = builtins.readFile ../../crates/crucible-harness/tests/gate_abi_conformance.rs;
  shmemGateTest =
    builtins.readFile ../../crates/crucible-shmem/tests/gate_abi_conformance.rs
    + builtins.readFile ../../crates/crucible-shmem/tests/gate_abi_conformance/gate_cases.rs;
  protocolGateTest = builtins.readFile ../../crates/crucible-protocol/tests/gate_abi_conformance.rs;
  protocolGoldenTest = builtins.readFile ../../crates/crucible-protocol/tests/golden_vectors.rs;
  pluginGateTest = builtins.readFile ../../crates/crucible-qemu-plugin/tests/gate_abi_conformance.rs;
  engineGateTest = builtins.readFile ../../crates/crucible/tests/gate_abi_conformance.rs;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  apiRpcAbi = builtins.readFile ../../crates/crucible-api/src/rpc_abi.rs;
  apiGateTest = builtins.readFile ../../crates/crucible-api/tests/gate_abi_conformance.rs;
  harnessSpec = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  apiSpec = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  patternsSpec = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-harness/src/lib.rs" harnessLib [
      {
        label = "canonical gate implemented";
        needle = ''
          name: "gate:abi-conformance",
                  phase: GatePhase::Phase2,
                  owner: "crucible-harness",
                  status: GateStatus::Implemented,'';
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "harness ABI target implemented";
        needle = ''
          gate: "gate:abi-conformance",
                  package: "crucible-harness",
                  test_target: "gate_abi_conformance",
                  required_features: &[],
                  placeholder: false,'';
      }
      {
        label = "protocol ABI target implemented";
        needle = ''
          gate: "gate:abi-conformance",
                  package: "crucible-protocol",
                  test_target: "gate_abi_conformance",
                  required_features: &[],
                  placeholder: false,'';
      }
      {
        label = "API ABI target implemented";
        needle = ''
          gate: "gate:abi-conformance",
                  package: "crucible-api",
                  test_target: "gate_abi_conformance",
                  required_features: &[],
                  placeholder: false,'';
      }
      {
        label = "qemu plugin ABI target implemented";
        needle = ''
          gate: "gate:abi-conformance",
                  package: "crucible-qemu-plugin",
                  test_target: "gate_abi_conformance",
                  required_features: &[],
                  placeholder: false,'';
      }
      {
        label = "engine ABI target implemented";
        needle = ''
          gate: "gate:abi-conformance",
                  package: "crucible",
                  test_target: "gate_abi_conformance",
                  required_features: &["test-double"],
                  placeholder: false,'';
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_abi_conformance.rs" harnessGateTest [
      {
        label = "catalog implementation assertion";
        needle = "gate_abi_conformance_is_implemented_in_catalog_and_targets";
      }
      {
        label = "golden vector runner success case";
        needle = "golden_vector_runner_accepts_matching_vectors";
      }
      {
        label = "golden vector runner drift cases";
        needle = "golden_vector_runner_rejects_version_and_byte_drift";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/gate_abi_conformance.rs" shmemGateTest [
      {
        label = "generated header and golden vector aggregate";
        needle = "gate_abi_conformance_checks_generated_header_and_golden_vectors";
      }
      {
        label = "version bump regeneration guard";
        needle = "assert_version_bump_regenerates_vectors";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/gate_abi_conformance.rs" protocolGateTest [
      {
        label = "protocol version check";
        needle = "protocol_golden_vector_versions_are_explicit";
      }
      {
        label = "protocol byte-for-byte check";
        needle = "protocol_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "protocol literal bytes";
        needle = "protocol_golden_vectors_freeze_literal_frame_bytes";
      }
      {
        label = "doorbell frame golden vectors";
        needle = "protocol_doorbell_frame_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "doorbell frame golden corpus";
        needle = "GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS";
      }
      {
        label = "doorbell marker golden vectors";
        needle = "protocol_doorbell_marker_payload_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "doorbell marker closed vocabulary";
        needle = "protocol_doorbell_marker_kind_vocabulary_is_closed_and_versioned";
      }
      {
        label = "doorbell marker closed subvocabularies";
        needle = "protocol_doorbell_marker_subvocabularies_are_closed_and_versioned";
      }
      {
        label = "doorbell marker golden corpus";
        needle = "GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/golden_vectors.rs" protocolGoldenTest [
      {
        label = "protocol golden vector corpus still covered";
        needle = "golden_vectors_match_canonical_codec_bytes";
      }
      {
        label = "doorbell frame golden vector corpus still covered";
        needle = "doorbell_frame_golden_vectors_match_canonical_codec_bytes";
      }
      {
        label = "doorbell marker golden vector corpus still covered";
        needle = "marker_payload_golden_vectors_match_canonical_codec_bytes";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/tests/gate_abi_conformance.rs" pluginGateTest [
      {
        label = "plugin I/O wire ABI owner";
        needle = "gate_abi_conformance_covers_plugin_io_wire_fuzzing";
      }
      {
        label = "plugin fuzz phase execution assertion";
        needle = "run-qemu-plugin-io-wire-fuzz";
      }
      {
        label = "plugin owner executes I/O wire unit target";
        needle = "run_plugin_io_wire_fuzz_unit_target(&root)?";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_abi_conformance.rs" engineGateTest [
      {
        label = "engine ABI aggregate owner";
        needle = "gate_abi_conformance_engine_aggregates_boundary_abi_owners";
      }
      {
        label = "engine plugin I/O wire aggregate";
        needle = "PluginIoWireAbi";
      }
      {
        label = "engine marker payload semantic mapping";
        needle = "whitebox_marker_payloads_map_to_engine_event_semantics";
      }
      {
        label = "engine marker assertion bridge";
        needle = "observable_event_from_whitebox_marker_payload";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "RPC ABI module";
        needle = "pub mod rpc_abi;";
      }
      {
        label = "RPC ABI exports";
        needle = "GOLDEN_RPC_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/rpc_abi.rs" apiRpcAbi [
      {
        label = "explicit major version";
        needle = "pub const RPC_PROTOCOL_MAJOR: u16 = 5;";
      }
      {
        label = "explicit minor version";
        needle = "pub const RPC_PROTOCOL_MINOR: u16 = 0;";
      }
      {
        label = "explicit patch version";
        needle = "pub const RPC_PROTOCOL_PATCH: u16 = 0;";
      }
      {
        label = "build identifier";
        needle = "pub const RPC_PROTOCOL_BUILD: &str = \"crucible-rpc-abi-v5\";";
      }
      {
        label = "golden vector protocol version";
        needle = "pub const GOLDEN_VECTOR_RPC_PROTOCOL_VERSION";
      }
      {
        label = "regeneration rule";
        needle = "GOLDEN_VECTOR_RPC_REGENERATION_RULE";
      }
      {
        label = "open-set payload kinds";
        needle = "pub const RPC_OPEN_SET_PAYLOAD_KINDS";
      }
      {
        label = "golden vector struct";
        needle = "pub struct RpcGoldenVector";
      }
      {
        label = "golden vector message enum";
        needle = "pub enum RpcGoldenVectorMessage";
      }
      {
        label = "major mismatch typed error";
        needle = "MajorVersionMismatch";
      }
      {
        label = "major mismatch negotiation";
        needle = "peer.major != RPC_PROTOCOL_VERSION.major";
      }
      {
        label = "RPC golden corpus";
        needle = "pub const GOLDEN_RPC_VECTORS";
      }
      {
        label = "Hello request vector";
        needle = "name: \"hello-request\"";
      }
      {
        label = "Hello response vector";
        needle = "name: \"hello-response\"";
      }
      {
        label = "Attached vector";
        needle = "name: \"attached\"";
      }
      {
        label = "reproduction attach vector";
        needle = "name: \"attached-with-reproduction\"";
      }
      {
        label = "GetReproduction request vector";
        needle = "name: \"get-reproduction-request\"";
      }
      {
        label = "GetReproduction response vector";
        needle = "name: \"get-reproduction-response\"";
      }
      {
        label = "command request vector";
        needle = "name: \"send-request\"";
      }
      {
        label = "command response vector";
        needle = "name: \"send-response\"";
      }
      {
        label = "rejected command response vector";
        needle = "name: \"send-response-rejected-not-found\"";
      }
      {
        label = "typed RPC error vector";
        needle = "name: \"rpc-error-invalid-state\"";
      }
      {
        label = "event vector";
        needle = "name: \"event-fault-activated\"";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_abi_conformance.rs" apiGateTest [
      {
        label = "major mismatch test";
        needle = "rpc_protocol_version_is_explicit_and_rejects_major_mismatch";
      }
      {
        label = "request response event coverage test";
        needle = "rpc_golden_vectors_cover_requests_responses_events_and_payload_kinds";
      }
      {
        label = "live encoder byte comparison";
        needle = "rpc_golden_vectors_match_live_encoder";
      }
      {
        label = "literal byte freeze";
        needle = "rpc_golden_vectors_freeze_literal_wire_bytes";
      }
      {
        label = "wire drift negative control";
        needle = "rpc_golden_vector_negative_control_detects_wire_drift";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessSpec [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/21-api.md" apiSpec [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes ABI conformance check";
        needle = "abiConformance = import ./phase2-abi-conformance.nix";
      }
      {
        label = "phase2 gate passes task IDs";
        needle = "taskIds = [\"T-HARN-17\" \"T-API-11\" \"T-API-12\" \"T-PAT-8\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 ABI conformance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-abi-conformance";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies;

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
          name = "run-abi-conformance-gate";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-harness \
              --test gate_abi_conformance \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-shmem \
              --test gate_abi_conformance \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test gate_abi_conformance \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test golden_vectors \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-api \
              --test gate_abi_conformance \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --test gate_abi_conformance \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test gate_abi_conformance \
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
            shmem_vectors=generated-header,layout-fixture,spsc-structure-aware,spsc-snapshot-byte-codec
            protocol_vectors=hello,hello-ack,setup-payload,setup-ack,quit
            rpc_vectors=hello-request,hello-response,attached,send-request,send-response,event-fault-activated
            plugin_io_wire_fuzz=phase2-protocol-codec-fuzz-run-qemu-plugin-io-wire-fuzz
            engine_abi_aggregate=true
            version_bump_rule=shmem+protocol+rpc-golden-corpora
            rpc_major_mismatch_rejection=true
            reference_client_scope=implemented-T-API-13
            RESULT
          '';
        }
      ];
    }

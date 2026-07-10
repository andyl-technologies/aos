{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.cruciblePackageAbiConformance",
  taskIds ? ["T-PKG-11"],
  rawAbiGate ? import ./phase2-abi-conformance.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase2.abiConformance";
  },
  gatedAbiGate ? null,
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  defaultChecks = builtins.readFile ./default.nix;
  abiConformanceCheck = builtins.readFile ./phase2-abi-conformance.nix;
  shmemGateTest = builtins.readFile ../../crates/crucible-shmem/tests/gate_abi_conformance.rs;
  protocolGateTest = builtins.readFile ../../crates/crucible-protocol/tests/gate_abi_conformance.rs;
  protocolGoldenTest = builtins.readFile ../../crates/crucible-protocol/tests/golden_vectors.rs;
  apiGateTest = builtins.readFile ../../crates/crucible-api/tests/gate_abi_conformance.rs;
  apiRpcAbi = builtins.readFile ../../crates/crucible-api/src/rpc_abi.rs;

  taskList = builtins.concatStringsSep "," taskIds;
  gatedAbiRawGate =
    if gatedAbiGate != null && gatedAbiGate ? rawGate
    then gatedAbiGate.rawGate
    else throw "crucible phase7 package ABI conformance check requires the actual phase2.gates.abiConformance wrapper";

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
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-11 checklist complete";
        needle = "- [x] **T-PKG-11**";
      }
      {
        label = "T-PKG-11 completion note";
        needle = "Completed by `checks.crucible.phase7.cruciblePackageAbiConformance`";
      }
      {
        label = "phase2 ABI gate reference";
        needle = "`checks.crucible.phase2.gates.abiConformance`";
      }
      {
        label = "phase2 raw ABI check reference";
        needle = "`checks.crucible.phase2.abiConformance`";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "raw phase2 ABI conformance check";
        needle = "abiConformance = import ./phase2-abi-conformance.nix {inherit pkgs lib;};";
      }
      {
        label = "scoped phase2 ABI gate wiring";
        needle = "abiConformance = greenBeforeAdvance {\n        attrPath = \"checks.crucible.phase2.gates.abiConformance\";\n        # lint needle: abiConformance = import ./phase2-abi-conformance.nix\n        gate = import ./phase2-abi-conformance.nix {\n          inherit pkgs lib;\n          attrPath = \"checks.crucible.phase2.gates.abiConformance\";\n          taskIds = [\"T-HARN-17\" \"T-API-11\" \"T-API-12\" \"T-PAT-8\"];\n          dependencies = [\n            phase1.gates.harnessLint.rawGate\n            phase1.gates.layer0Determinism.rawGate";
      }
      {
        label = "scoped phase2 ABI wrapper dependencies";
        needle = "dependencies = [\n          phase1.gates.harnessLint\n          phase1.gates.layer0Determinism\n          phase1.gates.contentAddress\n          phase1.gates.replayOracle\n          phase1.gates.singleVmFingerprint\n          phase1.gates.divergenceBisect\n        ];";
      }
      {
        label = "phase7 package ABI conformance check imported";
        needle = "cruciblePackageAbiConformance = import ./phase7-crucible-package-abi-conformance.nix";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-abi-conformance.nix" abiConformanceCheck [
      {
        label = "AOS mkDerivation check";
        needle = "pkgs.mkDerivation";
      }
      {
        label = "vendored cargo dependencies";
        needle = "cargoDeps = pkgs.fetchCargoDeps";
      }
      {
        label = "frozen offline cargo gate";
        needle = "cargo test \\\n              --frozen \\\n              --offline";
      }
      {
        label = "shmem ABI owner test";
        needle = "-p crucible-shmem \\\n              --test gate_abi_conformance";
      }
      {
        label = "protocol ABI owner test";
        needle = "-p crucible-protocol \\\n              --test gate_abi_conformance";
      }
      {
        label = "protocol golden-vector test";
        needle = "-p crucible-protocol \\\n              --test golden_vectors";
      }
      {
        label = "RPC ABI owner test";
        needle = "-p crucible-api \\\n              --test gate_abi_conformance";
      }
      {
        label = "plugin ABI owner test";
        needle = "-p crucible-qemu-plugin \\\n              --test gate_abi_conformance";
      }
      {
        label = "engine test-double aggregate";
        needle = "-p crucible \\\n              --features test-double \\\n              --test gate_abi_conformance";
      }
      {
        label = "ABI gate result marker";
        needle = "gate=gate:abi-conformance";
      }
      {
        label = "version bump result marker";
        needle = "version_bump_rule=shmem+protocol+rpc-golden-corpora";
      }
      {
        label = "RPC mismatch result marker";
        needle = "rpc_major_mismatch_rejection=true";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/gate_abi_conformance.rs" shmemGateTest [
      {
        label = "shmem generated header and golden vector aggregate";
        needle = "gate_abi_conformance_checks_generated_header_and_golden_vectors";
      }
      {
        label = "shmem ABI version field check";
        needle = "assert_abi_version_field(&fixture)";
      }
      {
        label = "shmem version bump negative control";
        needle = "assert_version_bump_regenerates_vectors(&fixture)";
      }
      {
        label = "shmem wire drift negative control";
        needle = "golden_vector_negative_control_detects_layout_drift";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/gate_abi_conformance.rs" protocolGateTest [
      {
        label = "protocol version field check";
        needle = "protocol_golden_vector_versions_are_explicit";
      }
      {
        label = "protocol live codec comparison";
        needle = "protocol_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "protocol literal-byte freeze";
        needle = "protocol_golden_vectors_freeze_literal_frame_bytes";
      }
      {
        label = "protocol version bump negative control";
        needle = "assert_version_bump_regenerates_vectors";
      }
      {
        label = "doorbell frame golden vectors";
        needle = "protocol_doorbell_frame_golden_vectors_match_live_codec_bytes";
      }
      {
        label = "doorbell marker golden vectors";
        needle = "protocol_doorbell_marker_payload_golden_vectors_match_live_codec_bytes";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/golden_vectors.rs" protocolGoldenTest [
      {
        label = "protocol golden corpus direct test";
        needle = "golden_vectors_match_canonical_codec_bytes";
      }
      {
        label = "doorbell frame golden corpus direct test";
        needle = "doorbell_frame_golden_vectors_match_canonical_codec_bytes";
      }
      {
        label = "marker payload golden corpus direct test";
        needle = "marker_payload_golden_vectors_match_canonical_codec_bytes";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/rpc_abi.rs" apiRpcAbi [
      {
        label = "RPC semantic version";
        needle = "pub const RPC_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion";
      }
      {
        label = "RPC golden vector version";
        needle = "pub const GOLDEN_VECTOR_RPC_PROTOCOL_VERSION";
      }
      {
        label = "RPC regeneration rule";
        needle = "GOLDEN_VECTOR_RPC_REGENERATION_RULE";
      }
      {
        label = "RPC major mismatch error";
        needle = "RpcAbiError::MajorVersionMismatch";
      }
      {
        label = "RPC golden corpus";
        needle = "pub const GOLDEN_RPC_VECTORS";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_abi_conformance.rs" apiGateTest [
      {
        label = "RPC explicit version and mismatch check";
        needle = "rpc_protocol_version_is_explicit_and_rejects_major_mismatch";
      }
      {
        label = "RPC golden vector coverage";
        needle = "rpc_golden_vectors_cover_requests_responses_events_and_payload_kinds";
      }
      {
        label = "RPC live encoder comparison";
        needle = "rpc_golden_vectors_match_live_encoder";
      }
      {
        label = "RPC literal-byte freeze";
        needle = "rpc_golden_vectors_freeze_literal_wire_bytes";
      }
      {
        label = "RPC wire drift negative control";
        needle = "rpc_golden_vector_negative_control_detects_wire_drift";
      }
      {
        label = "RPC version bump negative control call";
        needle = "assert_version_bump_regenerates_vectors();";
      }
      {
        label = "RPC version bump negative control implementation";
        needle = "fn assert_version_bump_regenerates_vectors()";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 package ABI conformance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    builtins.derivation {
      name = "crucible-phase7-package-abi-conformance-0";
      inherit (lib) system;
      builder = "${pkgs.bash}/bin/bash";
      PATH = "${pkgs.coreutils}/bin";
      args = [
        "-c"
        ''
          set -eu
          mkdir -p "$out"

          {
            printf '%s\n' 'PASS'
            printf 'check=%s\n' "$ATTR_PATH"
            printf 'tasks=%s\n' "$TASK_IDS"
            printf '%s\n' 'gate=gate:abi-conformance'
            printf 'raw_abi_gate=%s\n' "$RAW_ABI_GATE"
            printf 'gated_abi_gate=%s\n' "$GATED_ABI_GATE"
            printf 'gated_abi_raw_gate=%s\n' "$GATED_ABI_RAW_GATE"
            printf '%s\n' 'check_class=eval+double-backed-aos'
            printf '%s\n' 'aos_builder=pkgs.mkDerivation'
            printf '%s\n' 'cargo_mode=frozen-offline-vendored'
            printf '%s\n' 'shmem_vectors=generated-header,layout-fixture,spsc-structure-aware,spsc-snapshot-byte-codec'
            printf '%s\n' 'protocol_vectors=hello,hello-ack,setup-payload,setup-ack,quit,doorbell-frame,doorbell-marker'
            printf '%s\n' 'rpc_vectors=hello-request,hello-response,attached,send-request,send-response,event-fault-activated'
            printf '%s\n' 'version_bump_rule=shmem+protocol+rpc-golden-corpora'
            printf '%s\n' 'rpc_major_mismatch_rejection=true'
            printf '%s\n' 'engine_test_double_aggregate=true'
          } > "$out/result"
        ''
      ];
      ATTR_PATH = attrPath;
      TASK_IDS = taskList;
      RAW_ABI_GATE = rawAbiGate;
      GATED_ABI_GATE = gatedAbiGate;
      GATED_ABI_RAW_GATE = gatedAbiRawGate;
    }

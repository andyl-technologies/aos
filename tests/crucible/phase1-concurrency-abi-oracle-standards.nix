{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  standardsRust = builtins.readFile ../../crates/crucible-harness/tests/concurrency_abi_oracle_standards.rs;
  standardsSupport = builtins.readFile ../../crates/crucible-harness/tests/support/concurrency_abi_oracle_standards.rs;
  standardsCode = standardsRust + "\n" + standardsSupport;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  # Character-exact scrub of Rust comments and string literals. The fold is
  # chunked per source line (each chunk keeps its trailing newline, and the
  # parser state — mode/depth/skip — threads across chunks) with the output
  # string forced after every chunk. A whole-file per-character fold builds a
  # haystack-deep chain of unforced `+` thunks and overflows the evaluator
  # stack on large sources.
  scrubCommentsAndStrings = content: let
    scrubChunk = chunkState: chunk: let
      length = builtins.stringLength chunk;
      charAt = index: builtins.substring index 1 chunk;
      indexes = builtins.genList (index: index) length;
      folded = builtins.foldl' step chunkState indexes;
      step = state: index:
        if state.skip
        then
          state
          // {
            skip = false;
          }
        else let
          ch = charAt index;
          next =
            if (index + 1) < length
            then charAt (index + 1)
            else "";
        in
          if state.mode == "code"
          then
            if ch == "/" && next == "/"
            then
              state
              // {
                out = state.out + "  ";
                mode = "line";
                skip = true;
              }
            else if ch == "/" && next == "*"
            then
              state
              // {
                out = state.out + "  ";
                mode = "block";
                depth = 1;
                skip = true;
              }
            else if ch == "\""
            then
              state
              // {
                out = state.out + " ";
                mode = "string";
              }
            else
              state
              // {
                out = state.out + ch;
              }
          else if state.mode == "line"
          then
            if ch == "\n"
            then
              state
              // {
                out = state.out + "\n";
                mode = "code";
              }
            else
              state
              // {
                out = state.out + " ";
              }
          else if state.mode == "block"
          then
            if ch == "/" && next == "*"
            then
              state
              // {
                out = state.out + "  ";
                depth = state.depth + 1;
                skip = true;
              }
            else if ch == "*" && next == "/"
            then
              state
              // {
                out = state.out + "  ";
                mode =
                  if state.depth == 1
                  then "code"
                  else "block";
                depth =
                  if state.depth == 1
                  then 0
                  else state.depth - 1;
                skip = true;
              }
            else
              state
              // {
                out =
                  state.out
                  + (
                    if ch == "\n"
                    then "\n"
                    else " "
                  );
              }
          else if ch == "\\" && next != ""
          then
            state
            // {
              out =
                state.out
                + " "
                + (
                  if next == "\n"
                  then "\n"
                  else " "
                );
              skip = true;
            }
          else if ch == "\""
          then
            state
            // {
              out = state.out + " ";
              mode = "code";
            }
          else
            state
            // {
              out =
                state.out
                + (
                  if ch == "\n"
                  then "\n"
                  else " "
                );
            };
    in
      # Force the accumulated output flat before the next chunk so thunk
      # depth stays bounded by the longest line, not the whole file.
      builtins.seq (builtins.stringLength folded.out) folded;
    lines = lib.splitString "\n" content;
    lineCount = builtins.length lines;
    chunkAt = index:
      builtins.elemAt lines index
      + (
        if index + 1 < lineCount
        then "\n"
        else ""
      );
    result =
      builtins.foldl'
      (state: index: scrubChunk state (chunkAt index))
      {
        out = "";
        mode = "code";
        depth = 0;
        skip = false;
      }
      (builtins.genList (index: index) lineCount);
  in
    result.out;

  targets = [
    {
      gate = "gate:abi-conformance";
      package = "crucible-harness";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible-shmem";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
    }
    {
      gate = "gate:layer1-injection";
      package = "crucible-shmem";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible-protocol";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible-api";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
    }
    {
      gate = "gate:layer1-injection";
      package = "crucible-device";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
    }
    {
      gate = "gate:replay-oracle";
      package = "crucible";
      testTarget = "gate_replay_oracle";
      requiredFeatures = ["test-double"];
    }
  ];

  spscRingMarkers = [
    "assert_spsc_ring_exhaustive_ordering_model("
    "assert_spsc_ring_exhaustive_trace_properties("
    "NoLostFrame"
    "NoDuplicatedFrame"
    "FifoOrder"
    "FullEmpty"
    "Wraparound"
  ];

  abiMarkers = [
    "assert_frozen_golden_vectors("
    "assert_decode_encode_roundtrip("
    "assert_abi_version_field("
    "assert_version_bump_regenerates_vectors("
    "assert_structure_aware_fuzz_corpus("
    "regression_corpus"
  ];

  harnessAbiMarkers = [
    "assert_frozen_golden_vectors("
    "assert_decode_encode_roundtrip("
    "assert_abi_version_field("
    "assert_version_bump_regenerates_vectors("
    "assert_structure_aware_fuzz_corpus("
    "ShmemLayoutAbi"
    "GuestHostProtocolAbi"
    "ControlPlaneRpcAbi"
  ];

  protocolCodecFuzzMarkers = [
    "assert_protocol_codec_fuzz_corpus("
    "assert_decode_encode_roundtrip("
    "assert_clean_reject_or_deterministic_decode("
    "regression_corpus"
  ];

  deviceInjectionMarkers = [
    "run_two_vm_injection"
    "struct ObservedInjection"
    "producer_host_tick"
    "HostStep::Observe"
    "assert_eq!(producer_skewed, consumer_skewed);"
    "assert_ne!(producer_skewed, consumer_skewed);"
  ];

  replayOracleMarkers = [
    "assert_replay_oracle_fixed_checkpoint_corpus("
    "struct MaterializedCheckpoint"
    "fn materialize_fat_checkpoint("
    "fn schedule_delta("
    "fn replay_schedule("
    "assert_replay_oracle_rejects_corrupt_configuration_metadata("
    "assert_replay_oracle_rejects_corrupt_schedule_delta_metadata("
    "assert_replay_oracle_excludes_observational_entries("
    "assert_replay_oracle_reports_first_mismatch("
    "assert_twice_reduce_canonical_digest("
    "SimDouble"
  ];

  standards = [
    {
      id = "all-boundary-abi-conformance";
      gate = "gate:abi-conformance";
      package = "crucible-harness";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      kind = "boundary-abi";
      requiredMarkers = harnessAbiMarkers;
    }
    {
      id = "spsc-ring-concurrency";
      gate = "gate:layer1-injection";
      package = "crucible-shmem";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
      kind = "spsc-concurrency";
      requiredMarkers = spscRingMarkers;
    }
    {
      id = "shmem-layout-abi";
      gate = "gate:abi-conformance";
      package = "crucible-shmem";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      kind = "boundary-abi";
      requiredMarkers = abiMarkers;
    }
    {
      id = "guest-host-protocol-abi";
      gate = "gate:abi-conformance";
      package = "crucible-protocol";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      kind = "boundary-abi";
      requiredMarkers = abiMarkers;
    }
    {
      id = "control-plane-rpc-abi";
      gate = "gate:abi-conformance";
      package = "crucible-api";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      kind = "boundary-abi";
      requiredMarkers = abiMarkers;
    }
    {
      id = "protocol-codec-fuzzing";
      gate = "gate:abi-conformance";
      package = "crucible-protocol";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      kind = "wire-fuzzing";
      requiredMarkers = protocolCodecFuzzMarkers;
    }
    {
      id = "device-injection-determinism";
      gate = "gate:layer1-injection";
      package = "crucible-device";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
      kind = "injection-determinism";
      requiredMarkers = deviceInjectionMarkers;
    }
    {
      id = "replay-oracle-fixed-corpus";
      gate = "gate:replay-oracle";
      package = "crucible";
      testTarget = "gate_replay_oracle";
      requiredFeatures = ["test-double"];
      kind = "replay-oracle";
      requiredMarkers = replayOracleMarkers;
    }
  ];

  targetFor = standard: let
    matches =
      builtins.filter (
        target: target.package == standard.package && target.testTarget == standard.testTarget
      )
      targets;
  in
    if matches == []
    then null
    else builtins.head matches;

  rustSourcePaths = dir: let
    entries =
      if builtins.pathExists dir
      then builtins.readDir dir
      else {};
  in
    lib.concatMap (
      name: let
        path = dir + "/${name}";
        kind = entries.${name};
      in
        if kind == "directory"
        then rustSourcePaths path
        else if kind == "regular" && lib.hasSuffix ".rs" name
        then [path]
        else []
    ) (lib.sort builtins.lessThan (builtins.attrNames entries));

  sourceFor = target: let
    path = cratesDir + "/${target.package}/tests/${target.testTarget}.rs";
    moduleDir = cratesDir + "/${target.package}/tests/${target.testTarget}";
    paths = lib.optionals (builtins.pathExists path) [path] ++ rustSourcePaths moduleDir;
  in
    builtins.concatStringsSep "\n" (map builtins.readFile paths);

  targetStandardFailures = standard: target:
    lib.optionals (target.gate != standard.gate) [
      "${target.package}:${target.testTarget} must cover ${standard.gate}, not ${target.gate}"
    ]
    ++ lib.optionals (target.requiredFeatures != standard.requiredFeatures) [
      "${target.package}:${target.testTarget} must run with features [${builtins.concatStringsSep ", " standard.requiredFeatures}]"
    ];

  bodyMarkerFailures = standard: target: content: let
    code = scrubCommentsAndStrings content;
  in
    lib.concatMap (
      marker:
        lib.optionals (!(hasInfix marker code)) [
          "${target.package}:${target.testTarget} must check ${marker} for ${standard.id}"
        ]
    )
    standard.requiredMarkers;

  standardFailures =
    lib.concatMap (
      standard: let
        target = targetFor standard;
      in
        if target == null
        then [
          "${standard.id} missing advanced test target ${standard.package}:${standard.testTarget} for ${standard.gate}"
        ]
        else
          targetStandardFailures standard target
          ++ bodyMarkerFailures standard target (sourceFor target)
    )
    standards;

  abiOwners =
    lib.sort builtins.lessThan (map (target: target.package) (builtins.filter (target: target.gate == "gate:abi-conformance") targets));
  expectedAbiOwners = ["crucible-api" "crucible-harness" "crucible-protocol" "crucible-shmem"];
  abiOwnerFailures = lib.optionals (abiOwners != expectedAbiOwners) [
    "gate:abi-conformance owner package mismatch: expected [${builtins.concatStringsSep ", " expectedAbiOwners}], found [${builtins.concatStringsSep ", " abiOwners}]"
  ];

  boundaryAbiIds =
    lib.sort builtins.lessThan (map (standard: standard.id) (builtins.filter (standard: standard.kind == "boundary-abi") standards));
  expectedBoundaryAbiIds = ["all-boundary-abi-conformance" "control-plane-rpc-abi" "guest-host-protocol-abi" "shmem-layout-abi"];
  boundaryAbiFailures = lib.optionals (boundaryAbiIds != expectedBoundaryAbiIds) [
    "advanced-test standards must cover the shmem, guest-host protocol, and control-plane RPC ABIs"
  ];

  requiredRustText = [
    "gate_targets_follow_concurrency_abi_and_oracle_standards"
    "standards_cover_the_required_abi_and_oracle_surface"
    "ADVANCED_TEST_STANDARDS"
    "SPSC_RING_MARKERS"
    "ABI_MARKERS"
    "HARNESS_ABI_MARKERS"
    "PROTOCOL_CODEC_FUZZ_MARKERS"
    "DEVICE_INJECTION_MARKERS"
    "REPLAY_ORACLE_MARKERS"
    "advanced_standard_regression_failures"
    "assert_spsc_ring_exhaustive_ordering_model("
    "assert_spsc_ring_exhaustive_trace_properties("
    "assert_frozen_golden_vectors("
    "assert_decode_encode_roundtrip("
    "assert_replay_oracle_fixed_checkpoint_corpus("
    "assert_replay_oracle_excludes_observational_entries("
  ];

  rustHarnessFailures =
    lib.concatMap (
      required:
        lib.optionals (!(hasInfix required standardsCode)) [
          "crates/crucible-harness/tests/concurrency_abi_oracle_standards.rs: missing advanced-standard wiring `${required}`"
        ]
    )
    requiredRustText;

  regressionFailures = let
    badTarget = {
      gate = "gate:abi-conformance";
      package = "crucible-shmem";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
    };
    spscStandard = builtins.elemAt standards 1;
    replayStandard = builtins.elemAt standards 7;
    findings =
      bodyMarkerFailures spscStandard badTarget ''
        /* assert_spsc_ring_exhaustive_ordering_model(NoLostFrame); */
        fn bad() {
          let _ = "assert_spsc_ring_exhaustive_trace_properties(FifoOrder)";
        }
      ''
      ++ targetStandardFailures replayStandard {
        gate = "gate:replay-oracle";
        package = "crucible";
        testTarget = "gate_replay_oracle";
        requiredFeatures = [];
      };
    hasFinding = needle: builtins.any (finding: hasInfix needle finding) findings;
  in
    lib.optionals (!(hasFinding "must check assert_spsc_ring_exhaustive_ordering_model(")) [
      "advanced-test regression failed to reject markers hidden in block comments/strings"
    ]
    ++ lib.optionals (!(hasFinding "features [test-double]")) [
      "advanced-test regression failed to reject missing replay-oracle feature"
    ];

  failures =
    standardFailures
    ++ abiOwnerFailures
    ++ boundaryAbiFailures
    ++ rustHarnessFailures
    ++ regressionFailures;
in
  if failures != []
  then throw "crucible phase1 concurrency/ABI/oracle standards lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-concurrency-abi-oracle-standards";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.concurrencyAbiOracleStandards
            gate=gate:layer1-injection,gate:abi-conformance,gate:replay-oracle
            tasks=T-STD-9
            spsc=exhaustive-ordering-model
            abi=golden-vectors,round-trip,fuzz-corpus
            replay_oracle=fixed-corpus
            RESULT
          '';
        }
      ];
    }

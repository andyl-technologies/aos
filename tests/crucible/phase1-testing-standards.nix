{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  testingStandardsRust = builtins.readFile ../../crates/crucible-harness/tests/testing_standards.rs;
  testingStandardsSupport = builtins.readFile ../../crates/crucible-harness/tests/support/testing_standards.rs;
  testingStandardsCode = testingStandardsRust + "\n" + testingStandardsSupport;

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

  lowerAscii = value:
    builtins.replaceStrings
    [
      "A"
      "B"
      "C"
      "D"
      "E"
      "F"
      "G"
      "H"
      "I"
      "J"
      "K"
      "L"
      "M"
      "N"
      "O"
      "P"
      "Q"
      "R"
      "S"
      "T"
      "U"
      "V"
      "W"
      "X"
      "Y"
      "Z"
    ]
    [
      "a"
      "b"
      "c"
      "d"
      "e"
      "f"
      "g"
      "h"
      "i"
      "j"
      "k"
      "l"
      "m"
      "n"
      "o"
      "p"
      "q"
      "r"
      "s"
      "t"
      "u"
      "v"
      "w"
      "x"
      "y"
      "z"
    ]
    value;

  twiceReduceHelper = "assert_twice_reduce_canonical_digest(";
  dumpComparePatterns = [
    "human_formatted_dump"
    "formatted_dump"
    "dump()"
  ];

  stripLineComment = line: builtins.elemAt (lib.splitString "//" line) 0;

  scrubLineStrings = line: let
    chars = builtins.genList (index: builtins.substring index 1 line) (builtins.stringLength line);
    step = state: ch:
      if state.inString
      then
        if state.escape
        then
          state
          // {
            out = state.out + " ";
            escape = false;
          }
        else if ch == "\\"
        then
          state
          // {
            out = state.out + " ";
            escape = true;
          }
        else if ch == "\""
        then {
          out = state.out + " ";
          inString = false;
          escape = false;
        }
        else
          state
          // {
            out = state.out + " ";
          }
      else if ch == "\""
      then {
        out = state.out + " ";
        inString = true;
        escape = false;
      }
      else
        state
        // {
          out = state.out + ch;
        };
    result =
      builtins.foldl' step {
        out = "";
        inString = false;
        escape = false;
      }
      chars;
  in
    result.out;

  scrubCommentsAndStrings = content:
    builtins.concatStringsSep "\n" (map (line: scrubLineStrings (stripLineComment line)) (lib.splitString "\n" content));

  targets = [
    {
      gate = "gate:harness-lint";
      package = "crucible-harness";
      testTarget = "harness_lint";
      requiredFeatures = [];
    }
    {
      gate = "gate:layer0-determinism";
      package = "crucible-sim";
      testTarget = "gate_layer0_determinism";
      requiredFeatures = [];
    }
    {
      gate = "gate:layer0-determinism";
      package = "crucible-assert";
      testTarget = "gate_layer0_determinism";
      requiredFeatures = [];
    }
    {
      gate = "gate:layer0-determinism";
      package = "crucible";
      testTarget = "gate_layer0_determinism";
      requiredFeatures = ["test-double"];
    }
    {
      gate = "gate:single-vm-fingerprint";
      package = "crucible-qemu";
      testTarget = "gate_single_vm_fingerprint";
      requiredFeatures = [];
    }
    {
      gate = "gate:single-vm-fingerprint";
      package = "crucible-qemu-plugin";
      testTarget = "gate_single_vm_fingerprint";
      requiredFeatures = [];
    }
    {
      gate = "gate:single-vm-fingerprint";
      package = "crucible-guest";
      testTarget = "gate_single_vm_fingerprint";
      requiredFeatures = [];
    }
    {
      gate = "gate:layer1-injection";
      package = "crucible-device";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
    }
    {
      gate = "gate:layer1-injection";
      package = "crucible-protocol";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
    }
    {
      gate = "gate:layer1-injection";
      package = "crucible-shmem";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
    }
    {
      gate = "gate:layer1-injection";
      package = "crucible";
      testTarget = "network_link_subnode";
      requiredFeatures = ["test-double"];
    }
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
      gate = "gate:abi-conformance";
      package = "crucible-qemu-plugin";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible";
      testTarget = "ninep_wire_abi";
      requiredFeatures = ["test-double"];
    }
    {
      gate = "gate:replay-oracle";
      package = "crucible";
      testTarget = "gate_replay_oracle";
      requiredFeatures = ["test-double"];
    }
    {
      gate = "gate:content-address";
      package = "crucible";
      testTarget = "gate_content_address";
      requiredFeatures = ["test-double"];
    }
    {
      gate = "gate:content-address";
      package = "crucible-sim";
      testTarget = "gate_content_address";
      requiredFeatures = [];
    }
    {
      gate = "gate:scheduler-liveness";
      package = "crucible";
      testTarget = "gate_scheduler_liveness";
      requiredFeatures = ["test-double"];
    }
    {
      gate = "gate:control-responsive";
      package = "crucible-session";
      testTarget = "gate_control_responsive";
      requiredFeatures = [];
    }
    {
      gate = "gate:control-responsive";
      package = "crucible-api";
      testTarget = "gate_control_responsive";
      requiredFeatures = [];
    }
    {
      gate = "gate:control-responsive";
      package = "crucible-daemon";
      testTarget = "gate_control_responsive";
      requiredFeatures = [];
    }
    {
      gate = "gate:any-guest";
      package = "crucible-qemu";
      testTarget = "gate_any_guest";
      requiredFeatures = [];
    }
    {
      gate = "gate:qemu-inert";
      package = "crucible-qemu";
      testTarget = "gate_qemu_inert";
      requiredFeatures = [];
    }
    {
      gate = "gate:qemu-inert";
      package = "crucible-qemu-plugin";
      testTarget = "gate_qemu_inert";
      requiredFeatures = [];
    }
    {
      gate = "gate:patch-microtests";
      package = "crucible-qemu-plugin";
      testTarget = "gate_patch_microtests";
      requiredFeatures = [];
    }
    {
      gate = "gate:divergence-bisect";
      package = "crucible-harness";
      testTarget = "gate_divergence_bisect";
      requiredFeatures = [];
    }
    {
      gate = "gate:adversarial-determinism";
      package = "crucible-harness";
      testTarget = "gate_adversarial_determinism";
      requiredFeatures = [];
    }
    {
      gate = "gate:e2e-determinism";
      package = "crucible-harness";
      testTarget = "gate_e2e_determinism";
      requiredFeatures = [];
    }
    {
      gate = "gate:e2e-determinism";
      package = "crucible-cli";
      testTarget = "gate_e2e_determinism";
      requiredFeatures = [];
    }
  ];

  standards = [
    {
      gate = "gate:harness-lint";
      ownerPackages = ["crucible-harness"];
      layers = ["CrossCutting"];
      shape = "static-lint";
      backend = "static-lint";
    }
    {
      gate = "gate:layer0-determinism";
      ownerPackages = ["crucible-sim" "crucible-assert" "crucible"];
      layers = ["L0" "L3"];
      shape = "twice-reduce-compare-by-hash";
      backend = "in-process";
    }
    {
      gate = "gate:single-vm-fingerprint";
      ownerPackages = ["crucible-qemu" "crucible-qemu-plugin" "crucible-guest"];
      layers = ["L2"];
      shape = "fingerprint-compare";
      backend = "real-qemu";
    }
    {
      gate = "gate:layer1-injection";
      ownerPackages = ["crucible-device" "crucible-protocol" "crucible-shmem" "crucible"];
      layers = ["L1" "L3"];
      shape = "observed-injection-icount-vectors";
      backend = "in-process";
    }
    {
      gate = "gate:abi-conformance";
      ownerPackages = ["crucible-harness" "crucible-shmem" "crucible-protocol" "crucible-api" "crucible-qemu-plugin" "crucible"];
      layers = ["L1" "L2" "L3" "L4" "CrossCutting"];
      shape = "abi-golden-vectors";
      backend = "in-process";
    }
    {
      gate = "gate:replay-oracle";
      ownerPackages = ["crucible"];
      layers = ["L3"];
      shape = "twice-reduce-compare-by-hash";
      backend = "sim-double";
    }
    {
      gate = "gate:content-address";
      ownerPackages = ["crucible" "crucible-sim"];
      layers = ["L0" "L3"];
      shape = "twice-reduce-compare-by-hash";
      backend = "in-process";
    }
    {
      gate = "gate:scheduler-liveness";
      ownerPackages = ["crucible"];
      layers = ["L3"];
      shape = "twice-reduce-compare-by-hash";
      backend = "sim-double";
    }
    {
      gate = "gate:control-responsive";
      ownerPackages = ["crucible-session" "crucible-api" "crucible-daemon"];
      layers = ["L4"];
      shape = "responsiveness-bound";
      backend = "sim-double";
    }
    {
      gate = "gate:any-guest";
      ownerPackages = ["crucible-qemu"];
      layers = ["L2"];
      shape = "fingerprint-compare";
      backend = "real-qemu";
    }
    {
      gate = "gate:qemu-inert";
      ownerPackages = ["crucible-qemu" "crucible-qemu-plugin"];
      layers = ["L2"];
      shape = "qemu-inert-compare";
      backend = "real-qemu";
    }
    {
      gate = "gate:patch-microtests";
      ownerPackages = ["crucible-qemu-plugin"];
      layers = ["L2"];
      shape = "patch-microtests";
      backend = "real-qemu";
    }
    {
      gate = "gate:divergence-bisect";
      ownerPackages = ["crucible-harness"];
      layers = ["CrossCutting"];
      shape = "divergence-bisect";
      backend = "mixed";
    }
    {
      gate = "gate:adversarial-determinism";
      ownerPackages = ["crucible-harness"];
      layers = ["CrossCutting"];
      shape = "adversarial-compare";
      backend = "mixed";
    }
    {
      gate = "gate:e2e-determinism";
      ownerPackages = ["crucible-harness" "crucible-cli"];
      layers = ["L4" "CrossCutting"];
      shape = "e2e-determinism";
      backend = "mixed";
    }
  ];

  hashCompareGates = [
    "gate:layer0-determinism"
    "gate:replay-oracle"
    "gate:content-address"
    "gate:scheduler-liveness"
  ];

  flakyEscapePatterns = [
    "flaky"
    "retry"
    "rerun"
    "thread::sleep"
    "std::thread::sleep"
  ];

  crateOwnership = [
    {
      package = "crucible-sim";
      gates = ["gate:layer0-determinism" "gate:content-address"];
    }
    {
      package = "crucible-assert";
      gates = ["gate:layer0-determinism"];
    }
    {
      package = "crucible-shmem";
      gates = ["gate:abi-conformance" "gate:layer1-injection"];
    }
    {
      package = "crucible-protocol";
      gates = ["gate:layer1-injection" "gate:abi-conformance"];
    }
    {
      package = "crucible-device";
      gates = ["gate:layer1-injection"];
    }
    {
      package = "crucible-qemu";
      gates = ["gate:single-vm-fingerprint" "gate:any-guest" "gate:qemu-inert"];
    }
    {
      package = "crucible-qemu-plugin";
      gates = ["gate:single-vm-fingerprint" "gate:abi-conformance" "gate:qemu-inert" "gate:patch-microtests"];
    }
    {
      package = "crucible-guest";
      gates = ["gate:single-vm-fingerprint"];
    }
    {
      package = "crucible";
      gates = ["gate:layer0-determinism" "gate:layer1-injection" "gate:replay-oracle" "gate:content-address" "gate:scheduler-liveness"];
    }
    {
      package = "crucible-session";
      gates = ["gate:control-responsive"];
    }
    {
      package = "crucible-api";
      gates = ["gate:control-responsive" "gate:abi-conformance"];
    }
    {
      package = "crucible-daemon";
      gates = ["gate:control-responsive"];
    }
    {
      package = "crucible-cli";
      gates = ["gate:e2e-determinism"];
    }
    {
      package = "crucible-harness";
      gates = ["gate:harness-lint" "gate:abi-conformance" "gate:divergence-bisect" "gate:adversarial-determinism" "gate:e2e-determinism"];
    }
  ];

  packageLayer = package:
    if builtins.elem package ["crucible-sim" "crucible-assert"]
    then "L0"
    else if builtins.elem package ["crucible-shmem" "crucible-protocol" "crucible-device"]
    then "L1"
    else if builtins.elem package ["crucible-qemu" "crucible-qemu-plugin" "crucible-guest"]
    then "L2"
    else if package == "crucible"
    then "L3"
    else if builtins.elem package ["crucible-session" "crucible-api" "crucible-daemon" "crucible-cli"]
    then "L4"
    else if package == "crucible-harness"
    then "CrossCutting"
    else null;

  standardsForGate = gate: builtins.filter (standard: standard.gate == gate) standards;
  standardForGate = gate: let
    matches = standardsForGate gate;
  in
    if matches == []
    then null
    else builtins.head matches;

  packagesForGate = gate:
    lib.sort builtins.lessThan (map (target: target.package) (builtins.filter (target: target.gate == gate) targets));

  gatesForPackage = package:
    lib.sort builtins.lessThan (map (target: target.gate) (builtins.filter (target: target.package == package) targets));

  sourceShapeFailures = target: standard: content: let
    code = scrubCommentsAndStrings content;
    lower = lowerAscii code;
    placeholder = hasInfix "#[ignore" content && hasInfix "panic!" content;
    protocolDataPlaneTarget = target.package == "crucible-protocol" && target.gate == "gate:layer1-injection";
  in
    lib.optionals (!placeholder && standard.shape == "twice-reduce-compare-by-hash" && !(hasInfix twiceReduceHelper code)) [
      "${target.package}:${target.testTarget} must call ${twiceReduceHelper} to drive twice and compare canonical digests"
    ]
    ++ lib.optionals (!placeholder && protocolDataPlaneTarget && standard.shape == "observed-injection-icount-vectors" && (
      !(hasInfix "RUNTIME_DATA_PLANE_CONTRACT" code)
      || !(hasInfix "control_channel_carries_runtime_frames" code)
      || !(hasInfix "control_channel_carries_delivery_icounts" code)
      || !(hasInfix "control_channel_silent_between_setup_ack_and_quit" code)
    )) [
      "${target.package}:${target.testTarget} must prove runtime injection data stays out of the control protocol"
    ]
    ++ lib.optionals (!placeholder && !protocolDataPlaneTarget && standard.shape == "observed-injection-icount-vectors" && (
      !(hasInfix "run_two_vm_injection" code)
      || !(hasInfix "struct ObservedInjection" code)
      || !(hasInfix "producer_host_tick" code)
      || !(hasInfix "assert_eq!(producer_skewed, consumer_skewed);" code)
      || !(hasInfix "assert_ne!(producer_skewed, consumer_skewed);" code)
    )) [
      "${target.package}:${target.testTarget} must compare observed injection icount vectors across host interleavings with a host-timing negative control"
    ]
    ++ lib.optionals (!placeholder && builtins.any (pattern: hasInfix pattern lower) dumpComparePatterns) [
      "${target.package}:${target.testTarget} must compare canonical digests, not formatted dumps"
    ]
    ++ lib.optionals (!placeholder && standard.backend == "sim-double" && !(hasInfix "SimDouble" code)) [
      "${target.package}:${target.testTarget} must exercise the SimDouble backend"
    ];

  targetFailures = target: let
    standard = standardForGate target.gate;
    layer = packageLayer target.package;
  in
    lib.optionals (standard == null) [
      "${target.package}:${target.testTarget} has no per-layer testing standard"
    ]
    ++ lib.optionals (standard != null && !(builtins.elem layer standard.layers)) [
      "${target.package}:${target.testTarget} covers ${target.gate} from wrong layer ${layer}"
    ]
    ++ lib.optionals (standard != null && standard.backend == "sim-double" && layer == "L2") [
      "${target.package}:${target.testTarget} must use SimDouble/in-process coverage, not an L2 real-QEMU owner"
    ]
    ++ lib.optionals (standard != null && standard.backend == "real-qemu" && layer != "L2") [
      "${target.package}:${target.testTarget} is a real-QEMU-only gate but is not owned by an L2 crate"
    ]
    ++ lib.optionals (standard != null && standard.backend == "sim-double" && target.package == "crucible" && !(builtins.elem "test-double" target.requiredFeatures)) [
      "${target.package}:${target.testTarget} must run with --features test-double for SimDouble coverage"
    ];

  ownershipFailures =
    lib.concatMap (
      ownership: let
        actual = gatesForPackage ownership.package;
      in
        lib.concatMap (
          required:
            lib.optionals (!(builtins.elem required actual)) [
              "${ownership.package} missing crate-owned layer gate ${required}"
            ]
        )
        ownership.gates
    )
    crateOwnership;

  standardFailures =
    lib.concatMap (
      standard: let
        actualOwners = packagesForGate standard.gate;
        expectedOwners = lib.sort builtins.lessThan standard.ownerPackages;
      in
        lib.optionals (actualOwners != expectedOwners) [
          "${standard.gate} owner package mismatch: expected [${builtins.concatStringsSep ", " expectedOwners}], found [${builtins.concatStringsSep ", " actualOwners}]"
        ]
        ++ lib.optionals (builtins.elem standard.gate hashCompareGates && standard.shape != "twice-reduce-compare-by-hash") [
          "${standard.gate} must use the twice-reduce compare-by-hash shape"
        ]
    )
    standards;

  rustSources = dir: displayPrefix: let
    entries =
      if builtins.pathExists dir
      then builtins.readDir dir
      else {};
  in
    lib.concatMap (
      name: let
        path = dir + "/${name}";
        display = "${displayPrefix}/${name}";
        kind = entries.${name};
      in
        if kind == "directory"
        then rustSources path display
        else if kind == "regular" && lib.hasSuffix ".rs" name
        then [
          {
            inherit path display;
          }
        ]
        else []
    ) (lib.sort builtins.lessThan (builtins.attrNames entries));

  testSourcesForPackage = package: let
    packageDir = cratesDir + "/${package}";
    integrationSources =
      map (
        source:
          source
          // {
            inherit package;
            testTarget = lib.removeSuffix ".rs" (lib.removePrefix "tests/" source.display);
          }
      ) (rustSources (packageDir + "/tests") "tests");
    srcSources = rustSources (packageDir + "/src") "src";
    hasUnitTestModule =
      builtins.any (
        source: let
          content = builtins.readFile source.path;
        in
          hasInfix "#[cfg(test" content || hasInfix "mod tests" content
      )
      srcSources;
    unitSources =
      map (
        source:
          source
          // {
            inherit package;
            testTarget = lib.removeSuffix ".rs" (lib.removePrefix "src/" source.display);
          }
      ) (
        if hasUnitTestModule
        then srcSources
        else []
      );
  in
    builtins.filter (
      source: !(source.package == "crucible-harness" && builtins.elem source.testTarget ["testing_standards" "support/testing_standards"])
    ) (integrationSources ++ unitSources);

  testSources = lib.concatMap (ownership: testSourcesForPackage ownership.package) crateOwnership;

  flakyEscapeFailuresFor = source: let
    content = lowerAscii (builtins.readFile source.path);
  in
    lib.concatMap (
      pattern:
        lib.optionals (hasInfix pattern content) [
          "${source.package}:${source.testTarget} contains flaky-test escape pattern `${pattern}`"
        ]
    )
    flakyEscapePatterns;

  rustHarnessFailures = let
    requiredRustText = [
      "gate_targets_follow_per_layer_testing_standards"
      "gate_target_sources_treat_flaky_as_failing"
      "GATE_TESTING_STANDARDS"
      "HASH_COMPARE_GATES"
      "FLAKY_ESCAPE_PATTERNS"
      "CRATE_TESTING_OWNERSHIP"
      "TwiceReduceCompareByHash"
      "ObservedInjectionIcountVectors"
      "SimDouble"
      "RealQemu"
      "flaky_escape_failures"
      "source_shape_failures"
      "assert_twice_reduce_canonical_digest("
      "testing_standard_regression_failures"
    ];
  in
    lib.concatMap (
      required:
        lib.optionals (!(hasInfix required testingStandardsCode)) [
          "crates/crucible-harness/tests/testing_standards.rs: missing testing-standard wiring `${required}`"
        ]
    )
    requiredRustText;

  regressionFailures = let
    wrongLayerTarget = {
      gate = "gate:replay-oracle";
      package = "crucible-qemu";
      testTarget = "gate_replay_oracle";
      requiredFeatures = [];
    };
    unknownTarget = {
      gate = "gate:unknown";
      package = "crucible-harness";
      testTarget = "unknown_gate";
      requiredFeatures = [];
    };
    unshapedTarget = {
      gate = "gate:replay-oracle";
      package = "crucible";
      testTarget = "gate_replay_oracle";
      requiredFeatures = ["test-double"];
    };
    findings =
      targetFailures wrongLayerTarget
      ++ targetFailures unknownTarget
      ++ sourceShapeFailures unshapedTarget (standardForGate "gate:replay-oracle") ''
        // assert_twice_reduce_canonical_digest(canonical_digest);
        // SimDouble
        fn bad() {
          assert_twice_reduce_canonical_digest(|| canonical_digest());
          assert_eq!(human_formatted_dump(), human_formatted_dump());
        }
      ''
      ++ [
        "crucible-assert missing crate-owned layer gate gate:layer0-determinism"
      ];
    hasFinding = needle: builtins.any (finding: hasInfix needle finding) findings;
  in
    lib.optionals (!(hasFinding "wrong layer")) [
      "testing-standard regression failed to reject higher/lower layer ownership drift"
    ]
    ++ lib.optionals (!(hasFinding "SimDouble")) [
      "testing-standard regression failed to reject missing SimDouble ownership"
    ]
    ++ lib.optionals (!(hasFinding "no per-layer testing standard")) [
      "testing-standard regression failed to reject unknown gate standard"
    ]
    ++ lib.optionals (!(hasFinding "canonical digests")) [
      "testing-standard regression failed to reject non-hash determinism assertions"
    ]
    ++ lib.optionals (!(hasFinding "SimDouble backend")) [
      "testing-standard regression failed to reject missing SimDouble body coverage"
    ]
    ++ lib.optionals (!(hasFinding "crucible-assert missing crate-owned layer gate")) [
      "testing-standard regression failed to reject missing per-crate ownership"
    ];

  failures =
    lib.concatMap targetFailures targets
    ++ ownershipFailures
    ++ standardFailures
    ++ lib.concatMap (
      target: let
        standard = standardForGate target.gate;
        path = cratesDir + "/${target.package}/tests/${target.testTarget}.rs";
      in
        if standard == null || !(builtins.pathExists path)
        then []
        else sourceShapeFailures target standard (builtins.readFile path)
    )
    targets
    ++ lib.concatMap flakyEscapeFailuresFor testSources
    ++ rustHarnessFailures
    ++ regressionFailures;
in
  if failures != []
  then throw "crucible phase1 testing-standards lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-testing-standards";
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
            check=checks.crucible.phase1.testingStandards
            gate=gate:harness-lint
            tasks=T-STD-8
            test_shape=twice-reduce-compare-by-hash
            flaky_policy=flaky-is-failing
            simdouble_scope=L1,L3,L4
            RESULT
          '';
        }
      ];
    }

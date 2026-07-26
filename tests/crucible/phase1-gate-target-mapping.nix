{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;

  targets = [
    {
      gate = "gate:harness-lint";
      package = "crucible-harness";
      testTarget = "harness_lint";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:layer0-determinism";
      package = "crucible-sim";
      testTarget = "gate_layer0_determinism";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:layer0-determinism";
      package = "crucible-assert";
      testTarget = "gate_layer0_determinism";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:layer0-determinism";
      package = "crucible";
      testTarget = "gate_layer0_determinism";
      requiredFeatures = ["test-double"];
      placeholder = false;
    }
    {
      gate = "gate:single-vm-fingerprint";
      package = "crucible";
      testTarget = "gate_single_vm_fingerprint";
      requiredFeatures = ["test-double"];
      placeholder = false;
    }
    {
      gate = "gate:single-vm-fingerprint";
      package = "crucible-qemu";
      testTarget = "gate_single_vm_fingerprint";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:single-vm-fingerprint";
      package = "crucible-qemu-plugin";
      testTarget = "gate_single_vm_fingerprint";
      requiredFeatures = [];
      placeholder = true;
    }
    {
      gate = "gate:single-vm-fingerprint";
      package = "crucible-guest";
      testTarget = "gate_single_vm_fingerprint";
      requiredFeatures = [];
      placeholder = true;
    }
    {
      gate = "gate:layer1-injection";
      package = "crucible-device";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:layer1-injection";
      package = "crucible-protocol";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:layer1-injection";
      package = "crucible-shmem";
      testTarget = "gate_layer1_injection";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible-harness";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible-shmem";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible-protocol";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible-api";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible-qemu-plugin";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible-guest";
      testTarget = "gate_abi_conformance";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:abi-conformance";
      package = "crucible";
      testTarget = "gate_abi_conformance";
      requiredFeatures = ["test-double"];
      placeholder = false;
    }
    {
      gate = "gate:replay-oracle";
      package = "crucible";
      testTarget = "gate_replay_oracle";
      requiredFeatures = ["test-double"];
      placeholder = false;
    }
    {
      gate = "gate:content-address";
      package = "crucible";
      testTarget = "gate_content_address";
      requiredFeatures = ["test-double"];
      placeholder = false;
    }
    {
      gate = "gate:content-address";
      package = "crucible-sim";
      testTarget = "gate_content_address";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:scheduler-liveness";
      package = "crucible";
      testTarget = "gate_scheduler_liveness";
      requiredFeatures = ["test-double"];
      placeholder = false;
    }
    {
      gate = "gate:control-responsive";
      package = "crucible-session";
      testTarget = "gate_control_responsive";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:control-responsive";
      package = "crucible-api";
      testTarget = "gate_control_responsive";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:control-responsive";
      package = "crucible-daemon";
      testTarget = "gate_control_responsive";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:any-guest";
      package = "crucible-qemu";
      testTarget = "gate_any_guest";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:qemu-inert";
      package = "crucible-qemu";
      testTarget = "gate_qemu_inert";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:qemu-inert";
      package = "crucible-qemu-plugin";
      testTarget = "gate_qemu_inert";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:patch-microtests";
      package = "crucible-qemu-plugin";
      testTarget = "gate_patch_microtests";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:divergence-bisect";
      package = "crucible-harness";
      testTarget = "gate_divergence_bisect";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:adversarial-determinism";
      package = "crucible";
      testTarget = "gate_adversarial_determinism";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:e2e-determinism";
      package = "crucible";
      testTarget = "gate_e2e_determinism_concurrency";
      requiredFeatures = ["test-double"];
      placeholder = false;
    }
    {
      gate = "gate:e2e-determinism";
      package = "crucible-cli";
      testTarget = "gate_e2e_determinism";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:fleet-equivalence";
      package = "crucible";
      testTarget = "gate_fleet_equivalence";
      requiredFeatures = ["test-double"];
      placeholder = false;
    }
    {
      gate = "gate:campaign-continuity";
      package = "crucible-cas";
      testTarget = "gate_campaign_continuity";
      requiredFeatures = [];
      placeholder = false;
    }
    {
      gate = "gate:perf-bench";
      package = "crucible-harness";
      testTarget = "gate_perf_bench";
      requiredFeatures = [];
      placeholder = false;
    }
  ];

  canonicalGates = [
    "gate:harness-lint"
    "gate:layer0-determinism"
    "gate:single-vm-fingerprint"
    "gate:layer1-injection"
    "gate:content-address"
    "gate:replay-oracle"
    "gate:divergence-bisect"
    "gate:scheduler-liveness"
    "gate:control-responsive"
    "gate:any-guest"
    "gate:qemu-inert"
    "gate:abi-conformance"
    "gate:patch-microtests"
    "gate:adversarial-determinism"
    "gate:e2e-determinism"
    "gate:perf-bench"
    "gate:fleet-equivalence"
    "gate:campaign-continuity"
  ];

  crucibleTestDoubleGates = [
    "gate:layer0-determinism"
    "gate:single-vm-fingerprint"
    "gate:abi-conformance"
    "gate:replay-oracle"
    "gate:content-address"
    "gate:scheduler-liveness"
    "gate:e2e-determinism"
    "gate:fleet-equivalence"
  ];

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

  targetFailuresWithManifest = target: manifest: let
    packageDir = cratesDir + "/${target.package}";
    testPath = packageDir + "/tests/${target.testTarget}.rs";
    content =
      if builtins.pathExists testPath
      then builtins.readFile testPath
      else "";
    requiresTestDouble =
      target.package == "crucible"
      && builtins.elem target.gate crucibleTestDoubleGates;
    manifestTargetHasRequiredFeature =
      builtins.any (
        cargoTest:
          cargoTest
          ? name
          && cargoTest.name == target.testTarget
          && cargoTest ? "required-features"
          && builtins.elem "test-double" cargoTest."required-features"
      ) (
        if manifest ? test
        then manifest.test
        else []
      );
    manifestTargetHasPath =
      builtins.any (
        cargoTest:
          cargoTest
          ? name
          && cargoTest.name == target.testTarget
          && cargoTest ? path
          && cargoTest.path == "tests/${target.testTarget}.rs"
      ) (
        if manifest ? test
        then manifest.test
        else []
      );
  in
    lib.optionals (!(builtins.pathExists (packageDir + "/Cargo.toml"))) [
      "${target.package}: package for ${target.gate} does not exist"
    ]
    ++ lib.optionals (!(builtins.elem target.gate canonicalGates)) [
      "${target.package}:${target.testTarget} references unknown canonical gate ${target.gate}"
    ]
    ++ lib.optionals (!(builtins.pathExists testPath)) [
      "crates/${target.package}/tests/${target.testTarget}.rs: missing integration test target for ${target.gate}"
    ]
    ++ lib.optionals (target.placeholder && builtins.pathExists testPath && (!(hasInfix "#[ignore" content) || !(hasInfix "panic!" content))) [
      "crates/${target.package}/tests/${target.testTarget}.rs: placeholder gate target must be ignored and fail when explicitly run"
    ]
    ++ lib.optionals ((!target.placeholder) && builtins.pathExists testPath && hasInfix "#[ignore" content) [
      "crates/${target.package}/tests/${target.testTarget}.rs: implemented gate target must not be ignored"
    ]
    ++ lib.optionals (requiresTestDouble && target.requiredFeatures != ["test-double"]) [
      "${target.package}:${target.testTarget} must run with --features test-double"
    ]
    ++ lib.optionals (requiresTestDouble && !manifestTargetHasRequiredFeature) [
      "${target.package}:${target.testTarget} Cargo manifest must set required-features = [\"test-double\"]"
    ]
    ++ lib.optionals (requiresTestDouble && !manifestTargetHasPath) [
      "${target.package}:${target.testTarget} Cargo manifest must set path = \"tests/${target.testTarget}.rs\""
    ];

  targetFailures = target: let
    packageDir = cratesDir + "/${target.package}";
    manifest = builtins.fromTOML (builtins.readFile (packageDir + "/Cargo.toml"));
  in
    targetFailuresWithManifest target manifest;

  mappingRegressionFailures = let
    findings =
      targetFailuresWithManifest {
        gate = "gate:replay-oracle";
        package = "crucible";
        testTarget = "gate_replay_oracle";
        requiredFeatures = ["test-double"];
        placeholder = true;
      } {
        test = [];
      }
      ++ lib.concatMap targetFailures [
        {
          gate = "gate:replay-oracle";
          package = "crucible";
          testTarget = "gate_replay_oracle";
          requiredFeatures = [];
          placeholder = true;
        }
        {
          gate = "gate:unknown";
          package = "crucible-harness";
          testTarget = "unknown_gate";
          requiredFeatures = [];
          placeholder = true;
        }
      ];
    hasFinding = needle:
      builtins.any (finding: hasInfix needle finding) findings;
  in
    lib.optionals (!(hasFinding "--features test-double")) [
      "gate-target mapping regression failed to reject missing test-double feature"
    ]
    ++ lib.optionals (!(hasFinding "required-features")) [
      "gate-target mapping regression failed to reject missing Cargo required-features"
    ]
    ++ lib.optionals (!(hasFinding "must set path")) [
      "gate-target mapping regression failed to reject missing Cargo test path"
    ]
    ++ lib.optionals (!(hasFinding "unknown canonical gate")) [
      "gate-target mapping regression failed to reject unknown gate"
    ];

  failures = lib.concatMap targetFailures targets ++ mappingRegressionFailures;
in
  if failures != []
  then throw "crucible phase1 gate-target mapping lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-gate-target-mapping";
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
            check=checks.crucible.phase1.gateTargetMapping
            tasks=T-CRATE-12
            engine_features=test-double
            placeholder_targets=0
            RESULT
          '';
        }
      ];
    }

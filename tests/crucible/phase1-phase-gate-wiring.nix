{
  pkgs,
  lib,
}: let
  defaultSource = builtins.readFile ./default.nix;
  testingAndGatesDoc = builtins.readFile ../../docs/engineering/crucible/testing-and-gates.md;

  # The documented gate ordering is the first text block under "## Gate
  # ordering"; each line reads `phaseN  gate:name  checks.crucible.attr.path`.
  orderingSectionParts = lib.splitString "\n## Gate ordering\n" testingAndGatesDoc;
  orderingSection =
    if builtins.length orderingSectionParts >= 2
    then builtins.elemAt orderingSectionParts 1
    else "";
  orderingBlockParts = lib.splitString "```" orderingSection;
  orderingBlock =
    if builtins.length orderingBlockParts >= 2
    then lib.removePrefix "text\n" (builtins.elemAt orderingBlockParts 1)
    else "";
  orderingEntries =
    builtins.filter (words: words != [])
    (map (line: builtins.filter (word: word != "") (lib.splitString " " line))
      (lib.splitString "\n" orderingBlock));

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  gateNameFromCatalogLine = line: let
    matched = builtins.match ".*`(gate:[a-z0-9-]+)`.*" line;
  in
    if matched == null
    then []
    else matched;

  catalogGateLines =
    builtins.filter (line: lib.hasPrefix "| `gate:" line) (lib.splitString "\n" testingAndGatesDoc);
  catalogGates =
    builtins.sort builtins.lessThan
    (lib.unique (lib.concatMap gateNameFromCatalogLine catalogGateLines));
  wiredCatalogGates = catalogGates;

  phaseGateTargets = [
    {
      phase = "phase1";
      attr = "licenseBoundary";
      gate = "gate:license-boundary";
    }
    {
      phase = "phase0";
      attr = "blockers";
      label = "phase0:blockers";
    }
    {
      phase = "phase1";
      attr = "harnessLint";
      gate = "gate:harness-lint";
    }
    {
      phase = "phase1";
      attr = "layer0Determinism";
      gate = "gate:layer0-determinism";
    }
    {
      phase = "phase1";
      attr = "contentAddress";
      gate = "gate:content-address";
    }
    {
      phase = "phase1";
      attr = "campaignModel";
      gate = "gate:campaign-model";
    }
    {
      phase = "phase1";
      attr = "replayOracle";
      gate = "gate:replay-oracle";
    }
    {
      phase = "phase1";
      attr = "singleVmFingerprint";
      gate = "gate:single-vm-fingerprint";
    }
    {
      phase = "phase1";
      attr = "divergenceBisect";
      gate = "gate:divergence-bisect";
    }
    {
      phase = "phase2";
      attr = "abiConformance";
      gate = "gate:abi-conformance";
    }
    {
      phase = "phase2";
      attr = "typedChoice";
      gate = "gate:typed-choice";
    }
    {
      phase = "phase2";
      attr = "layer1Injection";
      gate = "gate:layer1-injection";
    }
    {
      phase = "phase2";
      attr = "patchMicrotests";
      gate = "gate:patch-microtests";
    }
    {
      phase = "phase2";
      attr = "qemuInert";
      gate = "gate:qemu-inert";
    }
    {
      phase = "phase2";
      attr = "singleVmFingerprint";
      gate = "gate:single-vm-fingerprint";
    }
    {
      phase = "phase2";
      attr = "anyGuest";
      gate = "gate:any-guest";
    }
    {
      phase = "phase3";
      attr = "layer1Injection";
      gate = "gate:layer1-injection";
    }
    {
      phase = "phase3";
      attr = "schedulerLiveness";
      gate = "gate:scheduler-liveness";
    }
    {
      phase = "phase3";
      attr = "adversarialDeterminism";
      gate = "gate:adversarial-determinism";
    }
    {
      phase = "phase4";
      attr = "replayOracle";
      gate = "gate:replay-oracle";
    }
    {
      phase = "phase4";
      attr = "campaignStatistics";
      gate = "gate:campaign-statistics";
    }
    {
      phase = "phase4";
      attr = "e2eDeterminism";
      gate = "gate:e2e-determinism";
    }
    {
      phase = "phase5";
      attr = "controlResponsive";
      gate = "gate:control-responsive";
    }
    {
      phase = "phase6";
      attr = "replayOracle";
      gate = "gate:replay-oracle";
    }
    {
      phase = "phase6";
      attr = "basicBlockCoverage";
      attrPath = "checks.crucible.phase6.basicBlockCoverage";
      gate = "gate:basic-block-coverage";
    }
    {
      phase = "phase6";
      attr = "checkpointMaterialization";
      attrPath = "checks.crucible.phase6.checkpointMaterialization";
      gate = "gate:checkpoint-materialization";
    }
    {
      phase = "phase6";
      attr = "stateSpaceSearch";
      attrPath = "checks.crucible.phase6.stateSpaceSearch";
      gate = "gate:state-space-search";
    }
    {
      phase = "phase7";
      attr = "perfBench";
      gate = "gate:perf-bench";
    }
    {
      phase = "phase7";
      attr = "e2eDeterminism";
      gate = "gate:e2e-determinism";
    }
    {
      phase = "phase7";
      attr = "fleetEquivalence";
      gate = "gate:fleet-equivalence";
    }
    {
      phase = "phase7";
      attr = "campaignContinuity";
      gate = "gate:campaign-continuity";
    }
    {
      phase = "phase7";
      attr = "productionRustPluginFlight";
      attrPath = "checks.crucible.phase7.productionRustPluginFlight";
      gate = "gate:production-rust-plugin-flight";
    }
    {
      phase = "phase7";
      attr = "signalFaultSystem";
      gate = "gate:signal-fault-system";
    }
  ];

  targetAttrPath = target:
    if target ? attrPath
    then target.attrPath
    else "checks.crucible.${target.phase}.gates.${target.attr}";
  targetName = target:
    if target ? gate
    then target.gate
    else target.label;
  expectedGateNames =
    builtins.sort builtins.lessThan
    (lib.unique (builtins.filter (name: name != null) (map (target:
      if target ? gate
      then target.gate
      else null)
    phaseGateTargets)));

  missingCatalogWiring =
    builtins.filter (gate: !(builtins.elem gate expectedGateNames)) wiredCatalogGates;
  unknownPhaseGates =
    builtins.filter (gate: !(builtins.elem gate catalogGates)) expectedGateNames;

  targetFailures = lib.concatMap (target: let
    attrPath = targetAttrPath target;
    gateOrLabel = targetName target;
  in
    lib.optionals (!(hasInfix "attrPath = \"${attrPath}\"" defaultSource)) [
      "${attrPath}: phase gate target is not wired in tests/crucible/default.nix"
    ]
    ++ lib.optionals (!(builtins.elem [target.phase gateOrLabel attrPath] orderingEntries)) [
      "${gateOrLabel}: ${target.phase} occurrence at ${attrPath} is absent from the gate ordering in docs/engineering/crucible/testing-and-gates.md"
    ]
    ++ lib.optionals (target ? gate && !(builtins.elem target.gate catalogGates)) [
      "${target.gate}: phase gate is absent from the canonical gate catalog"
    ])
  phaseGateTargets;

  failures =
    targetFailures
    ++ map (gate: "${gate}: catalog gate is not assigned to a phase exit target") missingCatalogWiring
    ++ map (gate: "${gate}: phase exit target is not in the canonical gate catalog") unknownPhaseGates;
in
  if failures != []
  then throw "crucible phase-gate wiring lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-phase-gate-wiring";
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
            check=checks.crucible.phase1.phaseGateWiring
            tasks=T-PLAN-3
            status=complete
            phase_gate_targets=${toString (builtins.length phaseGateTargets)}
            canonical_gates=${toString (builtins.length catalogGates)}
            RESULT
          '';
        }
      ];
    }

{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleGateCiWiring",
  taskIds ? ["T-PKG-14"],
  dependencies ? [],
}: let
  rootDefault = builtins.readFile ../../default.nix;
  flake = builtins.readFile ../../flake.nix;
  defaultChecks = builtins.readFile ./default.nix;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  phasePlan = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  gateCatalog = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  phasePlanRust = builtins.readFile ../../crates/crucible-harness/src/phase_plan.rs;
  harnessLint = builtins.readFile ./phase1-harness-lint.nix;
  layer0Determinism = builtins.readFile ./phase1-layer0-determinism.nix;
  contentAddress = builtins.readFile ./phase1-content-address.nix;
  replayOracle = builtins.readFile ./phase1-replay-oracle.nix;
  layer1Injection = builtins.readFile ./phase1-layer1-injection.nix;
  abiConformance = builtins.readFile ./phase2-abi-conformance.nix;
  patchMicrotests = builtins.readFile ./phase2-patch-microtests.nix;
  qemuInert = builtins.readFile ./phase2-qemu-inert.nix;
  phase7E2e = builtins.readFile ./phase7-e2e-determinism.nix;

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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  evalClassGates = [
    {
      gate = "gate:harness-lint";
      path = "checks.crucible.phase1.gates.harnessLint";
      sourceLabel = "tests/crucible/phase1-harness-lint.nix";
      source = harnessLint;
    }
    {
      gate = "gate:layer0-determinism";
      path = "checks.crucible.phase1.gates.layer0Determinism";
      sourceLabel = "tests/crucible/phase1-layer0-determinism.nix";
      source = layer0Determinism;
    }
    {
      gate = "gate:content-address";
      path = "checks.crucible.phase1.gates.contentAddress";
      sourceLabel = "tests/crucible/phase1-content-address.nix";
      source = contentAddress;
    }
    {
      gate = "gate:replay-oracle";
      path = "checks.crucible.phase1.gates.replayOracle";
      sourceLabel = "tests/crucible/phase1-replay-oracle.nix";
      source = replayOracle;
    }
    {
      gate = "gate:abi-conformance";
      path = "checks.crucible.phase2.gates.abiConformance";
      sourceLabel = "tests/crucible/phase2-abi-conformance.nix";
      source = abiConformance;
    }
    {
      gate = "gate:layer1-injection";
      path = "checks.crucible.phase2.gates.layer1Injection";
      sourceLabel = "tests/crucible/phase1-layer1-injection.nix";
      source = layer1Injection;
    }
  ];

  packageClassGates = [
    {
      gate = "gate:patch-microtests";
      path = "checks.crucible.phase2.gates.patchMicrotests";
      packagePath = "checks.integration.qemu-crucible-patch-microtests";
    }
    {
      gate = "gate:qemu-inert";
      path = "checks.crucible.phase2.gates.qemuInert";
      packagePath = "checks.integration.qemu-crucible-qemu-inert";
    }
  ];

  expectedOrderingEdges = [
    {
      label = "L0 waits for harness lint";
      edge = "gate:harness-lint->gate:layer0-determinism";
      needle = "dependencies = [harnessLint.rawGate];";
    }
    {
      label = "content-address waits for L0";
      edge = "gate:layer0-determinism->gate:content-address";
      needle = "dependencies = [layer0Determinism.rawGate];";
    }
    {
      label = "replay-oracle waits for content-address";
      edge = "gate:content-address->gate:replay-oracle";
      needle = "dependencies = [contentAddress.rawGate phase1.simDouble];";
    }
    {
      label = "ABI gate waits for phase1 gates";
      edge = "phase1-gates->gate:abi-conformance";
      needle = "phase1.gates.divergenceBisect.rawGate";
    }
    {
      label = "L1 injection waits for ABI";
      edge = "gate:abi-conformance->gate:layer1-injection";
      needle = "dependencies = [abiConformance.rawGate];";
    }
    {
      label = "patch microtests wait for L1";
      edge = "gate:layer1-injection->gate:patch-microtests";
      needle = "dependencies = [layer1Injection.rawGate];";
    }
    {
      label = "qemu-inert waits for patch microtests";
      edge = "gate:patch-microtests->gate:qemu-inert";
      needle = "dependencies = [patchMicrotests.rawGate];";
    }
    {
      label = "phase7 e2e waits for perf and package inputs";
      edge = "gate:perf-bench+package-inputs->gate:e2e-determinism";
      needle = "dependencies = [perfBench.rawGate phase7.crucibleLinuxKernel phase7.crucibleFixtures phase7.crucibleGateCiWiring];";
    }
    {
      label = "phase7 e2e wrapper waits for package inputs";
      edge = "gate:perf-bench-wrapper+package-inputs->gate:e2e-determinism-wrapper";
      needle = "dependencies = [perfBench phase7.crucibleLinuxKernel phase7.crucibleFixtures phase7.crucibleGateCiWiring];";
    }
    {
      label = "fleet equivalence waits for e2e";
      edge = "gate:e2e-determinism->gate:fleet-equivalence";
      needle = "dependencies = [e2eDeterminism.rawGate];";
    }
    {
      label = "campaign continuity waits for fleet equivalence";
      edge = "gate:fleet-equivalence->gate:campaign-continuity";
      needle = "dependencies = [fleetEquivalence.rawGate];";
    }
  ];

  allClassifiedGates = evalClassGates ++ packageClassGates ++ [
    {
      gate = "gate:e2e-determinism";
      path = "checks.crucible.phase7.gates.e2eDeterminism";
    }
  ];

  gateCatalogFailures = lib.concatMap (gate:
    failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" gateCatalog [
      {
        label = "${gate.gate} catalog entry";
        needle = "`" + gate.gate + "`";
      }
    ])
  allClassifiedGates;

  phasePlanFailures = lib.concatMap (gate:
    failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" phasePlan [
      {
        label = "${gate.gate} phase ladder entry";
        needle = gate.gate;
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/phase_plan.rs" phasePlanRust [
      {
        label = "${gate.path} canonical phase-plan target";
        needle = "\"" + gate.path + "\"";
      }
    ])
  allClassifiedGates;

  evalClassFailures = lib.concatMap (gate:
    failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "${gate.path} AOS check attrPath";
        needle = ''attrPath = "${gate.path}";'';
      }
    ]
    ++ forbiddenFor gate.sourceLabel gate.source [
      {
        label = "QEMU package dependency in eval-class gate";
        needle = "pkgs.qemu-crucible";
      }
      {
        label = "fleet harness dependency in eval-class gate";
        needle = "mkFleetTest";
      }
      {
        label = "KVM feature requirement in eval-class gate";
        needle = "requiredSystemFeatures";
      }
    ])
  evalClassGates;

  packageClassFailures =
    failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "patch-microtests AOS check attrPath";
        needle = ''attrPath = "checks.crucible.phase2.gates.patchMicrotests";'';
      }
      {
        label = "patch-microtests gate import";
        needle = "gate = import ./phase2-patch-microtests.nix";
      }
      {
        label = "patch-microtests waits for layer1 injection";
        needle = "dependencies = [layer1Injection.rawGate];";
      }
      {
        label = "qemu-inert AOS check attrPath";
        needle = ''attrPath = "checks.crucible.phase2.gates.qemuInert";'';
      }
      {
        label = "qemu-inert gate import";
        needle = "gate = import ./phase2-qemu-inert.nix";
      }
      {
        label = "qemu-inert waits for patch microtests";
        needle = "dependencies = [patchMicrotests.rawGate];";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-patch-microtests.nix" patchMicrotests [
      {
        label = "patch-microtests accept package check QEMU";
        needle = "qemuPackage ? pkgs.qemu-crucible,";
      }
      {
        label = "patch-microtests record package path";
        needle = "patched_qemu_package=\${qemuPackage}";
      }
      {
        label = "patch-microtests record qemu-inert dependency edge";
        needle = "qemu_inert_gate_dependency=gate:qemu-inert->gate:patch-microtests";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-inert.nix" qemuInert [
      {
        label = "qemu-inert accepts reference package";
        needle = "referenceQemu ? pkgs.qemu-crucible-reference,";
      }
      {
        label = "qemu-inert accepts patched package";
        needle = "patchedQemu ? pkgs.qemu-crucible,";
      }
      {
        label = "qemu-inert consumes patch microtests result";
        needle = ''PATCH_MICROTESTS_RESULT = "''${patchMicrotests}/result";'';
      }
      {
        label = "qemu-inert records patched package path";
        needle = "patched_qemu=\${patchedQemu}";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "package check collector detects package checks";
        needle = "pkg ? checks && builtins.isFunction pkg.checks";
      }
      {
        label = "package check collector prefixes package name";
        needle = "prefixAttrs name (";
      }
      {
        label = "package checks exposed in integration namespace";
        needle = "integration = packageChecks // stdenvChecks;";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "qemu-crucible package checks function";
        needle = "checks = {testing, self, pkgs}:";
      }
      {
        label = "package checks limited to qemu-crucible";
        needle = ''if pname == "qemu-crucible"'';
      }
      {
        label = "package patch-microtests import";
        needle = "import ../../tests/crucible/phase2-patch-microtests.nix";
      }
      {
        label = "package qemu-inert import";
        needle = "import ../../tests/crucible/phase2-qemu-inert.nix";
      }
      {
        label = "package patch-microtests integration attrPath";
        needle = ''attrPath = "checks.integration.qemu-crucible-patch-microtests";'';
      }
      {
        label = "package patch-microtests uses package self";
        needle = "qemuPackage = self;";
      }
      {
        label = "package qemu-inert integration attrPath";
        needle = ''attrPath = "checks.integration.qemu-crucible-qemu-inert";'';
      }
      {
        label = "package qemu-inert uses package self";
        needle = "patchedQemu = self;";
      }
      {
        label = "package qemu-inert uses reference package";
        needle = "referenceQemu = pkgs.qemu-crucible-reference;";
      }
      {
        label = "package qemu-inert consumes package patch microtests";
        needle = "inherit patchMicrotests;";
      }
      {
        label = "package qemu-inert waits for package patch microtests";
        needle = "dependencies = [patchMicrotests];";
      }
    ]
    ++ forbiddenFor "tests/crucible/phase2-patch-microtests.nix" patchMicrotests [
      {
        label = "KVM feature requirement";
        needle = "requiredSystemFeatures";
      }
    ]
    ++ forbiddenFor "tests/crucible/phase2-qemu-inert.nix" qemuInert [
      {
        label = "KVM feature requirement";
        needle = "requiredSystemFeatures";
      }
    ];

  orderingFailures =
    failuresFor "tests/crucible/default.nix" defaultChecks
    (map (edge: {inherit (edge) label needle;}) expectedOrderingEdges);

  aosSurfaceFailures =
    failuresFor "default.nix" rootDefault [
      {
        label = "Crucible checks exposed in AOS checks tree";
        needle = "crucible = crucibleChecks;";
      }
      {
        label = "Crucible e2e fleet wrapper defined";
        needle = "crucible-e2e-determinism = let";
      }
      {
        label = "fleet wrapper consumes Crucible e2e gate";
        needle = "e2eGate = crucibleChecks.phase7.gates.e2eDeterminism.rawGate;";
      }
      {
        label = "fleet wrapper verifies e2e fleet metadata";
        needle = "grep -q '^fleet_check_surface=checks.fleet.crucible-e2e-determinism$'";
      }
      {
        label = "fleet checks exposed with Crucible e2e surface";
        needle = "fleet = discoverFleetTests // crucibleFleetChecks;";
      }
    ]
    ++ failuresFor "flake.nix" flake [
      {
        label = "flake exposes fleet checks";
        needle = ''// prefixAttrs "fleet" aos.checks.fleet'';
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "T-PKG-14 wiring guard is exposed";
        needle = ''attrPath = "checks.crucible.phase7.crucibleGateCiWiring";'';
      }
      {
        label = "phase7 e2e gate import";
        needle = "gate = import ./phase7-e2e-determinism.nix";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-e2e-determinism.nix" phase7E2e [
      {
        label = "phase7 acceptance gate records fleet handoff";
        needle = "real_host_reproduction=deferred-to-packaging-and-fleet-gates";
      }
      {
        label = "phase7 acceptance gate records fleet check class";
        needle = "ci_check_class=fleet-check-surface";
      }
      {
        label = "phase7 acceptance gate records fleet check surface";
        needle = "fleet_check_surface=checks.fleet.crucible-e2e-determinism";
      }
      {
        label = "phase7 acceptance gate records CI wiring guard";
        needle = "ci_wiring_guard=checks.crucible.phase7.crucibleGateCiWiring";
      }
    ];

  docFailures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "PKG-27 eval-class mapping";
        needle = "the **pure/eval-level**";
      }
      {
        label = "PKG-27 package-class mapping";
        needle = "**QEMU-backed** gates";
      }
      {
        label = "PKG-27 e2e VM/fleet mapping";
        needle = "the **e2e** gate";
      }
      {
        label = "T-PKG-14 checklist complete";
        needle = "- [x] **T-PKG-14**";
      }
      {
        label = "T-PKG-14 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleGateCiWiring`";
      }
    ];

  failures =
    gateCatalogFailures
    ++ phasePlanFailures
    ++ evalClassFailures
    ++ packageClassFailures
    ++ orderingFailures
    ++ aosSurfaceFailures
    ++ docFailures;
in
  if failures != []
  then throw "crucible phase7 gate CI wiring check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-gate-ci-wiring";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils] ++ dependencies;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            eval_class_gates=${builtins.concatStringsSep "," (map (gate: gate.gate) evalClassGates)}
            package_class_gates=${builtins.concatStringsSep "," (map (gate: gate.gate) packageClassGates)}
            e2e_gate=gate:e2e-determinism
            e2e_gate_class=fleet-check-surface
            ordering_source=checked-gate-targets-and-explicit-default.nix-dependencies
            ordering_edges=${builtins.concatStringsSep "," (map (edge: edge.edge) expectedOrderingEdges)}
            ci_ordering=green-before-advance
            qemu_package_checks=${builtins.concatStringsSep "," (map (gate: gate.packagePath) packageClassGates)}
            fleet_check_surface=checks.fleet.crucible-e2e-determinism
            RESULT
          '';
        }
      ];
    }

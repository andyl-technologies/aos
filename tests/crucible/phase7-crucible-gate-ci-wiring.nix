{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleGateCiWiring",
  taskIds ? ["T-PKG-14"],
  openTaskIds ? [],
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
  phase7FleetEquivalence = builtins.readFile ./phase7-crucible-fleet-equivalence.nix;
  phase7CampaignContinuity = builtins.readFile ./phase7-crucible-campaign-continuity.nix;

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
      edge = "gate:perf-bench+package-inputs+release-manifest+reproduction-provenance->gate:e2e-determinism";
      needle = "dependencies = [perfBench.rawGate phase7.crucibleLinuxKernel phase7.crucibleFixtures phase7.crucibleGateCiWiring phase7.crucibleReleaseManifest phase7.reproductionProvenanceTriple];";
    }
    {
      label = "phase7 e2e wrapper waits for package inputs";
      edge = "gate:perf-bench-wrapper+package-inputs+release-manifest+reproduction-provenance->gate:e2e-determinism-wrapper";
      needle = "dependencies = [perfBench phase7.crucibleLinuxKernel phase7.crucibleFixtures phase7.crucibleGateCiWiring phase7.crucibleReleaseManifest phase7.reproductionProvenanceTriple];";
    }
    {
      label = "fleet equivalence waits for real-QEMU slice, e2e, fleet store, shared DagStore, frontier leases, four-layer dedup, determinism guardrail, and seam proof";
      edge = "gate:single-vm-fingerprint-real-qemu+gate:e2e-determinism+fleet-store+shared-dag-store+frontier-leases+four-layer-dedup+determinism-guardrail+same-seam->gate:fleet-equivalence";
      needle = "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
    }
    {
      label = "fleet equivalence wrapper waits for real-QEMU slice, e2e, fleet store, shared DagStore, frontier leases, four-layer dedup, determinism guardrail, and seam proof";
      edge = "gate:single-vm-fingerprint-real-qemu-wrapper+gate:e2e-determinism-wrapper+fleet-store+shared-dag-store+frontier-leases+four-layer-dedup+determinism-guardrail+same-seam->gate:fleet-equivalence-wrapper";
      needle = "dependencies = [phase2.gates.singleVmFingerprint e2eDeterminism phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
    }
    {
      label = "campaign continuity waits for fleet equivalence, campaign manifest, campaign seeding, storage bounding, and campaign provenance";
      edge = "gate:fleet-equivalence+campaign-manifest+campaign-seeding+campaign-storage-bounding+campaign-provenance->gate:campaign-continuity";
      needle = "dependencies = [fleetEquivalence.rawGate phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";
    }
    {
      label = "campaign continuity wrapper waits for fleet equivalence, campaign manifest, campaign seeding, storage bounding, and campaign provenance";
      edge = "gate:fleet-equivalence-wrapper+campaign-manifest+campaign-seeding+campaign-storage-bounding+campaign-provenance->gate:campaign-continuity-wrapper";
      needle = "dependencies = [fleetEquivalence phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";
    }
  ];

  allClassifiedGates =
    evalClassGates
    ++ packageClassGates
    ++ [
      {
        gate = "gate:e2e-determinism";
        path = "checks.crucible.phase7.gates.e2eDeterminism";
      }
      {
        gate = "gate:fleet-equivalence";
        path = "checks.crucible.phase7.gates.fleetEquivalence";
      }
      {
        gate = "gate:campaign-continuity";
        path = "checks.crucible.phase7.gates.campaignContinuity";
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
      {
        label = "qemu-inert compares raw TCG guest serial";
        needle = ''compare_files boot-tcg-raw "$TMPDIR/serial-reference-tcg.log" "$TMPDIR/serial-patched-tcg.log"'';
      }
      {
        label = "qemu-inert compares raw plain-icount guest serial";
        needle = ''compare_files boot-plain-icount-raw "$TMPDIR/serial-reference-icount.log" "$TMPDIR/serial-patched-icount.log"'';
      }
      {
        label = "qemu-inert disables guest printk timestamps before capture";
        needle = "printk.time=0";
      }
      {
        label = "qemu-inert exercises normalization masking negative control";
        needle = "exercise_serial_normalization_negative_control";
      }
      {
        label = "qemu-inert records completed status";
        needle = "status=complete";
      }
      {
        label = "qemu-inert owns completed RFC tasks";
        needle = ''taskIds ? ["T-DET-23" "T-HARN-21" "T-PATCH-3"]'';
      }
      {
        label = "qemu-inert has no open RFC tasks";
        needle = "openTaskIds ? []";
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
        # Format-robust: the package `checks` function is defined (its args and
        # qemu-crucible scoping are covered by the pname needle below). A
        # single-line signature needle cannot survive nix formatting.
        label = "qemu-crucible package checks function";
        needle = "checks = {";
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
        label = "package patch-microtests completed task ownership";
        needle = ''taskIds = ["T-PKG-4" "T-HARN-20" "T-PATCH-2"'';
      }
      {
        label = "package patch-microtests has no open task ownership";
        needle = "openTaskIds = [];";
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
        label = "package qemu-inert completed task ownership";
        needle = ''taskIds = ["T-PLAN-3" "T-DET-23" "T-HARN-21" "T-PATCH-3"]'';
      }
      {
        label = "package qemu-inert has no open task ownership";
        needle = "openTaskIds = [];";
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
      {
        label = "distributed continuous exploration fleet wrapper defined";
        needle = "crucible-distributed-continuous-exploration = let";
      }
      {
        label = "distributed fleet wrapper consumes fleet store package";
        needle = "fleetStore = pkgs.crucible-fleet-store;";
      }
      {
        label = "distributed fleet wrapper consumes explorer package";
        needle = "explorer = pkgs.crucible;";
      }
      {
        label = "distributed fleet wrapper consumes source gate";
        needle = "fleetStoreGate = crucibleChecks.phase7.crucibleFleetStore;";
      }
      {
        label = "distributed fleet wrapper consumes shared DagStore gate";
        needle = "sharedDagStoreGate = crucibleChecks.phase7.crucibleSharedDagStore;";
      }
      {
        label = "distributed fleet wrapper consumes frontier lease gate";
        needle = "frontierLeaseGate = crucibleChecks.phase7.crucibleFrontierLeases;";
      }
      {
        label = "distributed fleet wrapper consumes four-layer dedup gate";
        needle = "fourLayerDedupGate = crucibleChecks.phase7.crucibleFourLayerDedup;";
      }
      {
        label = "distributed fleet wrapper consumes determinism guardrail gate";
        needle = "determinismGuardrailGate = crucibleChecks.phase7.crucibleDeterminismGuardrail;";
      }
      {
        label = "distributed fleet wrapper consumes campaign provenance gate";
        needle = "campaignProvenanceGate = crucibleChecks.phase7.crucibleCampaignProvenance;";
      }
      {
        label = "distributed fleet wrapper consumes fleet equivalence gate";
        needle = "fleetEquivalenceGate = crucibleChecks.phase7.gates.fleetEquivalence.rawGate;";
      }
      {
        label = "distributed fleet wrapper consumes campaign continuity gate";
        needle = "campaignContinuityGate = crucibleChecks.phase7.gates.campaignContinuity.rawGate;";
      }
      {
        label = "distributed fleet wrapper records fleet equivalence result";
        needle = ''fleet_equivalence_gate_result=''${fleetEquivalenceGate}/result'';
      }
      {
        label = "distributed fleet wrapper records campaign continuity result";
        needle = ''campaign_continuity_gate_result=''${campaignContinuityGate}/result'';
      }
      {
        label = "distributed fleet wrapper records byte-identical fleet equivalence";
        needle = "fleet_equivalence_artifacts=byte-identical";
      }
      {
        label = "distributed fleet wrapper records structural fleet equivalence";
        needle = "fleet_equivalence_structural=root-budget-graph-exhaustion";
      }
      {
        label = "distributed fleet wrapper records real-QEMU fleet equivalence source";
        needle = "fleet_equivalence_real_qemu_slice=checks.crucible.phase2.gates.singleVmFingerprint";
      }
      {
        label = "distributed fleet wrapper records reproducible campaign continuity seed";
        needle = "campaign_continuity_seed_reproducible=bit-identical-prior-corpus";
      }
      {
        label = "distributed fleet wrapper records campaign continuity refusal";
        needle = "campaign_continuity_cross_provenance_refused=true";
      }
      {
        label = "distributed fleet wrapper records campaign continuity fresh lineage";
        needle = "campaign_continuity_fresh_lineage=forked";
      }
      {
        label = "distributed fleet wrapper records triple-keyed provenance seeding";
        needle = "provenance_seed_gate=triple-keyed";
      }
      {
        label = "distributed fleet wrapper records TCG-only execution";
        needle = "tcg_only=true";
      }
      {
        label = "distributed fleet wrapper records no required system features";
        needle = "required_system_features=none";
      }
      {
        label = "distributed fleet wrapper records no KVM dependency";
        needle = "kvm_required=false";
      }
      {
        label = "distributed fleet wrapper records distributed search";
        needle = "distributed_search_surface=enabled";
      }
      {
        label = "distributed fleet wrapper records continuous campaign";
        needle = "continuous_campaign_surface=enabled";
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
        label = "T-PKG-21 fleet store guard is exposed";
        needle = ''attrPath = "checks.crucible.phase7.crucibleFleetStore";'';
      }
      {
        label = "T-PKG-23 CAS fleet seam guard is exposed";
        needle = ''attrPath = "checks.crucible.phase7.crucibleCasFleetRatchetSeam";'';
      }
      {
        label = "T-DCE-4 campaign manifest guard is exposed";
        needle = ''attrPath = "checks.crucible.phase7.crucibleCampaignManifest";'';
      }
      {
        label = "T-DCE-5 campaign seeding guard is exposed";
        needle = ''attrPath = "checks.crucible.phase7.crucibleCampaignSeeding";'';
      }
      {
        label = "T-DCE-6 campaign storage bounding guard is exposed";
        needle = ''attrPath = "checks.crucible.phase7.crucibleCampaignStorageBounding";'';
      }
      {
        label = "T-DCE-7 determinism guardrail guard is exposed";
        needle = ''attrPath = "checks.crucible.phase7.crucibleDeterminismGuardrail";'';
      }
      {
        label = "T-PKG-22 campaign provenance guard is exposed";
        needle = ''attrPath = "checks.crucible.phase7.crucibleCampaignProvenance";'';
      }
      {
        label = "phase7 e2e gate import";
        needle = "gate = import ./phase7-e2e-determinism.nix";
      }
      {
        label = "phase7 fleet equivalence gate import";
        needle = "gate = import ./phase7-crucible-fleet-equivalence.nix";
      }
      {
        label = "phase7 campaign continuity gate import";
        needle = "gate = import ./phase7-crucible-campaign-continuity.nix";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-e2e-determinism.nix" phase7E2e [
      {
        label = "phase7 acceptance gate records production fleet evidence";
        needle = "real_host_reproduction=checks.fleet.crucible-e2e-determinism";
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
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-fleet-equivalence.nix" phase7FleetEquivalence [
      {
        label = "phase7 fleet equivalence gate records SimDouble fleet coverage";
        needle = "simdouble_fleet=host-profile-matrix";
      }
      {
        label = "phase7 fleet equivalence gate records adversarial host conditions";
        needle = "adversarial_host_conditions=canonical-host-adversary-matrix-simdouble-fleet";
      }
      {
        label = "phase7 fleet equivalence gate records real-QEMU slice source";
        needle = "real_qemu_slice_source=checks.crucible.phase2.gates.singleVmFingerprint";
      }
      {
        label = "phase7 fleet equivalence gate records bisection handoff";
        needle = "divergence_bisection=SearchReplayOracleBisectionRequest";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-campaign-continuity.nix" phase7CampaignContinuity [
      {
        label = "phase7 campaign continuity gate records seed reproducibility";
        needle = "seed_reproducibility=bit-identical-prior-corpus";
      }
      {
        label = "phase7 campaign continuity gate records coverage ratchet";
        needle = "coverage_ratchet=monotone-non-decreasing";
      }
      {
        label = "phase7 campaign continuity gate records provenance refusal";
        needle = "cross_provenance_reuse=refused";
      }
      {
        label = "phase7 campaign continuity gate records fresh lineage";
        needle = "fresh_lineage=forked";
      }
      {
        label = "phase7 campaign continuity gate records triple-keyed provenance";
        needle = "provenance_seed_gate=triple-keyed";
      }
    ];

  docFailures = failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
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
      label = "T-PKG-4 checklist complete";
      needle = "- [x] **T-PKG-4**";
    }
    {
      label = "T-PKG-4 completion note";
      needle = "Completed by `checks.crucible.phase2.gates.patchMicrotests`";
    }
    {
      label = "T-PKG-14 completion note";
      needle = "Completed by `checks.crucible.phase7.crucibleGateCiWiring`";
    }
    {
      label = "T-PKG-21 checklist complete";
      needle = "- [x] **T-PKG-21**";
    }
    {
      label = "T-PKG-21 completion note";
      needle = "Completed by `checks.crucible.phase7.crucibleFleetStore`";
    }
    {
      label = "T-PKG-22 checklist complete";
      needle = "- [x] **T-PKG-22**";
    }
    {
      label = "T-PKG-22 completion note";
      needle = "Completed by `checks.crucible.phase7.crucibleCampaignProvenance`";
    }
    {
      label = "T-PKG-23 checklist complete";
      needle = "- [x] **T-PKG-23**";
    }
    {
      label = "T-PKG-23 completion note";
      needle = "Completed by `checks.crucible.phase7.crucibleCasFleetRatchetSeam`";
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
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            status=complete
            evidence_scope=gate-ci-wiring-with-complete-per-patch-attribution
            eval_class_gates=${builtins.concatStringsSep "," (map (gate: gate.gate) evalClassGates)}
            package_class_gates=${builtins.concatStringsSep "," (map (gate: gate.gate) packageClassGates)}
            e2e_gate=gate:e2e-determinism
            e2e_gate_class=fleet-check-surface
            ordering_source=checked-gate-targets-and-explicit-default.nix-dependencies
            ordering_edges=${builtins.concatStringsSep "," (map (edge: edge.edge) expectedOrderingEdges)}
            ci_ordering=green-before-advance
            qemu_package_checks=${builtins.concatStringsSep "," (map (gate: gate.packagePath) packageClassGates)}
            shared_dag_store_source=checks.crucible.phase7.crucibleSharedDagStore
            frontier_lease_source=checks.crucible.phase7.crucibleFrontierLeases
            four_layer_dedup_source=checks.crucible.phase7.crucibleFourLayerDedup
            determinism_guardrail_source=checks.crucible.phase7.crucibleDeterminismGuardrail
            campaign_manifest_source=checks.crucible.phase7.crucibleCampaignManifest
            campaign_seeding_source=checks.crucible.phase7.crucibleCampaignSeeding
            campaign_storage_bounding_source=checks.crucible.phase7.crucibleCampaignStorageBounding
            campaign_provenance_source=checks.crucible.phase7.crucibleCampaignProvenance
            campaign_continuity_source=checks.crucible.phase7.gates.campaignContinuity
            fleet_check_surface=checks.fleet.crucible-e2e-determinism,checks.fleet.crucible-distributed-continuous-exploration
            RESULT
          '';
        }
      ];
    }

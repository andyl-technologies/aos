{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.campaignContinuity",
  taskIds ? ["T-DCE-9"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  casSource =
    builtins.readFile ../../crates/crucible-cas/src/lib.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_codec.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_model.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_store.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/invalidation.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/tests.rs;
  fleetStoreProbe = builtins.readFile ../../crates/crucible-cas/src/bin/crucible-fleet-store.rs;
  gateTest = builtins.readFile ../../crates/crucible-cas/tests/gate_campaign_continuity.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateTargetMappingTest = builtins.readFile ../../crates/crucible-harness/tests/gate_target_mapping.rs;
  testingStandards = builtins.readFile ../../crates/crucible-harness/tests/testing_standards.rs;
  testingStandardsSupport = builtins.readFile ../../crates/crucible-harness/tests/support/testing_standards.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  phase1TestingStandards = builtins.readFile ./phase1-testing-standards.nix;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  rootDefault = builtins.readFile ../../default.nix;
  fleetStorePackage = builtins.readFile ../../pkgs/tools/crucible-fleet-store.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  campaignContinuityRawDependency = "dependencies = [fleetEquivalence.rawGate phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";
  campaignContinuityWrapperDependency = "dependencies = [fleetEquivalence phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";

  failures =
    failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "T-DCE-9 completion note";
        needle = "Completed by `checks.crucible.phase7.gates.campaignContinuity`";
      }
      {
        label = "DCE-26 provenance keyed gating";
        needle = "keyed to the **provenance triple**";
      }
      {
        label = "DCE-27 cross-provenance refusal";
        needle = "REFUSE reuse; FORK a fresh campaign lineage";
      }
      {
        label = "campaign continuity gate name";
        needle = "`gate:campaign-continuity`";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "stale full campaign-continuity remaining note";
        needle = "full campaign-continuity gate remains T-DCE-9";
      }
      {
        label = "stale campaign-continuity remaining note";
        needle = "campaign-continuity gate remains T-DCE-9";
      }
      {
        label = "stale campaign continuity remaining note";
        needle = "Campaign continuity remains T-DCE-9";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "campaign-continuity catalog entry";
        needle = "`gate:campaign-continuity`";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "campaign provenance schema";
        needle = "CAMPAIGN_PROVENANCE_SCHEMA";
      }
      {
        label = "campaign lineage schema";
        needle = "CAMPAIGN_LINEAGE_SCHEMA";
      }
      {
        label = "fresh lineage schema";
        needle = "CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA";
      }
      {
        label = "cross-provenance refusal reason";
        needle = "CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON";
      }
      {
        label = "provenance-aware seeding API";
        needle = "pub fn seed_next_run_for_provenance";
      }
      {
        label = "fresh-lineage fork API";
        needle = "pub fn fork_fresh_campaign_lineage";
      }
      {
        label = "fresh-lineage roots type";
        needle = "pub struct CampaignFreshLineageRoots";
      }
      {
        label = "continuity decision type";
        needle = "pub enum CampaignContinuitySeedDecision";
      }
      {
        label = "fresh-lineage event type";
        needle = "pub struct CampaignFreshLineageBaselineEvent";
      }
      {
        label = "fresh-lineage event reader";
        needle = "pub fn read_fresh_lineage_baseline_event";
      }
      {
        label = "fresh-lineage head install helper";
        needle = "install_fresh_lineage_head";
      }
      {
        label = "baseline event content hash";
        needle = "baseline_event_hash";
      }
      {
        label = "campaign provenance key API";
        needle = "pub fn campaign_provenance_key";
      }
      {
        label = "campaign lineage id API";
        needle = "pub fn campaign_lineage_id";
      }
      {
        label = "same-provenance seed decision";
        needle = "SeedPriorCorpus";
      }
      {
        label = "cross-provenance refusal decision";
        needle = "RefuseCrossProvenanceReuse";
      }
      {
        label = "corpus reuse refusal";
        needle = "fresh campaign lineage corpus must not reuse prior corpus entries";
      }
      {
        label = "coverage reuse refusal";
        needle = "fresh campaign lineage coverage must not reuse prior coverage edges";
      }
      {
        label = "findings reuse refusal";
        needle = "fresh campaign lineage findings must not reuse prior finding artifacts";
      }
      {
        label = "unkeyed seed refusal";
        needle = "campaign seed provenance does not match manifest provenance";
      }
      {
        label = "current-head requirement for fresh lineage";
        needle = "fresh campaign lineage requires prior manifest to be current head";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/bin/crucible-fleet-store.rs" fleetStoreProbe [
      {
        label = "campaign continuity probe";
        needle = "prove_campaign_continuity_gate";
      }
      {
        label = "implemented probe output";
        needle = "campaign_continuity=implemented";
      }
      {
        label = "seed reproducibility probe output";
        needle = "campaign_continuity_seed_reproducible=true";
      }
      {
        label = "coverage monotonicity probe output";
        needle = "campaign_continuity_coverage_monotone=true";
      }
      {
        label = "cross-provenance refusal probe output";
        needle = "campaign_continuity_cross_provenance_refused=true";
      }
      {
        label = "fresh-lineage fork probe output";
        needle = "campaign_continuity_fresh_lineage=forked";
      }
      {
        label = "prior findings probe output";
        needle = "campaign_continuity_prior_findings_reproducible=true";
      }
      {
        label = "triple-keyed provenance probe output";
        needle = "provenance_seed_gate=triple-keyed";
      }
      {
        label = "probe rejects direct cross-provenance seeding";
        needle = "campaign continuity allowed unkeyed cross-provenance seeding";
      }
      {
        label = "probe reads persisted baseline event";
        needle = "read_fresh_lineage_baseline_event";
      }
      {
        label = "probe installs fresh lineage head";
        needle = "campaign continuity fresh lineage was not installed as head";
      }
    ]
    ++ failuresFor "crates/crucible-cas/tests/gate_campaign_continuity.rs" gateTest [
      {
        label = "seed and coverage positive test";
        needle = "gate_campaign_continuity_seeds_prior_corpus_and_ratchets_coverage";
      }
      {
        label = "cross-provenance refusal positive test";
        needle = "gate_campaign_continuity_refuses_cross_provenance_and_forks_fresh_lineage";
      }
      {
        label = "silent mixing negative test";
        needle = "gate_campaign_continuity_rejects_silent_cross_provenance_mixing";
      }
      {
        label = "current head negative test";
        needle = "gate_campaign_continuity_requires_prior_manifest_as_current_head";
      }
      {
        label = "same-provenance seed decision assertion";
        needle = "SeedPriorCorpus";
      }
      {
        label = "cross-provenance refusal assertion";
        needle = "RefuseCrossProvenanceReuse";
      }
      {
        label = "coverage monotonicity API use";
        needle = "accumulated_coverage_delta";
      }
      {
        label = "campaign CAS use";
        needle = "compare_and_swap_head";
      }
      {
        label = "coverage regression negative control";
        needle = "campaign coverage-map advance would reduce accumulated coverage";
      }
      {
        label = "fresh corpus reuse negative control";
        needle = "fresh campaign lineage corpus must not reuse prior corpus entries";
      }
      {
        label = "fresh coverage reuse negative control";
        needle = "fresh campaign lineage coverage must not reuse prior coverage edges";
      }
      {
        label = "fresh findings reuse negative control";
        needle = "fresh campaign lineage findings must not reuse prior finding artifacts";
      }
      {
        label = "direct seed provenance refusal";
        needle = "campaign seed provenance does not match manifest provenance";
      }
      {
        label = "persisted baseline event assertion";
        needle = "read_fresh_lineage_baseline_event";
      }
      {
        label = "fresh lineage head assertion";
        needle = "assert_eq!(fresh_head.manifest_hash, event.fresh_manifest_hash);";
      }
    ]
    ++ forbiddenFor "crates/crucible-cas/tests/gate_campaign_continuity.rs" gateTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "campaign-continuity gate catalog implemented";
        needle = "name: \"gate:campaign-continuity\",\n        phase: GatePhase::Phase7,\n        owner: \"crucible-harness\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "campaign-continuity implemented status assertion";
        needle = "find_gate(\"gate:campaign-continuity\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "campaign-continuity gate target implemented";
        needle = "gate: \"gate:campaign-continuity\",\n        package: \"crucible-cas\",\n        test_target: \"gate_campaign_continuity\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_target_mapping.rs" gateTargetMappingTest [
      {
        label = "campaign-continuity target mapping assertion";
        needle = "\"gate:campaign-continuity\",\n                \"crucible-cas\",\n                \"gate_campaign_continuity\"";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/testing_standards.rs" testingStandards [
      {
        label = "campaign-continuity testing standard";
        needle = "gate: \"gate:campaign-continuity\",\n        owner_packages: &[\"crucible-cas\"],\n        layers: &[Layer::L3],\n        shape: TestShape::CampaignContinuity,\n        backend: TestBackend::InProcess,";
      }
      {
        label = "crucible-cas owns campaign continuity";
        needle = "package: \"crucible-cas\",\n        gates: &[\"gate:campaign-continuity\"],";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/support/testing_standards.rs" testingStandardsSupport [
      {
        label = "campaign-continuity source shape";
        needle = "TestShape::CampaignContinuity";
      }
      {
        label = "crucible-cas layer";
        needle = "\"crucible\" | \"crucible-cas\" => Some(Layer::L3)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "phase1 target lint includes campaign continuity";
        needle = "gate = \"gate:campaign-continuity\";\n      package = \"crucible-cas\";\n      testTarget = \"gate_campaign_continuity\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-testing-standards.nix" phase1TestingStandards [
      {
        label = "phase1 testing standards target includes campaign continuity";
        needle = "gate = \"gate:campaign-continuity\";\n      package = \"crucible-cas\";\n      testTarget = \"gate_campaign_continuity\";\n      requiredFeatures = [];";
      }
      {
        label = "phase1 testing standards include campaign continuity";
        needle = "gate = \"gate:campaign-continuity\";\n      ownerPackages = [\"crucible-cas\"];\n      layers = [\"L3\"];\n      shape = \"campaign-continuity\";\n      backend = \"in-process\";";
      }
      {
        label = "phase1 testing standards enforce campaign continuity shape";
        needle = "must prove seed replay, coverage monotonicity, and provenance refusal for campaign continuity";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "campaign continuity gate imported";
        needle = "gate = import ./phase7-crucible-campaign-continuity.nix";
      }
      {
        label = "campaign continuity raw dependencies";
        needle = campaignContinuityRawDependency;
      }
      {
        label = "campaign continuity wrapper dependencies";
        needle = campaignContinuityWrapperDependency;
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "stale campaign continuity red placeholder";
        needle = "reason = \"campaign continuity gate is intentionally pending\";";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring reads campaign continuity source";
        needle = "phase7CampaignContinuity = builtins.readFile ./phase7-crucible-campaign-continuity.nix;";
      }
      {
        label = "CI wiring classifies campaign continuity gate";
        needle = "gate = \"gate:campaign-continuity\";";
      }
      {
        label = "CI wiring expects campaign continuity import";
        needle = "gate = import ./phase7-crucible-campaign-continuity.nix";
      }
      {
        label = "CI wiring records campaign continuity source";
        needle = "campaign_continuity_source=checks.crucible.phase7.gates.campaignContinuity";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "distributed wrapper consumes campaign provenance gate";
        needle = "campaignProvenanceGate = crucibleChecks.phase7.crucibleCampaignProvenance;";
      }
      {
        label = "distributed wrapper consumes campaign continuity gate";
        needle = "campaignContinuityGate = crucibleChecks.phase7.gates.campaignContinuity.rawGate;";
      }
      {
        label = "distributed wrapper checks campaign continuity result";
        needle = ''campaign_continuity_result="''${campaignContinuityGate}/result"'';
      }
      {
        label = "distributed wrapper records campaign continuity result";
        needle = ''campaign_continuity_gate_result=''${campaignContinuityGate}/result'';
      }
      {
        label = "distributed wrapper records reproducible continuity seed";
        needle = "campaign_continuity_seed_reproducible=bit-identical-prior-corpus";
      }
      {
        label = "distributed wrapper records continuity coverage monotonicity";
        needle = "campaign_continuity_coverage_monotone=true";
      }
      {
        label = "distributed wrapper records cross-provenance refusal";
        needle = "campaign_continuity_cross_provenance_refused=true";
      }
      {
        label = "distributed wrapper records fresh lineage fork";
        needle = "campaign_continuity_fresh_lineage=forked";
      }
      {
        label = "distributed wrapper records triple-keyed seeding";
        needle = "provenance_seed_gate=triple-keyed";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "package validates campaign continuity";
        needle = "grep -q '^campaign_continuity=implemented$'";
      }
      {
        label = "package validates campaign continuity seed";
        needle = "grep -q '^campaign_continuity_seed_reproducible=true$'";
      }
      {
        label = "package validates campaign continuity provenance refusal";
        needle = "grep -q '^campaign_continuity_cross_provenance_refused=true$'";
      }
      {
        label = "package records DCE campaign continuity task";
        needle = "dce_campaign_continuity_task=T-DCE-9";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 campaign-continuity check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-campaign-continuity";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
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
          name = "run-campaign-continuity";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase7-campaign-continuity-target" \
              -p crucible-cas \
              --test gate_campaign_continuity \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            gate=gate:campaign-continuity
            tasks=${builtins.concatStringsSep "," taskIds}
            seed_reproducibility=bit-identical-prior-corpus
            coverage_ratchet=monotone-non-decreasing
            accumulated_coverage=grow-only-union-crdt
            cross_provenance_reuse=refused
            fresh_lineage=forked
            provenance_seed_gate=triple-keyed
            prior_findings=reproducible
            pure_check=true
            RESULT
          '';
        }
      ];
    }

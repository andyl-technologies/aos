{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleCampaignSeeding",
  taskIds ? ["T-DCE-5"],
  dependencies ? [],
}: let
  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  casSource =
    builtins.readFile ../../crates/crucible-cas/src/lib.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_codec.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_model.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_store.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/invalidation.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/tests.rs;
  fleetStoreProbe = builtins.readFile ../../crates/crucible-cas/src/bin/crucible-fleet-store.rs;
  fleetStorePackage = builtins.readFile ../../pkgs/tools/crucible-fleet-store.nix;
  rootDefault = builtins.readFile ../../default.nix;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  fleetStore = pkgs.crucible-fleet-store;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  campaignContinuityRawDependency =
    "dependencies = [fleetEquivalence.rawGate phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";
  campaignContinuityWrapperDependency =
    "dependencies = [fleetEquivalence phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";

  failures =
    failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "T-DCE-5 checklist complete";
        needle = "- [x] **T-DCE-5**";
      }
      {
        label = "T-DCE-5 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleCampaignSeeding`";
      }
      {
        label = "DCE-11 seed prior corpus text";
        needle = "Run N+1 of a campaign MUST seed from the corpus";
      }
      {
        label = "DCE-12 accumulated coverage ratchet text";
        needle = "continuous coverage ratchet";
      }
      {
        label = "DCE-13 findings ledger text";
        needle = "content-addressed **findings ledger**";
      }
      {
        label = "DCE-24 grow-only union CRDT text";
        needle = "grow-only union CRDT";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "stale T-DCE-5 placeholder";
        needle = "- [ ] **T-DCE-5**";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "self-contained replay artifact type";
        needle = "pub struct CampaignReplayArtifact";
      }
      {
        label = "corpus seed type";
        needle = "pub struct CampaignCorpusSeed";
      }
      {
        label = "coverage delta type";
        needle = "pub struct CampaignCoverageDelta";
      }
      {
        label = "campaign finding type";
        needle = "pub struct CampaignFinding";
      }
      {
        label = "persisted campaign finding type";
        needle = "pub struct PersistedCampaignFinding";
      }
      {
        label = "persist replay artifact API";
        needle = "pub fn persist_replay_artifact";
      }
      {
        label = "provenance-keyed seed next run API";
        needle = "pub fn seed_next_run(\n        &self,\n        manifest: &CampaignManifest,\n        run_provenance: &CampaignProvenance,";
      }
      {
        label = "campaign corpus persistence API";
        needle = "pub fn persist_campaign_corpus";
      }
      {
        label = "coverage map persistence API";
        needle = "pub fn persist_accumulated_coverage_map";
      }
      {
        label = "coverage novelty API";
        needle = "pub fn accumulated_coverage_delta";
      }
      {
        label = "coverage union API";
        needle = "pub fn merge_accumulated_coverage_maps";
      }
      {
        label = "findings ledger API";
        needle = "pub fn persist_findings_ledger";
      }
      {
        label = "findings ledger merge API";
        needle = "pub fn merge_findings_ledgers";
      }
      {
        label = "raw CAS typed-root regression guard";
        needle = "validate_monotone_manifest_advance";
      }
      {
        label = "finding artifact dedup helper";
        needle = "insert_deduped_finding_entry";
      }
      {
        label = "self-contained artifact format";
        needle = "format=crucible.campaign-replay-artifact.v1";
      }
      {
        label = "corpus root format";
        needle = "format=crucible.campaign-corpus.v1";
      }
      {
        label = "coverage root format";
        needle = "format=crucible.campaign-coverage-map.v1";
      }
      {
        label = "findings ledger format";
        needle = "format=crucible.campaign-findings-ledger.v1";
      }
      {
        label = "findings ledger artifact-keyed entries";
        needle = "entry artifact={}";
      }
      {
        label = "typed manifest root merge";
        needle = "try_merge_typed_manifest_root";
      }
      {
        label = "seed reproducibility unit proof";
        needle = "campaign_seed_loads_self_contained_replay_artifacts";
      }
      {
        label = "coverage ratchet unit proof";
        needle = "campaign_coverage_ratchet_is_grow_only_union_crdt";
      }
      {
        label = "findings ledger unit proof";
        needle = "campaign_findings_ledger_accumulates_and_deduplicates";
      }
      {
        label = "raw CAS regression unit proof";
        needle = "campaign_head_cas_rejects_typed_root_regression";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/bin/crucible-fleet-store.rs" fleetStoreProbe [
      {
        label = "campaign seeding probe function";
        needle = "prove_campaign_seed_coverage_findings";
      }
      {
        label = "probe uses replay artifacts";
        needle = "CampaignReplayArtifact::new";
      }
      {
        label = "probe uses campaign findings";
        needle = "CampaignFinding::new";
      }
      {
        label = "seed prior corpus output";
        needle = "campaign_seed=prior-corpus";
      }
      {
        label = "bit-identical seed output";
        needle = "campaign_seed_replay=bit-identical";
      }
      {
        label = "coverage ratchet output";
        needle = "coverage_ratchet=grow-only-union-crdt";
      }
      {
        label = "coverage CRDT output";
        needle = "coverage_crdt=commutative-associative-idempotent";
      }
      {
        label = "findings ledger output";
        needle = "findings_ledger=cross-run-grow-only";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "package validates campaign seed";
        needle = "grep -q '^campaign_seed=prior-corpus$'";
      }
      {
        label = "package validates coverage ratchet";
        needle = "grep -q '^coverage_ratchet=grow-only-union-crdt$'";
      }
      {
        label = "package validates findings ledger";
        needle = "grep -q '^findings_ledger=cross-run-grow-only$'";
      }
      {
        label = "package records DCE campaign seed task";
        needle = "dce_campaign_seed_task=T-DCE-5";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "distributed wrapper consumes campaign seeding gate";
        needle = "campaignSeedingGate = crucibleChecks.phase7.crucibleCampaignSeeding;";
      }
      {
        label = "distributed wrapper checks campaign seeding result";
        needle = ''campaign_seeding_result="''${campaignSeedingGate}/result"'';
      }
      {
        label = "distributed wrapper records campaign seeding result";
        needle = ''campaign_seeding_gate_result=''${campaignSeedingGate}/result'';
      }
      {
        label = "distributed wrapper records seed replay";
        needle = "campaign_seed_replay=bit-identical";
      }
      {
        label = "distributed wrapper records coverage ratchet";
        needle = "coverage_ratchet=grow-only-union-crdt";
      }
      {
        label = "distributed wrapper records findings ledger";
        needle = "findings_ledger=cross-run-grow-only";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 campaign seeding check imported";
        needle = "crucibleCampaignSeeding = import ./phase7-crucible-campaign-seeding.nix";
      }
      {
        label = "campaign continuity raw gate waits for campaign seeding";
        needle = campaignContinuityRawDependency;
      }
      {
        label = "campaign continuity wrapper waits for campaign seeding";
        needle = campaignContinuityWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects campaign seeding check";
        needle = "checks.crucible.phase7.crucibleCampaignSeeding";
      }
      {
        label = "CI wiring expects campaign seeding raw dependency";
        needle = campaignContinuityRawDependency;
      }
      {
        label = "CI wiring expects campaign seeding wrapper dependency";
        needle = campaignContinuityWrapperDependency;
      }
    ];
in
  if failures != []
  then throw "crucible phase7 campaign seeding check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-campaign-seeding";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep fleetStore] ++ dependencies;

      phases = [
        {
          name = "probe-campaign-seeding";
          script = ''
            set -eu
            probe_root="$TMPDIR/crucible-campaign-seeding"
            "${fleetStore}/bin/crucible-fleet-store" probe "$probe_root" > "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^campaign_seed=prior-corpus$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^campaign_seed_artifact=self-contained$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^campaign_seed_replay=bit-identical$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^campaign_seed_process_state=not-required$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^coverage_ratchet=grow-only-union-crdt$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^coverage_ratchet_monotone=true$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^coverage_crdt=commutative-associative-idempotent$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^coverage_novelty=against-accumulated-map$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^findings_ledger=cross-run-grow-only$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^findings_ledger_dedup=content-addressed$' "$TMPDIR/crucible-campaign-seeding.probe"
            grep -q '^finding_replay=bit-identical-from-ledger$' "$TMPDIR/crucible-campaign-seeding.probe"

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            fleet_store_component=${fleetStore}
            runtime_probe=crucible-fleet-store probe
            campaign_seed=prior-corpus
            campaign_seed_artifact=self-contained
            campaign_seed_replay=bit-identical
            campaign_seed_process_state=not-required
            coverage_ratchet=grow-only-union-crdt
            coverage_ratchet_monotone=true
            coverage_crdt=commutative-associative-idempotent
            coverage_novelty=against-accumulated-map
            findings_ledger=cross-run-grow-only
            findings_ledger_dedup=content-addressed
            finding_replay=bit-identical-from-ledger
            gate_dependency=checks.crucible.phase7.gates.campaignContinuity
            campaign_continuity_gate_status=implemented
            RESULT
          '';
        }
      ];
    }

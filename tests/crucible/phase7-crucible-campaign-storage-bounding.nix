{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleCampaignStorageBounding",
  taskIds ? ["T-DCE-6"],
  dependencies ? [],
}: let
  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  casSource = builtins.readFile ../../crates/crucible-cas/src/lib.rs;
  fleetStoreProbe = builtins.readFile ../../crates/crucible-cas/src/bin/crucible-fleet-store.rs;
  fleetStorePackage = builtins.readFile ../../pkgs/tools/crucible-fleet-store.nix;
  crucibleModel = import ./_crucible-model-source.nix {inherit lib;};
  crucibleLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  rootDefault = builtins.readFile ../../default.nix;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  fleetStore = pkgs.crucible-fleet-store;

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

  campaignContinuityRawDependency =
    "dependencies = [fleetEquivalence.rawGate phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";
  campaignContinuityWrapperDependency =
    "dependencies = [fleetEquivalence phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";

  failures =
    failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "T-DCE-6 checklist complete";
        needle = "- [x] **T-DCE-6**";
      }
      {
        label = "T-DCE-6 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleCampaignStorageBounding`";
      }
      {
        label = "DCE-14 storage bounding text";
        needle = "GC rooted at the manifest's";
      }
      {
        label = "DCE-15 deterministic seeded retention text";
        needle = "deterministic seeded corpus";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "stale T-DCE-6 placeholder";
        needle = "- [ ] **T-DCE-6**";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "campaign GC root type";
        needle = "pub struct CampaignGcRoots";
      }
      {
        label = "campaign GC plan type";
        needle = "pub struct CampaignGcPlan";
      }
      {
        label = "campaign GC report type";
        needle = "pub struct CampaignGcReport";
      }
      {
        label = "campaign retention policy type";
        needle = "pub struct CampaignCorpusRetentionPolicy";
      }
      {
        label = "campaign retention report type";
        needle = "pub struct CampaignCorpusRetentionReport";
      }
      {
        label = "fat-to-thin materialization type";
        needle = "pub struct CampaignCheckpointMaterialization";
      }
      {
        label = "manifest root GC API";
        needle = "pub fn campaign_gc_roots";
      }
      {
        label = "campaign GC planning API";
        needle = "pub fn campaign_gc_plan";
      }
      {
        label = "campaign GC sweep API";
        needle = "pub fn garbage_collect_campaign_candidates";
      }
      {
        label = "deterministic retention API";
        needle = "pub fn retain_campaign_corpus_under_cap";
      }
      {
        label = "explicit retention CAS API";
        needle = "pub fn compare_and_swap_head_with_retention";
      }
      {
        label = "retention typed root format";
        needle = "format=crucible.campaign-corpus-retention.v1";
      }
      {
        label = "retention source-cap-seed material";
        needle = "source={}";
      }
      {
        label = "retention deterministic score";
        needle = "campaign_corpus_retention_score";
      }
      {
        label = "retention head guard";
        needle = "validate_campaign_corpus_retention_advance";
      }
      {
        label = "retention source validation";
        needle = "campaign corpus retention source does not match current root";
      }
      {
        label = "retention policy authorization validation";
        needle = "campaign corpus retention policy does not match authorized retention policy";
      }
      {
        label = "retention explicit policy validation";
        needle = "campaign corpus retention roots require explicit retention policy";
      }
      {
        label = "retention cap-zero validation";
        needle = "campaign corpus retention cap must be greater than zero";
      }
      {
        label = "retention deterministic validation";
        needle = "campaign corpus retention root does not match deterministic seeded cap";
      }
      {
        label = "campaign GC unit proof";
        needle = "campaign_gc_is_rooted_at_manifest_roots_and_sweeps_unpinned_candidates";
      }
      {
        label = "fat-to-thin unit proof";
        needle = "campaign_fat_to_thin_eviction_preserves_checkpoint_value";
      }
      {
        label = "retention unit proof";
        needle = "campaign_corpus_retention_is_deterministic_seeded_cap";
      }
      {
        label = "retention merge guard unit proof";
        needle = "campaign_retention_merge_retry_does_not_expand_over_cap";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" crucibleModel [
      {
        label = "temporal graph GC roots";
        needle = "pub struct TemporalGraphGcRoots";
      }
      {
        label = "temporal graph mark-and-sweep";
        needle = "pub fn garbage_collect(";
      }
      {
        label = "temporal graph store-backed GC";
        needle = "pub fn garbage_collect_store<S>";
      }
      {
        label = "temporal graph fat-to-thin eviction";
        needle = "pub fn evict_fat_checkpoint_to_thin(";
      }
      {
        label = "temporal graph cache-only collection";
        needle = "pub fn collect_cached_snapshot";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crucibleLib [
      {
        label = "temporal graph fat-to-thin value proof";
        needle = "temporal_graph_evicts_fat_checkpoint_back_to_thin_without_state_change";
      }
      {
        label = "temporal graph GC replay proof";
        needle = "temporal_graph_gc_cache_collection_preserves_replay_oracle_path";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/bin/crucible-fleet-store.rs" fleetStoreProbe [
      {
        label = "campaign storage probe function";
        needle = "prove_campaign_storage_bounding";
      }
      {
        label = "probe uses retention policy";
        needle = "CampaignCorpusRetentionPolicy::new";
      }
      {
        label = "probe uses fat-to-thin model";
        needle = "CampaignCheckpointMaterialization::fat";
      }
      {
        label = "probe retains ordinary corpus artifacts";
        needle = "seed_artifact_hashes";
      }
      {
        label = "campaign GC roots output";
        needle = "campaign_gc_roots=manifest-roots";
      }
      {
        label = "campaign GC sweep output";
        needle = "campaign_gc_unpinned=swept-candidate";
      }
      {
        label = "fat-to-thin output";
        needle = "fat_to_thin_eviction=value-preserved";
      }
      {
        label = "retention output";
        needle = "corpus_retention=deterministic-seeded-cap";
      }
      {
        label = "retention authorization output";
        needle = "corpus_retention_authorized=explicit-policy";
      }
      {
        label = "findings retention output";
        needle = "findings_ledger_retention=never-evict";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "package validates campaign GC roots";
        needle = "grep -q '^campaign_gc_roots=manifest-roots$'";
      }
      {
        label = "package validates fat-to-thin";
        needle = "grep -q '^fat_to_thin_eviction=value-preserved$'";
      }
      {
        label = "package validates retention";
        needle = "grep -q '^corpus_retention=deterministic-seeded-cap$'";
      }
      {
        label = "package validates explicit retention policy";
        needle = "grep -q '^corpus_retention_authorized=explicit-policy$'";
      }
      {
        label = "package records DCE campaign storage bounding task";
        needle = "dce_campaign_storage_bounding_task=T-DCE-6";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "distributed wrapper consumes campaign storage bounding gate";
        needle = "campaignStorageBoundingGate = crucibleChecks.phase7.crucibleCampaignStorageBounding;";
      }
      {
        label = "distributed wrapper checks campaign storage bounding result";
        needle = ''campaign_storage_bounding_result="''${campaignStorageBoundingGate}/result"'';
      }
      {
        label = "distributed wrapper records campaign storage bounding result";
        needle = ''campaign_storage_bounding_gate_result=''${campaignStorageBoundingGate}/result'';
      }
      {
        label = "distributed wrapper records campaign GC";
        needle = "campaign_gc_roots=manifest-roots";
      }
      {
        label = "distributed wrapper records retention";
        needle = "corpus_retention=deterministic-seeded-cap";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 campaign storage bounding check imported";
        needle = "crucibleCampaignStorageBounding = import ./phase7-crucible-campaign-storage-bounding.nix";
      }
      {
        label = "campaign continuity raw gate waits for campaign storage bounding";
        needle = campaignContinuityRawDependency;
      }
      {
        label = "campaign continuity wrapper waits for campaign storage bounding";
        needle = campaignContinuityWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects campaign storage bounding check";
        needle = "checks.crucible.phase7.crucibleCampaignStorageBounding";
      }
      {
        label = "CI wiring expects campaign storage bounding raw dependency";
        needle = campaignContinuityRawDependency;
      }
      {
        label = "CI wiring expects campaign storage bounding wrapper dependency";
        needle = campaignContinuityWrapperDependency;
      }
    ];
in
  if failures != []
  then throw "crucible phase7 campaign storage bounding check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-campaign-storage-bounding";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep fleetStore] ++ dependencies;

      phases = [
        {
          name = "probe-campaign-storage-bounding";
          script = ''
            set -eu
            probe_root="$TMPDIR/crucible-campaign-storage-bounding"
            "${fleetStore}/bin/crucible-fleet-store" probe "$probe_root" > "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^campaign_gc_roots=manifest-roots$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^campaign_gc_scope=corpus,coverage,findings,genesis$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^campaign_gc_unpinned=swept-candidate$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^campaign_gc_value=cache-only$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^fat_to_thin_eviction=value-preserved$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^thin_checkpoint_source=parent-schedule-delta$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^corpus_retention=deterministic-seeded-cap$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^corpus_retention_authorized=explicit-policy$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^corpus_retention_reproducible=true$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^corpus_retention_root=source-cap-seed-proof$' "$TMPDIR/crucible-campaign-storage-bounding.probe"
            grep -q '^findings_ledger_retention=never-evict$' "$TMPDIR/crucible-campaign-storage-bounding.probe"

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            fleet_store_component=${fleetStore}
            runtime_probe=crucible-fleet-store probe
            campaign_gc_roots=manifest-roots
            campaign_gc_scope=corpus,coverage,findings,genesis
            campaign_gc_unpinned=swept-candidate
            campaign_gc_value=cache-only
            fat_to_thin_eviction=value-preserved
            thin_checkpoint_source=parent-schedule-delta
            corpus_retention=deterministic-seeded-cap
            corpus_retention_authorized=explicit-policy
            corpus_retention_reproducible=true
            corpus_retention_root=source-cap-seed-proof
            findings_ledger_retention=never-evict
            gate_dependency=checks.crucible.phase7.gates.campaignContinuity
            campaign_continuity_gate_status=implemented
            RESULT
          '';
        }
      ];
    }

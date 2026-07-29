{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleCampaignProvenance",
  taskIds ? ["T-PKG-22"],
  dependencies ? [],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  reproduction = builtins.readFile ../../crates/crucible-harness/src/reproduction.rs;
  reproductionTest = builtins.readFile ../../crates/crucible-harness/tests/reproduction_artifact.rs;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-22 checklist complete";
        needle = "- [x] **T-PKG-22**";
      }
      {
        label = "T-PKG-22 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleCampaignProvenance`";
      }
      {
        label = "fresh lineage remains explicit";
        needle = "fresh-lineage baseline event";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "stale T-PKG-22 placeholder";
        needle = "- [ ] **T-PKG-22**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "DCE provenance gating section";
        needle = "A campaign is keyed to the **provenance triple**";
      }
      {
        label = "DCE cross-provenance refusal";
        needle = "REFUSE reuse; FORK a fresh campaign lineage";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/reproduction.rs" reproduction [
      {
        label = "campaign provenance schema";
        needle = "CAMPAIGN_PROVENANCE_SCHEMA";
      }
      {
        label = "fresh-lineage event schema";
        needle = "CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA";
      }
      {
        label = "cross-provenance refusal reason";
        needle = "CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON";
      }
      {
        label = "campaign seed type";
        needle = "pub struct CampaignCorpusSeed";
      }
      {
        label = "fresh-lineage event type";
        needle = "pub struct CampaignFreshLineageBaselineEvent";
      }
      {
        label = "reuse decision enum";
        needle = "pub enum CampaignCorpusReuseDecision";
      }
      {
        label = "seed prior corpus decision";
        needle = "SeedPriorCorpus";
      }
      {
        label = "refuse cross-provenance decision";
        needle = "RefuseCrossProvenanceReuse";
      }
      {
        label = "campaign provenance key function";
        needle = "pub fn campaign_provenance_key";
      }
      {
        label = "campaign reuse evaluator";
        needle = "pub fn evaluate_campaign_corpus_reuse";
      }
      {
        label = "fresh lineage id";
        needle = "fresh_campaign_lineage_id";
      }
      {
        label = "Crucible version in provenance material";
        needle = "&identity.engine_version";
      }
      {
        label = "QEMU build id in provenance material";
        needle = "&identity.qemu_build_id";
      }
      {
        label = "QEMU patch series in provenance material";
        needle = "&identity.qemu_patch_series_hash";
      }
      {
        label = "shmem ABI in provenance material";
        needle = "&identity.shmem_abi_version";
      }
      {
        label = "guest-host ABI in provenance material";
        needle = "&identity.guest_host_protocol_version";
      }
      {
        label = "RPC ABI in provenance material";
        needle = "&identity.rpc_abi_version";
      }
      {
        label = "RPC build tag in provenance material";
        needle = "&identity.rpc_abi_build";
      }
      {
        label = "plugin ABI in provenance material";
        needle = "&identity.plugin_abi";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/reproduction_artifact.rs" reproductionTest [
      {
        label = "same-provenance seeding test";
        needle = "campaign_corpus_reuse_seeds_matching_provenance";
      }
      {
        label = "patch-series refusal test";
        needle = "campaign_corpus_reuse_refuses_patch_series_drift";
      }
      {
        label = "QEMU build id refusal test";
        needle = "campaign_corpus_reuse_refuses_qemu_build_id_drift";
      }
      {
        label = "ABI refusal test";
        needle = "campaign_corpus_reuse_refuses_abi_drift";
      }
      {
        label = "QEMU build id mutation";
        needle = "run_identity.qemu_build_id = content_address_bytes";
      }
      {
        label = "patch-series mutation";
        needle = "run_identity.qemu_patch_series_hash = String::from";
      }
      {
        label = "guest-host protocol mutation";
        needle = "run_identity.guest_host_protocol_version = String::from";
      }
      {
        label = "fresh-lineage event assertion";
        needle = "CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 campaign provenance check imported";
        needle = "crucibleCampaignProvenance = import ./phase7-crucible-campaign-provenance.nix";
      }
      {
        label = "campaign continuity raw gate waits for provenance check";
        needle = "dependencies = [fleetEquivalence.rawGate phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";
      }
      {
        label = "campaign continuity wrapper waits for provenance check";
        needle = "dependencies = [fleetEquivalence phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";
      }
      {
        label = "campaign continuity implemented gate import";
        needle = "gate = import ./phase7-crucible-campaign-continuity.nix";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects campaign provenance check";
        needle = "checks.crucible.phase7.crucibleCampaignProvenance";
      }
      {
        label = "CI wiring expects campaign provenance dependency";
        needle = "dependencies = [fleetEquivalence.rawGate phase7.crucibleCampaignManifest phase7.crucibleCampaignSeeding phase7.crucibleCampaignStorageBounding phase7.crucibleCampaignProvenance];";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 campaign provenance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-campaign-provenance";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils] ++ dependencies;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            provenance_key=campaign_provenance_key
            corpus_reuse_decision=CampaignCorpusReuseDecision
            refusal=RefuseCrossProvenanceReuse
            baseline_event=crucible.campaign.fresh-lineage-baseline.v1
            refusal_reason=cross-provenance-corpus-reuse-refused
            gate_dependency=checks.crucible.phase7.gates.campaignContinuity
            campaign_continuity_gate_status=implemented
            RESULT
          '';
        }
      ];
    }

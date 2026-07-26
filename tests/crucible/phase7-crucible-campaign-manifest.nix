{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleCampaignManifest",
  taskIds ? ["T-DCE-4"],
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

  hasInfix = needle: haystack:
    needle == ""
    || builtins.replaceStrings [needle] [""] haystack != haystack;

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
        label = "T-DCE-4 checklist complete";
        needle = "- [x] **T-DCE-4**";
      }
      {
        label = "T-DCE-4 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleCampaignManifest`";
      }
      {
        label = "DCE-9 manifest text";
        needle = "small **campaign manifest**";
      }
      {
        label = "DCE-10 CAS text";
        needle = "campaign head MUST be advanced by **compare-and-swap**";
      }
      {
        label = "DCE-23 read merge retry text";
        needle = "read-merge-retry on conflict";
      }
      {
        label = "T-DCE-4 advisory CAS lock note";
        needle = "advisory lock on that same file";
      }
      {
        label = "T-DCE-4 materialized merge-root note";
        needle = "immutable merge-root records";
      }
      {
        label = "T-DCE-4 append-only head log note";
        needle = "append-only checksummed head log";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "stale T-DCE-4 placeholder";
        needle = "- [ ] **T-DCE-4**";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "shared campaign store type";
        needle = "pub struct SharedCampaignStore";
      }
      {
        label = "campaign manifest type";
        needle = "pub struct CampaignManifest";
      }
      {
        label = "campaign provenance type";
        needle = "pub struct CampaignProvenance";
      }
      {
        label = "campaign CAS outcome";
        needle = "pub enum CampaignCasOutcome";
      }
      {
        label = "campaign head path API";
        needle = "pub fn head_path";
      }
      {
        label = "manifest persistence API";
        needle = "pub fn persist_manifest";
      }
      {
        label = "campaign compare-and-swap API";
        needle = "pub fn compare_and_swap_head";
      }
      {
        label = "campaign read-merge-retry API";
        needle = "pub fn advance_head_with_merge";
      }
      {
        label = "campaign manifest object store";
        needle = "SharedDagStore::new(root.join(\"objects\"))";
      }
      {
        label = "single mutable campaign head";
        needle = "self.root.join(\"campaign-head\")";
      }
      {
        label = "campaign head lock uses rustix flock";
        needle = "flock(&file, operation)";
      }
      {
        label = "campaign CAS takes exclusive lock";
        needle = "FlockOperation::LockExclusive";
      }
      {
        label = "campaign read takes shared lock";
        needle = "FlockOperation::LockShared";
      }
      {
        label = "campaign head appends locked file";
        needle = "SeekFrom::End(0)";
      }
      {
        label = "campaign head entry checksum";
        needle = "campaign_head_entry_checksum";
      }
      {
        label = "campaign head append log material";
        needle = "campaign_head_entry_material";
      }
      {
        label = "manifest root object validation";
        needle = "fn validate_manifest_roots";
      }
      {
        label = "materialized merge-root object";
        needle = "campaign_root_merge_record_material";
      }
      {
        label = "lost CAS retained proposal test";
        needle = "campaign_head_cas_loses_only_bookkeeping";
      }
      {
        label = "contended CAS serialization test";
        needle = "campaign_head_cas_serializes_contending_writers";
      }
      {
        label = "torn head log recovery test";
        needle = "campaign_head_ignores_torn_final_log_entry";
      }
      {
        label = "torn initial head log recovery test";
        needle = "campaign_head_recovers_from_torn_initial_log_entry";
      }
      {
        label = "read merge retry test";
        needle = "campaign_head_compare_and_swap_loop_advances_union_manifest";
      }
    ]
    ++ forbiddenFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "sidecar campaign head lock path";
        needle = "head-locks";
      }
      {
        label = "mtime stale campaign CAS lock repair";
        needle = "repair_stale_campaign_head_lock";
      }
      {
        label = "campaign head destructive truncate";
        needle = "lock.file.set_len(0)";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/bin/crucible-fleet-store.rs" fleetStoreProbe [
      {
        label = "campaign probe function";
        needle = "prove_campaign_manifest_store";
      }
      {
        label = "shared campaign store in probe";
        needle = "SharedCampaignStore::new";
      }
      {
        label = "campaign CAS in probe";
        needle = "compare_and_swap_head";
      }
      {
        label = "campaign read merge in probe";
        needle = "advance_head_with_merge";
      }
      {
        label = "campaign probe checks merged root objects";
        needle = "campaign merged root object was not stored";
      }
      {
        label = "campaign manifest output";
        needle = "campaign_manifest=content-addressed";
      }
      {
        label = "lost CAS output";
        needle = "lost_cas=bookkeeping-only";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fleet-store.nix" fleetStorePackage [
      {
        label = "package validates campaign manifest";
        needle = "grep -q '^campaign_manifest=content-addressed$'";
      }
      {
        label = "package validates campaign head CAS";
        needle = "grep -q '^campaign_head=cas-advanced$'";
      }
      {
        label = "package validates lost CAS";
        needle = "grep -q '^lost_cas=bookkeeping-only$'";
      }
      {
        label = "package records DCE campaign manifest task";
        needle = "dce_campaign_manifest_task=T-DCE-4";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "distributed wrapper consumes campaign manifest gate";
        needle = "campaignManifestGate = crucibleChecks.phase7.crucibleCampaignManifest;";
      }
      {
        label = "distributed wrapper checks campaign manifest result";
        needle = ''campaign_manifest_result="''${campaignManifestGate}/result"'';
      }
      {
        label = "distributed wrapper records campaign manifest result";
        needle = ''campaign_manifest_gate_result=''${campaignManifestGate}/result'';
      }
      {
        label = "distributed wrapper records campaign manifest";
        needle = "campaign_manifest=content-addressed";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 campaign manifest check imported";
        needle = "crucibleCampaignManifest = import ./phase7-crucible-campaign-manifest.nix";
      }
      {
        label = "campaign continuity raw gate waits for campaign manifest";
        needle = campaignContinuityRawDependency;
      }
      {
        label = "campaign continuity wrapper waits for campaign manifest";
        needle = campaignContinuityWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects campaign manifest check";
        needle = "checks.crucible.phase7.crucibleCampaignManifest";
      }
      {
        label = "CI wiring expects campaign manifest raw dependency";
        needle = campaignContinuityRawDependency;
      }
      {
        label = "CI wiring expects campaign manifest wrapper dependency";
        needle = campaignContinuityWrapperDependency;
      }
    ];
in
  if failures != []
  then throw "crucible phase7 campaign manifest check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-campaign-manifest";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep fleetStore] ++ dependencies;

      phases = [
        {
          name = "probe-campaign-manifest";
          script = ''
            set -eu
            probe_root="$TMPDIR/crucible-campaign-manifest"
            "${fleetStore}/bin/crucible-fleet-store" probe "$probe_root" > "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^campaign_store=persistent-dagstore$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^campaign_manifest=content-addressed$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^campaign_head=cas-advanced$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^campaign_head_lock=advisory-head-file$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^campaign_head_log=append-only-checksummed$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^manifest_head_only_mutable=true$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^manifest_roots=corpus,coverage,findings,genesis,provenance$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^manifest_root_objects=required$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^provenance_triple=recorded$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^lost_cas=bookkeeping-only$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^read_merge_retry=enabled$' "$TMPDIR/crucible-campaign-manifest.probe"
            grep -q '^merge_roots=materialized-objects$' "$TMPDIR/crucible-campaign-manifest.probe"

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            fleet_store_component=${fleetStore}
            runtime_probe=crucible-fleet-store probe
            campaign_store=persistent-dagstore
            campaign_manifest=content-addressed
            campaign_head=cas-advanced
            campaign_head_lock=advisory-head-file
            campaign_head_log=append-only-checksummed
            manifest_head_only_mutable=true
            manifest_roots=corpus,coverage,findings,genesis,provenance
            manifest_root_objects=required
            provenance_triple=recorded
            lost_cas=bookkeeping-only
            read_merge_retry=enabled
            merge_roots=materialized-objects
            gate_dependency=checks.crucible.phase7.gates.campaignContinuity
            campaign_continuity_gate_status=implemented
            RESULT
          '';
        }
      ];
    }

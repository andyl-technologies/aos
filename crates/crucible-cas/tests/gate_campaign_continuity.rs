//! Verifies campaign continuity, provenance refusal, and lineage preservation.

#![forbid(unsafe_code)]

use std::error::Error;

use crucible_cas::{
    CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON, CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA,
    CampaignCasOutcome, CampaignContinuitySeedDecision, CampaignFinding, CampaignFreshLineageRoots,
    CampaignManifest, CampaignProvenance, CampaignReplayArtifact, ContentHash, DagStore,
    SharedCampaignStore, campaign_lineage_id, campaign_provenance_key,
};

#[test]
fn gate_campaign_continuity_seeds_prior_corpus_and_ratchets_coverage() -> Result<(), Box<dyn Error>>
{
    let temp = tempfile::tempdir()?;
    let campaign = SharedCampaignStore::new(temp.path());
    let provenance = campaign_provenance("qemu-a", "abi-a");
    let artifact_a = artifact("a");
    let artifact_b = artifact("b");
    let edge_a = ContentHash::from_bytes(b"coverage:a");
    let edge_b = ContentHash::from_bytes(b"coverage:b");
    let prior_manifest = CampaignManifest::new(
        campaign.persist_campaign_corpus([artifact_a.clone()])?,
        campaign.persist_accumulated_coverage_map([edge_a])?,
        campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"finding:a"),
            artifact_a.clone(),
        )])?,
        campaign.manifest_store().put(b"genesis:a")?,
        provenance.clone(),
    );
    let unused_fresh_roots = fresh_empty_roots(&campaign, "unused")?;

    let decision =
        campaign.seed_next_run_for_provenance(&prior_manifest, &provenance, unused_fresh_roots)?;

    let seeds = match decision {
        CampaignContinuitySeedDecision::SeedPriorCorpus {
            seeds,
            lineage_id,
            provenance_key,
        } => {
            assert_eq!(lineage_id, campaign_lineage_id(&prior_manifest)?);
            assert_eq!(provenance_key, campaign_provenance_key(&provenance)?);
            seeds
        }
        CampaignContinuitySeedDecision::RefuseCrossProvenanceReuse(_) => {
            return Err("same-provenance campaign refused prior corpus".into());
        }
    };
    assert_eq!(seeds.len(), 1);
    assert!(seeds.iter().all(|seed| seed.reproduces_bit_identically()));
    assert_eq!(seeds[0].artifact, artifact_a);

    let next_manifest = CampaignManifest::new(
        campaign.persist_campaign_corpus([artifact_a.clone(), artifact_b.clone()])?,
        campaign.merge_accumulated_coverage_maps(
            prior_manifest.coverage_map_root,
            campaign.persist_accumulated_coverage_map([edge_b])?,
        )?,
        campaign.merge_findings_ledgers(
            prior_manifest.findings_root,
            campaign.persist_findings_ledger([CampaignFinding::new(
                ContentHash::from_bytes(b"finding:b"),
                artifact_b,
            )])?,
        )?,
        prior_manifest.genesis_pin,
        provenance,
    );
    let prior_head = match campaign.compare_and_swap_head(None, &prior_manifest)? {
        CampaignCasOutcome::Advanced(head) => head,
        CampaignCasOutcome::LostUpdate { .. } => {
            return Err("initial campaign continuity CAS lost".into());
        }
    };
    match campaign.compare_and_swap_head(Some(prior_head.manifest_hash), &next_manifest)? {
        CampaignCasOutcome::Advanced(head) => {
            assert_eq!(
                head.manifest.coverage_map_root,
                next_manifest.coverage_map_root
            );
        }
        CampaignCasOutcome::LostUpdate { .. } => {
            return Err("campaign continuity CAS lost".into());
        }
    }

    let coverage_edges = campaign.accumulated_coverage_edges(next_manifest.coverage_map_root)?;
    assert_eq!(coverage_edges, sorted_hashes([edge_a, edge_b]));
    let redundant =
        campaign.accumulated_coverage_delta(next_manifest.coverage_map_root, [edge_a])?;
    let novel = campaign.accumulated_coverage_delta(
        next_manifest.coverage_map_root,
        [edge_a, ContentHash::from_bytes(b"coverage:c")],
    )?;
    assert!(!redundant.is_novel());
    assert!(novel.is_novel());

    let coverage_regression = CampaignManifest::new(
        next_manifest.corpus_root,
        prior_manifest.coverage_map_root,
        next_manifest.findings_root,
        next_manifest.genesis_pin,
        next_manifest.provenance.clone(),
    );
    assert!(matches!(
        campaign.compare_and_swap_head(
            campaign.read_head()?.map(|head| head.manifest_hash),
            &coverage_regression,
        ),
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "campaign coverage-map advance would reduce accumulated coverage",
            ..
        })
    ));

    Ok(())
}

#[test]
fn gate_campaign_continuity_refuses_cross_provenance_and_forks_fresh_lineage()
-> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let campaign = SharedCampaignStore::new(temp.path());
    let prior_provenance = campaign_provenance("qemu-a", "abi-a");
    let run_provenance = campaign_provenance("qemu-b", "abi-a");
    let artifact_a = artifact("a");
    let prior_manifest = CampaignManifest::new(
        campaign.persist_campaign_corpus([artifact_a.clone()])?,
        campaign.persist_accumulated_coverage_map([ContentHash::from_bytes(b"coverage:a")])?,
        campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"finding:a"),
            artifact_a,
        )])?,
        campaign.manifest_store().put(b"genesis:a")?,
        prior_provenance,
    );
    let prior_head = match campaign.compare_and_swap_head(None, &prior_manifest)? {
        CampaignCasOutcome::Advanced(head) => head,
        CampaignCasOutcome::LostUpdate { .. } => {
            return Err("initial cross-provenance campaign CAS lost".into());
        }
    };
    assert_eq!(prior_head.manifest, prior_manifest);
    let fresh_roots = fresh_empty_roots(&campaign, "fresh")?;
    assert!(matches!(
        campaign.seed_next_run(&prior_manifest, &run_provenance),
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "campaign seed provenance does not match manifest provenance",
            ..
        })
    ));

    let decision =
        campaign.seed_next_run_for_provenance(&prior_manifest, &run_provenance, fresh_roots)?;

    let event = match decision {
        CampaignContinuitySeedDecision::RefuseCrossProvenanceReuse(event) => *event,
        CampaignContinuitySeedDecision::SeedPriorCorpus { .. } => {
            return Err("cross-provenance campaign seeded prior corpus".into());
        }
    };
    assert_eq!(
        event.schema_version,
        CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA
    );
    assert_eq!(event.reason, CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON);
    assert_eq!(event.refused_corpus_root, prior_manifest.corpus_root);
    assert_eq!(
        event.previous_lineage_id,
        campaign_lineage_id(&prior_manifest)?
    );
    assert_eq!(
        event.previous_provenance_key,
        campaign_provenance_key(&prior_manifest.provenance)?
    );
    assert_eq!(
        event.run_provenance_key,
        campaign_provenance_key(&run_provenance)?
    );
    assert_ne!(event.previous_provenance_key, event.run_provenance_key);
    assert_ne!(event.previous_lineage_id, event.fresh_lineage_id);
    assert_ne!(event.baseline_event_hash, ContentHash::default());
    assert!(campaign.manifest_store().has(&event.baseline_event_hash)?);
    assert_eq!(
        campaign.read_fresh_lineage_baseline_event(event.baseline_event_hash)?,
        event
    );
    assert_eq!(event.fresh_manifest.provenance, run_provenance);
    assert_ne!(event.fresh_manifest.corpus_root, prior_manifest.corpus_root);
    assert_ne!(
        event.fresh_manifest.coverage_map_root,
        prior_manifest.coverage_map_root
    );
    assert_ne!(
        event.fresh_manifest.findings_root,
        prior_manifest.findings_root
    );
    assert_ne!(event.fresh_manifest.genesis_pin, prior_manifest.genesis_pin);
    assert!(campaign.manifest_store().has(&event.fresh_manifest_hash)?);
    assert!(
        campaign
            .seed_next_run(&event.fresh_manifest, &run_provenance)?
            .is_empty()
    );
    assert!(
        campaign
            .accumulated_coverage_edges(event.fresh_manifest.coverage_map_root)?
            .is_empty()
    );
    assert!(
        campaign
            .findings_ledger_entries(event.fresh_manifest.findings_root)?
            .is_empty()
    );
    let fresh_head = campaign.read_head()?.ok_or("missing fresh lineage head")?;
    assert_eq!(fresh_head.manifest_hash, event.fresh_manifest_hash);
    assert_eq!(fresh_head.manifest, event.fresh_manifest);

    let prior_finding = campaign
        .findings_ledger_entries(prior_manifest.findings_root)?
        .into_iter()
        .next()
        .ok_or("missing prior finding")?;
    let prior_artifact = campaign.read_replay_artifact(prior_finding.artifact_hash)?;
    assert!(prior_finding.reproduces_bit_identically(&prior_artifact));

    Ok(())
}

#[test]
fn gate_campaign_continuity_rejects_silent_cross_provenance_mixing() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let campaign = SharedCampaignStore::new(temp.path());
    let prior_manifest = CampaignManifest::new(
        campaign.persist_campaign_corpus([artifact("a")])?,
        campaign.persist_accumulated_coverage_map([ContentHash::from_bytes(b"coverage:a")])?,
        campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"finding:a"),
            artifact("a"),
        )])?,
        campaign.manifest_store().put(b"genesis:a")?,
        campaign_provenance("qemu-a", "abi-a"),
    );
    let run_provenance = campaign_provenance("qemu-a", "abi-b");
    let reused_corpus_roots = CampaignFreshLineageRoots::new(
        prior_manifest.corpus_root,
        campaign.persist_accumulated_coverage_map([])?,
        campaign.persist_findings_ledger([])?,
        campaign.manifest_store().put(b"genesis:b")?,
    );
    assert!(matches!(
        campaign.seed_next_run_for_provenance(
            &prior_manifest,
            &run_provenance,
            reused_corpus_roots,
        ),
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "fresh campaign lineage must use a new corpus root",
            ..
        })
    ));

    let reused_coverage_roots = CampaignFreshLineageRoots::new(
        campaign.persist_campaign_corpus([])?,
        prior_manifest.coverage_map_root,
        campaign.persist_findings_ledger([])?,
        campaign.manifest_store().put(b"genesis:c")?,
    );
    assert!(matches!(
        campaign.seed_next_run_for_provenance(
            &prior_manifest,
            &run_provenance,
            reused_coverage_roots,
        ),
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "fresh campaign lineage must use a new coverage-map root",
            ..
        })
    ));

    let copied_prior_artifact_roots = CampaignFreshLineageRoots::new(
        campaign.persist_campaign_corpus([artifact("a"), artifact("fresh-copied-corpus")])?,
        campaign
            .persist_accumulated_coverage_map([ContentHash::from_bytes(b"fresh-copied-corpus")])?,
        campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"fresh-finding:copied-corpus"),
            artifact("fresh-copied-corpus"),
        )])?,
        campaign.manifest_store().put(b"genesis:d")?,
    );
    assert!(matches!(
        campaign.seed_next_run_for_provenance(
            &prior_manifest,
            &run_provenance,
            copied_prior_artifact_roots,
        ),
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "fresh campaign lineage corpus must not reuse prior corpus entries",
            ..
        })
    ));

    let copied_prior_coverage_roots = CampaignFreshLineageRoots::new(
        campaign.persist_campaign_corpus([artifact("fresh-copied-coverage")])?,
        campaign.persist_accumulated_coverage_map([
            ContentHash::from_bytes(b"coverage:a"),
            ContentHash::from_bytes(b"fresh-coverage"),
        ])?,
        campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"fresh-finding:copied-coverage"),
            artifact("fresh-copied-coverage"),
        )])?,
        campaign.manifest_store().put(b"genesis:e")?,
    );
    assert!(matches!(
        campaign.seed_next_run_for_provenance(
            &prior_manifest,
            &run_provenance,
            copied_prior_coverage_roots,
        ),
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "fresh campaign lineage coverage must not reuse prior coverage edges",
            ..
        })
    ));

    let copied_prior_finding_roots = CampaignFreshLineageRoots::new(
        campaign.persist_campaign_corpus([artifact("fresh-copied-finding")])?,
        campaign
            .persist_accumulated_coverage_map([ContentHash::from_bytes(b"fresh-finding-edge")])?,
        campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"fresh-finding:prior-artifact"),
            artifact("a"),
        )])?,
        campaign.manifest_store().put(b"genesis:f")?,
    );
    assert!(matches!(
        campaign.seed_next_run_for_provenance(
            &prior_manifest,
            &run_provenance,
            copied_prior_finding_roots,
        ),
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "fresh campaign lineage findings must not reuse prior finding artifacts",
            ..
        })
    ));

    Ok(())
}

#[test]
fn gate_campaign_continuity_requires_prior_manifest_as_current_head() -> Result<(), Box<dyn Error>>
{
    let temp = tempfile::tempdir()?;
    let campaign = SharedCampaignStore::new(temp.path());
    let prior_manifest = CampaignManifest::new(
        campaign.persist_campaign_corpus([artifact("a")])?,
        campaign.persist_accumulated_coverage_map([ContentHash::from_bytes(b"coverage:a")])?,
        campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"finding:a"),
            artifact("a"),
        )])?,
        campaign.manifest_store().put(b"genesis:a")?,
        campaign_provenance("qemu-a", "abi-a"),
    );
    let fresh_roots = CampaignFreshLineageRoots::new(
        campaign.persist_campaign_corpus([artifact("fresh-current-head")])?,
        campaign
            .persist_accumulated_coverage_map([ContentHash::from_bytes(b"fresh-current-head")])?,
        campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"fresh-finding:current-head"),
            artifact("fresh-current-head"),
        )])?,
        campaign
            .manifest_store()
            .put(b"genesis:fresh-current-head")?,
    );

    assert!(matches!(
        campaign.seed_next_run_for_provenance(
            &prior_manifest,
            &campaign_provenance("qemu-b", "abi-a"),
            fresh_roots,
        ),
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "fresh campaign lineage requires prior manifest to be current head",
            ..
        })
    ));
    assert!(campaign.read_head()?.is_none());

    Ok(())
}

fn campaign_provenance(qemu_build: &str, abi_versions: &str) -> CampaignProvenance {
    CampaignProvenance::new("crucible-test", qemu_build, abi_versions)
}

fn artifact(label: &str) -> CampaignReplayArtifact {
    CampaignReplayArtifact::new(
        format!("definition:{label}").into_bytes(),
        format!("seed:{label}").into_bytes(),
        format!("schedule:{label}").into_bytes(),
    )
}

fn fresh_empty_roots(
    campaign: &SharedCampaignStore,
    label: &str,
) -> Result<CampaignFreshLineageRoots, Box<dyn Error>> {
    Ok(CampaignFreshLineageRoots::new(
        campaign.persist_campaign_corpus([])?,
        campaign.persist_accumulated_coverage_map([])?,
        campaign.persist_findings_ledger([])?,
        campaign
            .manifest_store()
            .put(format!("genesis:{label}").as_bytes())?,
    ))
}

fn sorted_hashes<const N: usize>(hashes: [ContentHash; N]) -> Vec<ContentHash> {
    let mut hashes = hashes.to_vec();
    hashes.sort();
    hashes
}

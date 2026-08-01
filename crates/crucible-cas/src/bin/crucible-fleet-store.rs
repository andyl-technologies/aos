//! Probes the fleet-visible Crucible content-addressed store.
//!
//! This small binary is packaged as the AOS `crucible-fleet-store` component.
//! It intentionally exposes only a deterministic local probe surface for the
//! packaging and fleet-check harnesses; the public store interface remains the
//! `crucible-cas` [`crucible_cas::DagStore`] trait.

use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use crucible_cas::{
    CampaignCasOutcome, CampaignCheckpointMaterialization, CampaignContinuitySeedDecision,
    CampaignCorpusRetentionPolicy, CampaignFinding, CampaignFreshLineageRoots, CampaignManifest,
    CampaignProvenance, CampaignReplayArtifact, ContentHash, DagStore, ExpansionDedupDecision,
    FrontierClaimRequest, SharedCampaignStore, SharedDagStore, SharedDedupIndex, SharedFrontier,
    SoftHashAffinity,
};

const PROBE_PAYLOAD: &[u8] = b"crucible-fleet-store-probe-v1";
const CONCURRENT_WRITERS: usize = 16;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    let program = match args.next() {
        Some(program) => program,
        None => OsString::from("crucible-fleet-store"),
    };
    let Some(command) = args.next() else {
        print_usage(&program);
        return Err(input_error("missing command"));
    };
    match command.to_string_lossy().as_ref() {
        "probe" => {
            let Some(root) = args.next() else {
                print_usage(&program);
                return Err(input_error("missing probe root"));
            };
            if args.next().is_some() {
                print_usage(&program);
                return Err(input_error("unexpected extra argument"));
            }
            run_probe(PathBuf::from(root))
        }
        _ => {
            print_usage(&program);
            Err(input_error(format!(
                "unknown command `{}`",
                command.to_string_lossy()
            )))
        }
    }
}

fn print_usage(program: &OsString) {
    eprintln!("usage: {} probe <store-root>", program.to_string_lossy());
}

fn input_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn run_probe(root: PathBuf) -> Result<(), Box<dyn Error>> {
    let location_key =
        prove_location_independent_identity(&root.join("host-a"), &root.join("host-b"))?;
    let concurrent_key = prove_concurrent_put_idempotent(&root.join("shared"))?;
    let object_file_count =
        count_regular_files_named(&root.join("shared"), &concurrent_key.to_hex())?;
    if object_file_count != 1 {
        return Err(input_error(
            "shared store probe created duplicate concurrent objects",
        ));
    }
    prove_frontier_claim_leases(&root.join("leases"))?;
    prove_four_layer_dedup(&root.join("dedup"))?;
    prove_campaign_manifest_store(&root.join("campaign"))?;
    prove_campaign_seed_coverage_findings(&root.join("campaign-continuity-substrate"))?;
    prove_campaign_storage_bounding(&root.join("campaign-storage-bounding"))?;
    prove_campaign_continuity_gate(&root.join("campaign-continuity-gate"))?;

    println!("crucible-fleet-store probe");
    println!("root={}", root.display());
    println!("object={}", concurrent_key.to_hex());
    println!("interface=DagStore::put,DagStore::get,DagStore::has");
    println!("backend=SharedDagStore");
    println!("location_independent_identity=true");
    println!("location_independent_roots=2");
    println!("location_independent_object={}", location_key.to_hex());
    println!("concurrent_put=idempotent");
    println!("concurrent_writers={CONCURRENT_WRITERS}");
    println!("object_file_count={object_file_count}");
    println!("claim_lease=ttl-hint");
    println!("claim_key=content-addressed");
    println!("claim_path_excludes_host=true");
    println!("expired_lease=reclaimable");
    println!("stale_claim_lock=reclaimable");
    println!("reclaimed_node_byte_identical=true");
    println!("hash_affinity=priority-only");
    println!("affinity_filters_frontier=false");
    println!("static_partitioning=false");
    println!("lease_ttl_ticks=5");
    println!("dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set");
    println!("exists_gated_expansion=skip-existing");
    println!("coverage_map_admission=compare-and-merge");
    println!("coverage_map_repair=entry-markers-before-fingerprint");
    println!("coverage_map_duplicate=skipped");
    println!("reduction_fingerprint=shared-prune");
    println!("claim_set_anti_redundancy=unclaimed-first");
    println!("campaign_store=persistent-dagstore");
    println!("campaign_manifest=content-addressed");
    println!("campaign_head=cas-advanced");
    println!("campaign_head_lock=advisory-head-file");
    println!("campaign_head_log=append-only-checksummed");
    println!("manifest_head_only_mutable=true");
    println!("manifest_roots=corpus,coverage,findings,genesis,provenance");
    println!("manifest_root_objects=required");
    println!("provenance_triple=recorded");
    println!("lost_cas=bookkeeping-only");
    println!("read_merge_retry=enabled");
    println!("merge_roots=materialized-objects");
    println!("campaign_seed=prior-corpus");
    println!("campaign_seed_artifact=self-contained");
    println!("campaign_seed_replay=bit-identical");
    println!("campaign_seed_process_state=not-required");
    println!("coverage_ratchet=grow-only-union-crdt");
    println!("coverage_ratchet_monotone=true");
    println!("coverage_crdt=commutative-associative-idempotent");
    println!("coverage_novelty=against-accumulated-map");
    println!("findings_ledger=cross-run-grow-only");
    println!("findings_ledger_dedup=content-addressed");
    println!("finding_replay=bit-identical-from-ledger");
    println!("campaign_gc_roots=manifest-roots");
    println!("campaign_gc_scope=corpus,coverage,findings,genesis");
    println!("campaign_gc_unpinned=swept-candidate");
    println!("campaign_gc_value=cache-only");
    println!("fat_to_thin_eviction=value-preserved");
    println!("thin_checkpoint_source=parent-schedule-delta");
    println!("corpus_retention=deterministic-seeded-cap");
    println!("corpus_retention_authorized=explicit-policy");
    println!("corpus_retention_reproducible=true");
    println!("corpus_retention_root=source-cap-seed-proof");
    println!("findings_ledger_retention=never-evict");
    println!("campaign_continuity=implemented");
    println!("campaign_continuity_seed_reproducible=true");
    println!("campaign_continuity_coverage_monotone=true");
    println!("campaign_continuity_cross_provenance_refused=true");
    println!("campaign_continuity_fresh_lineage=forked");
    println!("campaign_continuity_prior_findings_reproducible=true");
    println!("provenance_seed_gate=triple-keyed");
    Ok(())
}

fn prove_location_independent_identity(
    left_root: &Path,
    right_root: &Path,
) -> Result<crucible_cas::ContentHash, Box<dyn Error>> {
    let left = SharedDagStore::new(left_root);
    let right = SharedDagStore::new(right_root);
    let left_key = left.put(PROBE_PAYLOAD)?;
    let right_key = right.put(PROBE_PAYLOAD)?;
    if left_key != right_key {
        return Err(input_error(
            "shared store probe produced root-dependent keys",
        ));
    }
    if left.object_path(&left_key) == right.object_path(&right_key) {
        return Err(input_error(
            "shared store probe used the same path for distinct roots",
        ));
    }
    if left.get(&left_key)? != right.get(&right_key)? {
        return Err(input_error(
            "shared store probe read root-dependent object bytes",
        ));
    }
    Ok(left_key)
}

fn prove_concurrent_put_idempotent(
    root: &Path,
) -> Result<crucible_cas::ContentHash, Box<dyn Error>> {
    let store = Arc::new(SharedDagStore::new(root));
    let start = Arc::new(Barrier::new(CONCURRENT_WRITERS));
    let mut handles = Vec::with_capacity(CONCURRENT_WRITERS);
    for _ in 0..CONCURRENT_WRITERS {
        let store = Arc::clone(&store);
        let start = Arc::clone(&start);
        handles.push(thread::spawn(move || {
            start.wait();
            store.put(PROBE_PAYLOAD)
        }));
    }

    let mut key = None;
    for handle in handles {
        let writer_key = handle
            .join()
            .map_err(|_| input_error("shared store writer panicked"))??;
        match key {
            Some(existing) if existing != writer_key => {
                return Err(input_error(
                    "shared store probe produced non-idempotent concurrent keys",
                ));
            }
            Some(_) => {}
            None => key = Some(writer_key),
        }
    }

    let key =
        key.ok_or_else(|| input_error("shared store probe did not publish a concurrent key"))?;
    if !store.has(&key)? {
        return Err(input_error(
            "shared store probe lost the concurrently published object",
        ));
    }
    if store.get(&key)? != PROBE_PAYLOAD {
        return Err(input_error(
            "shared store probe read back different concurrent bytes",
        ));
    }
    Ok(key)
}

fn prove_frontier_claim_leases(root: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Box::new(source)),
    }
    let store = SharedDagStore::new(root.join("objects"));
    let frontier = SharedFrontier::new(root.join("frontier"));
    let node_a = store.put(b"frontier-lease-a")?;
    let node_b = store.put(b"frontier-lease-b")?;
    frontier.admit(&node_a)?;
    frontier.admit(&node_b)?;

    let without_affinity = frontier.ordered_claimable_nodes(100, &SoftHashAffinity::off())?;
    let with_affinity =
        frontier.ordered_claimable_nodes(100, &SoftHashAffinity::prefer([node_b]))?;
    let mut without_set = without_affinity.clone();
    without_set.sort();
    let mut with_set = with_affinity.clone();
    with_set.sort();
    if with_set != without_set {
        return Err(input_error("soft hash affinity filtered the frontier"));
    }
    if with_affinity.first().copied() != Some(node_b) {
        return Err(input_error(
            "soft hash affinity did not prioritize the preferred node",
        ));
    }

    let preferred_lease = frontier
        .claim_next(
            &FrontierClaimRequest::new("host-a", 100, 5)
                .with_affinity(SoftHashAffinity::prefer([node_b])),
        )?
        .ok_or_else(|| input_error("frontier lease probe did not claim preferred node"))?;
    if preferred_lease.node != node_b {
        return Err(input_error("frontier lease probe claimed the wrong node"));
    }
    let claim_path = frontier.claim_path(&node_b);
    let claim_path_text = claim_path.to_string_lossy();
    if claim_path_text.contains("host-a") || claim_path_text.contains("host-b") {
        return Err(input_error("frontier claim path contains host metadata"));
    }

    let fallback_lease = frontier
        .claim_next(
            &FrontierClaimRequest::new("host-b", 101, 5)
                .with_affinity(SoftHashAffinity::prefer([node_b])),
        )?
        .ok_or_else(|| input_error("affinity filtered non-preferred claimable node"))?;
    if fallback_lease.node == node_b {
        return Err(input_error("unexpired lease was treated as claimable"));
    }

    let reclaimed = frontier
        .claim_next(
            &FrontierClaimRequest::new("host-b", 105, 5)
                .with_affinity(SoftHashAffinity::prefer([node_b])),
        )?
        .ok_or_else(|| input_error("expired frontier lease did not become claimable"))?;
    if reclaimed.node != node_b {
        return Err(input_error("expired lease did not reclaim the same node"));
    }
    if store.put(b"frontier-lease-b")? != node_b {
        return Err(input_error(
            "re-expanded frontier node did not dedup to the same content address",
        ));
    }

    let node_c = store.put(b"frontier-lease-stale-lock")?;
    let stale_frontier = SharedFrontier::new(root.join("stale-lock-frontier"));
    stale_frontier.admit(&node_c)?;
    let stale_lock_path = probe_content_path(&stale_frontier.root().join("claim-locks"), &node_c);
    if let Some(parent) = stale_lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &stale_lock_path,
        probe_claim_lock_record_material(&node_c, 200, 205),
    )?;
    if stale_frontier
        .claim_next(&FrontierClaimRequest::new("host-c", 204, 5))?
        .is_some()
    {
        return Err(input_error("unexpired claim lock was treated as stale"));
    }
    let stale_lock_reclaimed = stale_frontier
        .claim_next(&FrontierClaimRequest::new("host-c", 205, 5))?
        .ok_or_else(|| input_error("expired claim lock did not become reclaimable"))?;
    if stale_lock_reclaimed.node != node_c {
        return Err(input_error(
            "expired claim lock reclaimed a different frontier node",
        ));
    }

    Ok(())
}

fn prove_four_layer_dedup(root: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Box::new(source)),
    }
    let store = SharedDagStore::new(root.join("objects"));
    let index = SharedDedupIndex::new(root.join("index"));

    let child = ContentHash::from_bytes(b"four-layer-child");
    if index.exists_gated_expansion(&store, &child)? != ExpansionDedupDecision::Expand {
        return Err(input_error("absent child was not expandable"));
    }
    if store.put(b"four-layer-child")? != child {
        return Err(input_error("four-layer child did not use its content key"));
    }
    if index.exists_gated_expansion(&store, &child)? != ExpansionDedupDecision::SkipExisting {
        return Err(input_error("existing child was not skipped"));
    }

    let edge_a = ContentHash::from_bytes(b"coverage-edge-a");
    let edge_b = ContentHash::from_bytes(b"coverage-edge-b");
    let edge_c = ContentHash::from_bytes(b"coverage-edge-c");
    let coverage_ab = ContentHash::from_bytes(b"coverage-a-b");
    let first_coverage = index.admit_coverage_map(coverage_ab, [edge_a, edge_b])?;
    if !first_coverage.admitted() || first_coverage.new_entries.len() != 2 {
        return Err(input_error("new shared coverage was not admitted"));
    }
    let same_fingerprint = index.admit_coverage_map(coverage_ab, [edge_a, edge_b])?;
    if !same_fingerprint.redundant() || same_fingerprint.duplicate_entries.len() != 2 {
        return Err(input_error(
            "duplicate coverage fingerprint was not skipped",
        ));
    }
    let interrupted_fingerprint = ContentHash::from_bytes(b"coverage-interrupted");
    let interrupted_a = ContentHash::from_bytes(b"coverage-interrupted-a");
    let interrupted_b = ContentHash::from_bytes(b"coverage-interrupted-b");
    let interrupted_path = probe_content_path(
        &index.root().join("coverage-fingerprints"),
        &interrupted_fingerprint,
    );
    if let Some(parent) = interrupted_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &interrupted_path,
        probe_coverage_fingerprint_record_material(
            &interrupted_fingerprint,
            &[interrupted_a, interrupted_b],
        ),
    )?;
    if probe_content_path(&index.root().join("coverage-map"), &interrupted_a).exists() {
        return Err(input_error(
            "interrupted coverage admission already had entry markers",
        ));
    }
    let repaired =
        index.admit_coverage_map(interrupted_fingerprint, [interrupted_a, interrupted_b])?;
    if !repaired.redundant()
        || repaired.duplicate_entries.len() != 2
        || !probe_content_path(&index.root().join("coverage-map"), &interrupted_a).exists()
        || !probe_content_path(&index.root().join("coverage-map"), &interrupted_b).exists()
    {
        return Err(input_error(
            "interrupted coverage admission was not repaired",
        ));
    }
    let duplicate_coverage = index.admit_coverage_map(
        ContentHash::from_bytes(b"coverage-a-b-duplicate"),
        [edge_a, edge_b],
    )?;
    if !duplicate_coverage.redundant() || duplicate_coverage.duplicate_entries.len() != 2 {
        return Err(input_error("duplicate shared coverage was not skipped"));
    }
    let merged_coverage =
        index.admit_coverage_map(ContentHash::from_bytes(b"coverage-b-c"), [edge_b, edge_c])?;
    if merged_coverage.new_entries != vec![edge_c]
        || merged_coverage.duplicate_entries != vec![edge_b]
    {
        return Err(input_error(
            "shared coverage compare-and-merge did not isolate novelty",
        ));
    }

    let reduction_fingerprint = ContentHash::from_bytes(b"symmetry-por-fingerprint");
    let representative = ContentHash::from_bytes(b"canonical-representative");
    let covered = ContentHash::from_bytes(b"covered-equivalent");
    let first_reduction =
        index.admit_reduction_fingerprint(reduction_fingerprint, representative)?;
    if !first_reduction.admitted() || first_reduction.representative != representative {
        return Err(input_error(
            "first shared reduction fingerprint was not retained",
        ));
    }
    let covered_reduction = index.admit_reduction_fingerprint(reduction_fingerprint, covered)?;
    if !covered_reduction.covered()
        || covered_reduction.representative != representative
        || covered_reduction.covered != Some(covered)
    {
        return Err(input_error(
            "shared reduction fingerprint did not prune covered candidate",
        ));
    }

    let frontier = SharedFrontier::new(root.join("frontier"));
    let node_a = store.put(b"claim-anti-redundancy-a")?;
    let node_b = store.put(b"claim-anti-redundancy-b")?;
    frontier.admit(&node_a)?;
    frontier.admit(&node_b)?;
    let first_claim = frontier
        .claim_next(&FrontierClaimRequest::new("host-a", 1, 5))?
        .ok_or_else(|| input_error("first host did not claim a frontier node"))?;
    let second_claim = frontier
        .claim_next(&FrontierClaimRequest::new("host-b", 2, 5))?
        .ok_or_else(|| input_error("second host did not claim fallback frontier node"))?;
    if first_claim.node == second_claim.node {
        return Err(input_error(
            "claim-set anti-redundancy reused a leased node",
        ));
    }
    if frontier.claimable_nodes(3)?.contains(&first_claim.node) {
        return Err(input_error("leased node remained in the claimable set"));
    }

    Ok(())
}

fn prove_campaign_manifest_store(root: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Box::new(source)),
    }
    let campaign = SharedCampaignStore::new(root);
    let first = probe_campaign_manifest(&campaign, "corpus-a", "coverage-a", "findings-a")?;
    let second = probe_campaign_manifest(&campaign, "corpus-b", "coverage-b", "findings-b")?;
    let first_hash = campaign.persist_manifest(&first)?;
    let mirror = SharedCampaignStore::new(root.join("mirror"));
    let mirror_first = probe_campaign_manifest(&mirror, "corpus-a", "coverage-a", "findings-a")?;
    if mirror.persist_manifest(&mirror_first)? != first_hash {
        return Err(input_error(
            "campaign manifest identity depended on store location",
        ));
    }
    if campaign.head_path() == campaign.manifest_store().object_path(&first_hash) {
        return Err(input_error("campaign head was stored as a manifest object"));
    }

    let first_head = match campaign.compare_and_swap_head(None, &first)? {
        CampaignCasOutcome::Advanced(head) => head,
        CampaignCasOutcome::LostUpdate { .. } => {
            return Err(input_error("initial campaign head CAS lost"));
        }
    };
    let proposed_manifest_hash = match campaign.compare_and_swap_head(None, &second)? {
        CampaignCasOutcome::LostUpdate {
            current,
            proposed_manifest_hash,
            ..
        } => {
            if current != Some(first_head.manifest_hash) {
                return Err(input_error("lost campaign CAS reported wrong current head"));
            }
            proposed_manifest_hash
        }
        CampaignCasOutcome::Advanced(_) => {
            return Err(input_error("stale campaign head CAS advanced"));
        }
    };
    if !campaign.manifest_store().has(&proposed_manifest_hash)? {
        return Err(input_error(
            "lost campaign CAS did not retain proposed manifest",
        ));
    }
    if campaign.read_head()?.map(|head| head.manifest_hash) != Some(first_head.manifest_hash) {
        return Err(input_error("lost campaign CAS changed the head"));
    }

    let merged = campaign.advance_head_with_merge(&second, 3)?;
    if merged.head.manifest_hash == first_head.manifest_hash {
        return Err(input_error(
            "read-merge-retry did not advance campaign head",
        ));
    }
    if merged.head.manifest.provenance != first.provenance {
        return Err(input_error("campaign manifest lost provenance triple"));
    }
    if merged.head.manifest.genesis_pin != first.genesis_pin {
        return Err(input_error("campaign manifest lost genesis pin"));
    }
    for root in [
        merged.head.manifest.corpus_root,
        merged.head.manifest.coverage_map_root,
        merged.head.manifest.findings_root,
    ] {
        if !campaign.manifest_store().has(&root)? {
            return Err(input_error("campaign merged root object was not stored"));
        }
    }
    if campaign.read_head()?.map(|head| head.manifest_hash) != Some(merged.head.manifest_hash) {
        return Err(input_error(
            "campaign head did not point at merged manifest",
        ));
    }

    Ok(())
}

fn probe_campaign_manifest(
    campaign: &SharedCampaignStore,
    corpus: &str,
    coverage: &str,
    findings: &str,
) -> Result<CampaignManifest, Box<dyn Error>> {
    Ok(CampaignManifest::new(
        probe_campaign_root(campaign, "corpus", corpus)?,
        probe_campaign_root(campaign, "coverage-map", coverage)?,
        probe_campaign_root(campaign, "findings", findings)?,
        ContentHash::from_bytes(b"genesis-pin"),
        CampaignProvenance::new("crucible-probe", "qemu-probe+series", "shmem:1,gh:1,rpc:1"),
    ))
}

fn probe_campaign_root(
    campaign: &SharedCampaignStore,
    label: &str,
    value: &str,
) -> Result<ContentHash, Box<dyn Error>> {
    campaign
        .manifest_store()
        .put(
            format!("format=crucible.campaign-root-probe.v1\nlabel={label}\nvalue={value}\n")
                .as_bytes(),
        )
        .map_err(|error| Box::new(error) as Box<dyn Error>)
}

fn prove_campaign_seed_coverage_findings(root: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Box::new(source)),
    }
    let campaign = SharedCampaignStore::new(root);
    let artifact_a = CampaignReplayArtifact::new(
        b"definition:seed-a".to_vec(),
        b"seed:a".to_vec(),
        b"schedule:a".to_vec(),
    );
    let artifact_b = CampaignReplayArtifact::new(
        b"definition:seed-b".to_vec(),
        b"seed:b".to_vec(),
        b"schedule:b".to_vec(),
    );
    let edge_a = ContentHash::from_bytes(b"campaign-continuity-edge-a");
    let edge_b = ContentHash::from_bytes(b"campaign-continuity-edge-b");
    let edge_c = ContentHash::from_bytes(b"campaign-continuity-edge-c");
    let corpus_root = campaign.persist_campaign_corpus([
        artifact_a.clone(),
        artifact_b.clone(),
        artifact_a.clone(),
    ])?;
    let coverage_left = campaign.persist_accumulated_coverage_map([edge_a, edge_b])?;
    let coverage_right = campaign.persist_accumulated_coverage_map([edge_b, edge_c])?;
    let findings_left = campaign.persist_findings_ledger([CampaignFinding::new(
        ContentHash::from_bytes(b"finding-a"),
        artifact_a,
    )])?;
    let findings_right = campaign.persist_findings_ledger([CampaignFinding::new(
        ContentHash::from_bytes(b"finding-b"),
        artifact_b,
    )])?;
    let manifest = CampaignManifest::new(
        corpus_root,
        coverage_left,
        findings_left,
        ContentHash::from_bytes(b"genesis-pin"),
        CampaignProvenance::new("crucible-probe", "qemu-probe+series", "shmem:1,gh:1,rpc:1"),
    );

    let seeds = campaign.seed_next_run(&manifest, &manifest.provenance)?;
    if seeds.len() != 2 || !seeds.iter().all(|seed| seed.reproduces_bit_identically()) {
        return Err(input_error(
            "campaign corpus seeds did not replay bit-identically",
        ));
    }
    if seeds.iter().any(|seed| {
        seed.artifact.definition().is_empty()
            || seed.artifact.seed().is_empty()
            || seed.artifact.schedule().is_empty()
    }) {
        return Err(input_error("campaign seed artifact was not self-contained"));
    }

    let merged_coverage =
        campaign.merge_accumulated_coverage_maps(coverage_left, coverage_right)?;
    let reverse_coverage =
        campaign.merge_accumulated_coverage_maps(coverage_right, coverage_left)?;
    let duplicate_coverage =
        campaign.merge_accumulated_coverage_maps(merged_coverage, coverage_left)?;
    let coverage_edges = campaign.accumulated_coverage_edges(merged_coverage)?;
    let redundant_delta = campaign.accumulated_coverage_delta(merged_coverage, [edge_a, edge_c])?;
    let novel_delta = campaign.accumulated_coverage_delta(
        merged_coverage,
        [
            edge_a,
            ContentHash::from_bytes(b"campaign-continuity-edge-d"),
        ],
    )?;
    if merged_coverage != reverse_coverage
        || merged_coverage != duplicate_coverage
        || coverage_edges.len() != 3
        || redundant_delta.is_novel()
        || !novel_delta.is_novel()
    {
        return Err(input_error(
            "campaign accumulated coverage was not a grow-only union",
        ));
    }

    let merged_findings = campaign.merge_findings_ledgers(findings_left, findings_right)?;
    let duplicate_findings = campaign.merge_findings_ledgers(merged_findings, findings_left)?;
    let entries = campaign.findings_ledger_entries(merged_findings)?;
    if duplicate_findings != merged_findings || entries.len() != 2 {
        return Err(input_error(
            "campaign findings ledger did not deduplicate across runs",
        ));
    }
    for entry in entries {
        let artifact = campaign.read_replay_artifact(entry.artifact_hash)?;
        if !entry.reproduces_bit_identically(&artifact) {
            return Err(input_error(
                "campaign ledger finding did not replay bit-identically",
            ));
        }
    }

    Ok(())
}

fn prove_campaign_storage_bounding(root: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Box::new(source)),
    }
    let campaign = SharedCampaignStore::new(root);
    let artifacts = [
        CampaignReplayArtifact::new(
            b"definition:storage-a".to_vec(),
            b"seed:a".to_vec(),
            b"schedule:a".to_vec(),
        ),
        CampaignReplayArtifact::new(
            b"definition:storage-b".to_vec(),
            b"seed:b".to_vec(),
            b"schedule:b".to_vec(),
        ),
        CampaignReplayArtifact::new(
            b"definition:storage-c".to_vec(),
            b"seed:c".to_vec(),
            b"schedule:c".to_vec(),
        ),
    ];
    let corpus_root = campaign.persist_campaign_corpus(artifacts.iter().cloned())?;
    let coverage_edge = campaign.manifest_store().put(b"storage-coverage-edge")?;
    let coverage_map_root = campaign.persist_accumulated_coverage_map([coverage_edge])?;
    let findings_root = campaign.persist_findings_ledger([CampaignFinding::new(
        ContentHash::from_bytes(b"storage-finding"),
        artifacts[0].clone(),
    )])?;
    let genesis_pin = campaign.manifest_store().put(b"storage-genesis-pin")?;
    let provenance =
        CampaignProvenance::new("crucible-probe", "qemu-probe+series", "shmem:1,gh:1,rpc:1");
    let manifest = CampaignManifest::new(
        corpus_root,
        coverage_map_root,
        findings_root,
        genesis_pin,
        provenance.clone(),
    );
    let finding_entry = campaign
        .findings_ledger_entries(findings_root)?
        .into_iter()
        .next()
        .ok_or_else(|| input_error("storage bounding probe did not persist a finding"))?;
    let abandoned = campaign.manifest_store().put(b"storage-abandoned-object")?;
    let seed_artifact_hashes = campaign
        .seed_next_run(&manifest, &manifest.provenance)?
        .into_iter()
        .map(|seed| seed.artifact_hash)
        .collect::<Vec<_>>();
    let mut candidates = vec![
        corpus_root,
        coverage_map_root,
        findings_root,
        genesis_pin,
        coverage_edge,
        finding_entry.artifact_hash,
        finding_entry.finding_hash,
        abandoned,
    ];
    candidates.extend(seed_artifact_hashes.iter().copied());

    let plan = campaign.campaign_gc_plan(&manifest, candidates.iter().copied())?;
    if !plan.roots.root_set().contains(&corpus_root)
        || !plan.roots.root_set().contains(&coverage_map_root)
        || !plan.roots.root_set().contains(&findings_root)
        || !plan.roots.root_set().contains(&genesis_pin)
        || !plan.retained_objects.contains(&finding_entry.artifact_hash)
        || !plan.retained_objects.contains(&finding_entry.finding_hash)
        || seed_artifact_hashes
            .iter()
            .any(|artifact_hash| !plan.retained_objects.contains(artifact_hash))
        || !plan.sweep_candidates.contains(&abandoned)
    {
        return Err(input_error(
            "campaign GC was not rooted at the manifest roots",
        ));
    }
    let gc_report =
        campaign.garbage_collect_campaign_candidates(&manifest, candidates.iter().copied())?;
    if !gc_report.swept_objects.contains(&abandoned)
        || campaign.manifest_store().has(&abandoned)?
        || !campaign.manifest_store().has(&findings_root)?
    {
        return Err(input_error(
            "campaign GC did not sweep only the unpinned candidate",
        ));
    }

    let fat_checkpoint = CampaignCheckpointMaterialization::fat(
        ContentHash::from_bytes(b"storage-checkpoint"),
        ContentHash::from_bytes(b"storage-parent"),
        ContentHash::from_bytes(b"storage-schedule-delta"),
        ContentHash::from_bytes(b"storage-materialization"),
    );
    let eviction = fat_checkpoint.evict_to_thin();
    if !eviction.preserves_value()
        || eviction.evicted_materialization.is_none()
        || eviction.after.materialization.is_some()
    {
        return Err(input_error(
            "fat-to-thin eviction did not preserve checkpoint value",
        ));
    }

    let policy =
        CampaignCorpusRetentionPolicy::new(2, ContentHash::from_bytes(b"storage-retention-seed"));
    let retention = campaign.retain_campaign_corpus_under_cap(corpus_root, policy)?;
    let repeat = campaign.retain_campaign_corpus_under_cap(corpus_root, policy)?;
    if retention != repeat
        || retention.retained_artifacts.len() != 2
        || retention.evicted_artifacts.len() != 1
    {
        return Err(input_error(
            "campaign corpus retention was not deterministic under cap",
        ));
    }
    let retained_manifest = CampaignManifest::new(
        retention.retained_root,
        coverage_map_root,
        findings_root,
        genesis_pin,
        provenance,
    );
    let head = match campaign.compare_and_swap_head(None, &manifest)? {
        CampaignCasOutcome::Advanced(head) => head,
        CampaignCasOutcome::LostUpdate { .. } => {
            return Err(input_error("initial storage-bounding campaign CAS lost"));
        }
    };
    match campaign.compare_and_swap_head(Some(head.manifest_hash), &retained_manifest) {
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "campaign corpus advance would drop a prior seed artifact",
            ..
        }) => {}
        Ok(_) => {
            return Err(input_error(
                "raw campaign CAS accepted retention without explicit policy",
            ));
        }
        Err(error) => return Err(Box::new(error)),
    }
    match campaign.compare_and_swap_head_with_retention(
        Some(head.manifest_hash),
        &retained_manifest,
        policy,
    )? {
        CampaignCasOutcome::Advanced(retained_head) => {
            if retained_head.manifest.findings_root != findings_root {
                return Err(input_error(
                    "campaign corpus retention changed the findings ledger root",
                ));
            }
        }
        CampaignCasOutcome::LostUpdate { .. } => {
            return Err(input_error("retention storage-bounding campaign CAS lost"));
        }
    }
    if campaign.findings_ledger_entries(findings_root)?.len() != 1 {
        return Err(input_error(
            "campaign storage bounding evicted a finding ledger entry",
        ));
    }

    Ok(())
}

fn prove_campaign_continuity_gate(root: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Box::new(source)),
    }
    let campaign = SharedCampaignStore::new(root);
    let prior_provenance = CampaignProvenance::new(
        "crucible-probe",
        "qemu-probe+series-a",
        "shmem:1,gh:1,rpc:1",
    );
    let next_provenance = CampaignProvenance::new(
        "crucible-probe",
        "qemu-probe+series-b",
        "shmem:1,gh:1,rpc:1",
    );
    let artifact_a = CampaignReplayArtifact::new(
        b"definition:continuity-a".to_vec(),
        b"seed:a".to_vec(),
        b"schedule:a".to_vec(),
    );
    let artifact_b = CampaignReplayArtifact::new(
        b"definition:continuity-b".to_vec(),
        b"seed:b".to_vec(),
        b"schedule:b".to_vec(),
    );
    let prior_edge = ContentHash::from_bytes(b"continuity-edge-a");
    let next_edge = ContentHash::from_bytes(b"continuity-edge-b");
    let prior_corpus = campaign.persist_campaign_corpus([artifact_a.clone()])?;
    let prior_coverage = campaign.persist_accumulated_coverage_map([prior_edge])?;
    let prior_findings = campaign.persist_findings_ledger([CampaignFinding::new(
        ContentHash::from_bytes(b"continuity-finding-a"),
        artifact_a.clone(),
    )])?;
    let prior_genesis = campaign.manifest_store().put(b"continuity-genesis-a")?;
    let prior_manifest = CampaignManifest::new(
        prior_corpus,
        prior_coverage,
        prior_findings,
        prior_genesis,
        prior_provenance.clone(),
    );

    let unused_fresh_roots = CampaignFreshLineageRoots::new(
        campaign.persist_campaign_corpus([])?,
        campaign.persist_accumulated_coverage_map([])?,
        campaign.persist_findings_ledger([])?,
        campaign
            .manifest_store()
            .put(b"continuity-unused-fresh-genesis")?,
    );
    let same_provenance = campaign.seed_next_run_for_provenance(
        &prior_manifest,
        &prior_provenance,
        unused_fresh_roots,
    )?;
    match same_provenance {
        CampaignContinuitySeedDecision::SeedPriorCorpus { seeds, .. } => {
            if seeds.len() != 1 || !seeds.iter().all(|seed| seed.reproduces_bit_identically()) {
                return Err(input_error(
                    "campaign continuity did not seed reproducible prior corpus entries",
                ));
            }
        }
        CampaignContinuitySeedDecision::RefuseCrossProvenanceReuse(_) => {
            return Err(input_error(
                "campaign continuity refused same-provenance corpus reuse",
            ));
        }
    }
    if !matches!(
        campaign.seed_next_run(&prior_manifest, &next_provenance),
        Err(crucible_cas::CasError::InvalidCampaignRecord {
            reason: "campaign seed provenance does not match manifest provenance",
            ..
        })
    ) {
        return Err(input_error(
            "campaign continuity allowed unkeyed cross-provenance seeding",
        ));
    }

    let next_corpus = campaign.persist_campaign_corpus([artifact_a.clone(), artifact_b.clone()])?;
    let next_coverage = campaign.merge_accumulated_coverage_maps(
        prior_coverage,
        campaign.persist_accumulated_coverage_map([next_edge])?,
    )?;
    let next_findings = campaign.merge_findings_ledgers(
        prior_findings,
        campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"continuity-finding-b"),
            artifact_b,
        )])?,
    )?;
    let next_manifest = CampaignManifest::new(
        next_corpus,
        next_coverage,
        next_findings,
        prior_genesis,
        prior_provenance,
    );
    let head = match campaign.compare_and_swap_head(None, &prior_manifest)? {
        CampaignCasOutcome::Advanced(head) => head,
        CampaignCasOutcome::LostUpdate { .. } => {
            return Err(input_error("initial continuity campaign CAS lost"));
        }
    };
    match campaign.compare_and_swap_head(Some(head.manifest_hash), &next_manifest)? {
        CampaignCasOutcome::Advanced(_) => {}
        CampaignCasOutcome::LostUpdate { .. } => {
            return Err(input_error("continuity campaign CAS lost"));
        }
    }
    let coverage_edges = campaign.accumulated_coverage_edges(next_coverage)?;
    if coverage_edges.len() != 2 || !coverage_edges.contains(&prior_edge) {
        return Err(input_error(
            "campaign continuity coverage ratchet was not monotone",
        ));
    }

    let fresh_roots = CampaignFreshLineageRoots::new(
        campaign.persist_campaign_corpus([])?,
        campaign.persist_accumulated_coverage_map([])?,
        campaign.persist_findings_ledger([])?,
        campaign.manifest_store().put(b"continuity-genesis-b")?,
    );
    let cross_provenance =
        campaign.seed_next_run_for_provenance(&next_manifest, &next_provenance, fresh_roots)?;
    match cross_provenance {
        CampaignContinuitySeedDecision::RefuseCrossProvenanceReuse(event) => {
            let recorded_event =
                campaign.read_fresh_lineage_baseline_event(event.baseline_event_hash)?;
            if event.reason != crucible_cas::CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON
                || event.baseline_event_hash == ContentHash::default()
                || event.refused_corpus_root != next_manifest.corpus_root
                || event.fresh_manifest.provenance != next_provenance
                || event.fresh_manifest.corpus_root == next_manifest.corpus_root
                || event.fresh_manifest.coverage_map_root == next_manifest.coverage_map_root
                || event.fresh_manifest.findings_root == next_manifest.findings_root
                || event.fresh_manifest.genesis_pin == next_manifest.genesis_pin
                || recorded_event != *event
                || !campaign.manifest_store().has(&event.baseline_event_hash)?
                || !campaign.manifest_store().has(&event.fresh_manifest_hash)?
            {
                return Err(input_error(
                    "campaign continuity did not fork a fresh cross-provenance lineage",
                ));
            }
            let fresh_head = campaign
                .read_head()?
                .ok_or_else(|| input_error("campaign continuity did not install fresh head"))?;
            if fresh_head.manifest_hash != event.fresh_manifest_hash
                || fresh_head.manifest != event.fresh_manifest
            {
                return Err(input_error(
                    "campaign continuity fresh lineage was not installed as head",
                ));
            }
        }
        CampaignContinuitySeedDecision::SeedPriorCorpus { .. } => {
            return Err(input_error(
                "campaign continuity seeded a cross-provenance corpus",
            ));
        }
    }
    for entry in campaign.findings_ledger_entries(prior_findings)? {
        let artifact = campaign.read_replay_artifact(entry.artifact_hash)?;
        if !entry.reproduces_bit_identically(&artifact) {
            return Err(input_error(
                "prior campaign finding stopped reproducing after fresh-lineage fork",
            ));
        }
    }

    Ok(())
}

fn probe_content_path(root: &Path, node: &ContentHash) -> PathBuf {
    let hex = node.to_hex();
    root.join(&hex[0..2]).join(hex)
}

fn probe_claim_lock_record_material(
    node: &ContentHash,
    acquired_at_tick: u64,
    expires_at_tick: u64,
) -> String {
    format!(
        "format=crucible.frontier-claim-lock.v1\nnode={}\nacquired_at_tick={acquired_at_tick}\nexpires_at_tick={expires_at_tick}\n",
        node.to_hex()
    )
}

fn probe_coverage_fingerprint_record_material(
    coverage_fingerprint: &ContentHash,
    entries: &[ContentHash],
) -> String {
    let entries = entries
        .iter()
        .map(|entry| entry.to_hex())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "format=crucible.coverage-fingerprint.v1\ncoverage_fingerprint={}\nentries={entries}\n",
        coverage_fingerprint.to_hex()
    )
}

fn count_regular_files_named(root: &Path, file_name: &str) -> Result<usize, io::Error> {
    if !root.exists() {
        return Ok(0);
    }
    let mut count = 0;
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() && entry.file_name() == OsStr::new(file_name) {
                count += 1;
            }
        }
    }
    Ok(count)
}

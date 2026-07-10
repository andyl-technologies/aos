#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn memory_store_deduplicates_identical_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryDagStore::new();

        let first = store.put(b"checkpoint")?;
        let second = store.put(b"checkpoint")?;

        assert_eq!(first, second);
        assert_eq!(store.object_count()?, 1);
        assert!(store.has(&first)?);
        assert_eq!(store.get(&first)?, b"checkpoint");

        Ok(())
    }

    #[test]
    fn local_store_uses_two_level_layout_and_validates_content()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = LocalDagStore::new(temp.path());
        let key = store.put(b"node")?;
        let path = store.object_path(&key);
        let hex = key.to_hex();

        assert_eq!(path, temp.path().join(&hex[0..2]).join(&hex));
        assert!(store.has(&key)?);
        assert_eq!(store.get(&key)?, b"node");

        fs::write(&path, b"corrupt")?;
        assert!(matches!(
            store.get(&key),
            Err(CasError::ContentMismatch { expected, .. }) if expected == key
        ));

        Ok(())
    }

    #[test]
    fn shared_store_identity_is_location_independent() -> Result<(), Box<dyn std::error::Error>> {
        let left_temp = tempfile::tempdir()?;
        let right_temp = tempfile::tempdir()?;
        let left = SharedDagStore::new(left_temp.path());
        let right = SharedDagStore::new(right_temp.path());

        let left_key = left.put(b"fleet-checkpoint")?;
        let right_key = right.put(b"fleet-checkpoint")?;

        assert_eq!(left_key, right_key);
        assert_eq!(left.get(&left_key)?, right.get(&right_key)?);
        assert_ne!(left.object_path(&left_key), right.object_path(&right_key));
        assert_eq!(
            left.object_path(&left_key).file_name(),
            right.object_path(&right_key).file_name()
        );

        Ok(())
    }

    #[test]
    fn shared_store_concurrent_put_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = Arc::new(SharedDagStore::new(temp.path()));
        let mut handles = Vec::new();

        for _ in 0..16 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || store.put(b"shared-frontier-node")));
        }

        let mut keys = BTreeSet::new();
        for handle in handles {
            keys.insert(
                handle
                    .join()
                    .map_err(|_| std::io::Error::other("shared store writer panicked"))??,
            );
        }

        assert_eq!(keys.len(), 1);
        let key = keys
            .iter()
            .next()
            .copied()
            .ok_or_else(|| std::io::Error::other("shared store did not publish a key"))?;
        assert!(store.has(&key)?);
        assert_eq!(store.get(&key)?, b"shared-frontier-node");

        Ok(())
    }

    #[test]
    fn shared_store_temp_creation_skips_existing_collision()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path());
        let key = ContentHash::from_bytes(b"shared-temp-collision");
        let path = store.object_path(&key);
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("shared store object path has no parent"))?;
        fs::create_dir_all(parent)?;

        let stale_temp = shared_store_temp_path(&path, &key, 0);
        fs::write(&stale_temp, b"stale writer temp")?;
        let mut sequences = [0_u64, 1].into_iter();

        let created =
            create_shared_store_temp_file_with(&path, &key, b"shared-temp-collision", || {
                sequences.next().unwrap_or(2)
            })?;

        assert_ne!(created, stale_temp);
        assert_eq!(fs::read(&stale_temp)?, b"stale writer temp");
        assert_eq!(fs::read(&created)?, b"shared-temp-collision");

        Ok(())
    }

    #[test]
    fn shared_frontier_claims_expired_leases_again() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let frontier = SharedFrontier::new(temp.path().join("frontier"));
        let node = store.put(b"frontier-node")?;
        frontier.admit(&node)?;

        let first = frontier
            .claim_next(&FrontierClaimRequest::new("host-a", 10, 5))?
            .ok_or_else(|| std::io::Error::other("first claim did not lease a node"))?;
        assert_eq!(first.node, node);
        assert_eq!(first.owner, "host-a");
        assert_eq!(first.expires_at_tick, 15);
        assert!(
            frontier
                .claim_next(&FrontierClaimRequest::new("host-b", 11, 5))?
                .is_none()
        );

        let reclaimed = frontier
            .claim_next(&FrontierClaimRequest::new("host-b", 15, 5))?
            .ok_or_else(|| std::io::Error::other("expired claim did not become claimable"))?;
        assert_eq!(reclaimed.node, node);
        assert_eq!(reclaimed.owner, "host-b");
        assert_ne!(reclaimed.lease_id, first.lease_id);
        assert_eq!(store.put(b"frontier-node")?, node);
        assert_eq!(store.get(&node)?, b"frontier-node");

        let claim_path = frontier.claim_path(&node);
        let claim_file = claim_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| std::io::Error::other("claim path has no UTF-8 file name"))?;
        assert_eq!(claim_file, node.to_hex());
        assert!(!claim_path.to_string_lossy().contains("host-a"));
        assert!(!claim_path.to_string_lossy().contains("host-b"));

        Ok(())
    }

    #[test]
    fn shared_frontier_claim_is_single_owner_under_contention()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let frontier = Arc::new(SharedFrontier::new(temp.path().join("frontier")));
        let node = store.put(b"contended-frontier-node")?;
        frontier.admit(&node)?;
        let workers = 16;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::new();

        for worker in 0..workers {
            let frontier = Arc::clone(&frontier);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                frontier.claim_next(&FrontierClaimRequest::new(format!("host-{worker}"), 100, 5))
            }));
        }

        let mut leases = Vec::new();
        for handle in handles {
            if let Some(lease) = handle
                .join()
                .map_err(|_| std::io::Error::other("frontier claimant panicked"))??
            {
                leases.push(lease);
            }
        }

        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].node, node);
        assert!(
            frontier
                .claim_next(&FrontierClaimRequest::new("late-host", 101, 5))?
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn shared_frontier_reclaims_expired_claim_lock() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let frontier = SharedFrontier::new(temp.path().join("frontier"));
        let node = store.put(b"stale-lock-frontier-node")?;
        frontier.admit(&node)?;
        let lock_path = frontier.claim_lock_path(&node);
        let parent = lock_path
            .parent()
            .ok_or_else(|| std::io::Error::other("claim lock path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(&lock_path, claim_lock_record_material(&node, 100, 105))?;

        assert!(
            frontier
                .claim_next(&FrontierClaimRequest::new("blocked-host", 104, 5))?
                .is_none()
        );
        let reclaimed = frontier
            .claim_next(&FrontierClaimRequest::new("reclaiming-host", 105, 5))?
            .ok_or_else(|| std::io::Error::other("expired claim lock was not reclaimed"))?;

        assert_eq!(reclaimed.node, node);
        assert_eq!(reclaimed.owner, "reclaiming-host");
        assert_eq!(reclaimed.expires_at_tick, 110);

        Ok(())
    }

    #[test]
    fn shared_dedup_index_proves_four_layers() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let index = SharedDedupIndex::new(temp.path().join("dedup"));
        let child = ContentHash::from_bytes(b"four-layer-child");

        assert_eq!(
            index.exists_gated_expansion(&store, &child)?,
            ExpansionDedupDecision::Expand
        );
        assert_eq!(store.put(b"four-layer-child")?, child);
        assert_eq!(
            index.exists_gated_expansion(&store, &child)?,
            ExpansionDedupDecision::SkipExisting
        );

        let edge_a = ContentHash::from_bytes(b"coverage-edge-a");
        let edge_b = ContentHash::from_bytes(b"coverage-edge-b");
        let edge_c = ContentHash::from_bytes(b"coverage-edge-c");
        let coverage_ab = ContentHash::from_bytes(b"coverage-a-b");
        let first_coverage = index.admit_coverage_map(coverage_ab, [edge_a, edge_b])?;
        assert!(first_coverage.admitted());
        assert_eq!(first_coverage.new_entries.len(), 2);
        let same_fingerprint = index.admit_coverage_map(coverage_ab, [edge_a, edge_b])?;
        assert!(same_fingerprint.redundant());
        assert_eq!(same_fingerprint.duplicate_entries.len(), 2);

        let interrupted_fingerprint = ContentHash::from_bytes(b"coverage-interrupted");
        let interrupted_a = ContentHash::from_bytes(b"coverage-interrupted-a");
        let interrupted_b = ContentHash::from_bytes(b"coverage-interrupted-b");
        let interrupted_path = index.coverage_fingerprint_path(&interrupted_fingerprint);
        let interrupted_parent = interrupted_path
            .parent()
            .ok_or_else(|| std::io::Error::other("coverage fingerprint path has no parent"))?;
        fs::create_dir_all(interrupted_parent)?;
        fs::write(
            &interrupted_path,
            coverage_fingerprint_record_material(
                &interrupted_fingerprint,
                &[interrupted_a, interrupted_b],
            ),
        )?;
        assert!(!index.coverage_path(&interrupted_a).exists());
        let repaired =
            index.admit_coverage_map(interrupted_fingerprint, [interrupted_a, interrupted_b])?;
        assert!(repaired.redundant());
        assert_eq!(repaired.duplicate_entries.len(), 2);
        assert!(index.coverage_path(&interrupted_a).exists());
        assert!(index.coverage_path(&interrupted_b).exists());

        let duplicate_coverage = index.admit_coverage_map(
            ContentHash::from_bytes(b"coverage-a-b-duplicate"),
            [edge_a, edge_b],
        )?;
        assert!(duplicate_coverage.redundant());
        assert_eq!(duplicate_coverage.duplicate_entries.len(), 2);
        let merged_coverage =
            index.admit_coverage_map(ContentHash::from_bytes(b"coverage-b-c"), [edge_b, edge_c])?;
        assert!(merged_coverage.admitted());
        assert_eq!(merged_coverage.new_entries, vec![edge_c]);
        assert_eq!(merged_coverage.duplicate_entries, vec![edge_b]);

        let reduction_fingerprint = ContentHash::from_bytes(b"symmetry-por-fingerprint");
        let representative = ContentHash::from_bytes(b"canonical-representative");
        let covered = ContentHash::from_bytes(b"covered-equivalent");
        let first_reduction =
            index.admit_reduction_fingerprint(reduction_fingerprint, representative)?;
        assert!(first_reduction.admitted());
        assert_eq!(first_reduction.representative, representative);
        let covered_reduction =
            index.admit_reduction_fingerprint(reduction_fingerprint, covered)?;
        assert!(covered_reduction.covered());
        assert_eq!(covered_reduction.representative, representative);
        assert_eq!(covered_reduction.covered, Some(covered));

        let frontier = SharedFrontier::new(temp.path().join("frontier"));
        let node_a = store.put(b"claim-anti-redundancy-a")?;
        let node_b = store.put(b"claim-anti-redundancy-b")?;
        frontier.admit(&node_a)?;
        frontier.admit(&node_b)?;
        let first_claim = frontier
            .claim_next(&FrontierClaimRequest::new("host-a", 1, 5))?
            .ok_or_else(|| std::io::Error::other("first host did not claim a frontier node"))?;
        let second_claim = frontier
            .claim_next(&FrontierClaimRequest::new("host-b", 2, 5))?
            .ok_or_else(|| std::io::Error::other("second host did not claim fallback node"))?;
        assert_ne!(first_claim.node, second_claim.node);
        assert!(!frontier.claimable_nodes(3)?.contains(&first_claim.node));

        Ok(())
    }

    #[test]
    fn campaign_seed_loads_self_contained_replay_artifacts()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = CampaignReplayArtifact::new(
            b"definition:partition-recovery".to_vec(),
            b"seed:0001".to_vec(),
            b"schedule:a,b,c".to_vec(),
        );
        let second = CampaignReplayArtifact::new(
            b"definition:crash-restart".to_vec(),
            b"seed:0002".to_vec(),
            b"schedule:x,y,z".to_vec(),
        );
        let corpus_root =
            campaign.persist_campaign_corpus([first.clone(), second.clone(), first.clone()])?;
        let manifest = CampaignManifest::new(
            corpus_root,
            campaign.persist_accumulated_coverage_map([])?,
            campaign.persist_findings_ledger([])?,
            ContentHash::from_bytes(b"genesis-pin"),
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1"),
        );

        let seeds = campaign.seed_next_run(&manifest, &manifest.provenance)?;

        assert_eq!(seeds.len(), 2);
        for seed in seeds {
            assert!(seed.reproduces_bit_identically());
            assert_eq!(
                campaign.read_replay_artifact(seed.artifact_hash)?,
                seed.artifact
            );
            assert!(
                seed.artifact
                    .replay_bytes()
                    .starts_with(b"format=crucible.campaign-replay-input.v1\n")
            );
        }

        Ok(())
    }

    #[test]
    fn campaign_coverage_ratchet_is_grow_only_union_crdt() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let edge_a = ContentHash::from_bytes(b"campaign-edge-a");
        let edge_b = ContentHash::from_bytes(b"campaign-edge-b");
        let edge_c = ContentHash::from_bytes(b"campaign-edge-c");
        let left = campaign.persist_accumulated_coverage_map([edge_a, edge_b])?;
        let right = campaign.persist_accumulated_coverage_map([edge_b, edge_c])?;

        let merged = campaign.merge_accumulated_coverage_maps(left, right)?;
        let reverse = campaign.merge_accumulated_coverage_maps(right, left)?;
        let duplicate = campaign.merge_accumulated_coverage_maps(merged, left)?;
        let delta = campaign.accumulated_coverage_delta(merged, [edge_a, edge_c])?;
        let novel = campaign.accumulated_coverage_delta(
            merged,
            [edge_a, ContentHash::from_bytes(b"campaign-edge-d")],
        )?;
        let mut expected_edges = vec![edge_a, edge_b, edge_c];
        expected_edges.sort();
        let mut expected_known = vec![edge_a, edge_c];
        expected_known.sort();

        assert_eq!(merged, reverse);
        assert_eq!(duplicate, merged);
        assert_eq!(campaign.accumulated_coverage_edges(merged)?, expected_edges);
        assert!(!delta.is_novel());
        assert_eq!(delta.known_edges, expected_known);
        assert!(novel.is_novel());
        assert_eq!(novel.new_edges.len(), 1);

        Ok(())
    }

    #[test]
    fn campaign_findings_ledger_accumulates_and_deduplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let artifact_a = CampaignReplayArtifact::new(
            b"definition:finding-a".to_vec(),
            b"seed:a".to_vec(),
            b"schedule:a".to_vec(),
        );
        let artifact_b = CampaignReplayArtifact::new(
            b"definition:finding-b".to_vec(),
            b"seed:b".to_vec(),
            b"schedule:b".to_vec(),
        );
        let finding_a =
            CampaignFinding::new(ContentHash::from_bytes(b"failure-a"), artifact_a.clone());
        let finding_a_rediscovered = CampaignFinding::new(
            ContentHash::from_bytes(b"failure-a-rediscovered"),
            artifact_a.clone(),
        );
        let finding_b =
            CampaignFinding::new(ContentHash::from_bytes(b"failure-b"), artifact_b.clone());
        let artifact_a_hash = campaign.persist_replay_artifact(&artifact_a)?;
        let left = campaign
            .persist_findings_ledger([finding_a.clone(), finding_a_rediscovered.clone()])?;
        let right = campaign.persist_findings_ledger([finding_a_rediscovered, finding_b])?;

        let merged = campaign.merge_findings_ledgers(left, right)?;
        let entries = campaign.findings_ledger_entries(merged)?;

        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.artifact_hash == artifact_a_hash)
                .count(),
            1
        );
        for entry in entries {
            let artifact = campaign.read_replay_artifact(entry.artifact_hash)?;
            assert!(entry.reproduces_bit_identically(&artifact));
        }

        Ok(())
    }

    #[test]
    fn campaign_gc_is_rooted_at_manifest_roots_and_sweeps_unpinned_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let corpus_artifact = CampaignReplayArtifact::new(
            b"definition:gc-corpus".to_vec(),
            b"seed:gc-corpus".to_vec(),
            b"schedule:gc-corpus".to_vec(),
        );
        let finding_artifact = CampaignReplayArtifact::new(
            b"definition:gc-finding".to_vec(),
            b"seed:gc-finding".to_vec(),
            b"schedule:gc-finding".to_vec(),
        );
        let corpus_artifact_hash = campaign.persist_replay_artifact(&corpus_artifact)?;
        let finding_artifact_hash = campaign.persist_replay_artifact(&finding_artifact)?;
        let coverage_edge = campaign.manifest_store().put(b"coverage-edge-object")?;
        let abandoned = campaign
            .manifest_store()
            .put(b"abandoned-unpinned-campaign-object")?;
        let genesis_pin = campaign.manifest_store().put(b"campaign-genesis-pin")?;
        let corpus_root = campaign.persist_campaign_corpus([corpus_artifact])?;
        let coverage_map_root = campaign.persist_accumulated_coverage_map([coverage_edge])?;
        let findings_root = campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"gc-finding-fingerprint"),
            finding_artifact,
        )])?;
        let finding_entry = campaign
            .findings_ledger_entries(findings_root)?
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::other("finding ledger did not persist an entry"))?;
        let manifest = CampaignManifest::new(
            corpus_root,
            coverage_map_root,
            findings_root,
            genesis_pin,
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1"),
        );

        let candidates = [
            corpus_root,
            coverage_map_root,
            findings_root,
            genesis_pin,
            corpus_artifact_hash,
            coverage_edge,
            finding_artifact_hash,
            finding_entry.finding_hash,
            abandoned,
        ];
        let plan = campaign.campaign_gc_plan(&manifest, candidates)?;

        assert_eq!(
            plan.roots.root_set(),
            BTreeSet::from([corpus_root, coverage_map_root, findings_root, genesis_pin])
        );
        assert!(plan.retained_objects.contains(&corpus_artifact_hash));
        assert!(plan.retained_objects.contains(&coverage_edge));
        assert!(plan.retained_objects.contains(&finding_artifact_hash));
        assert!(plan.retained_objects.contains(&finding_entry.finding_hash));
        assert_eq!(plan.sweep_candidates, BTreeSet::from([abandoned]));

        let report = campaign.garbage_collect_campaign_candidates(&manifest, candidates)?;
        assert_eq!(report.swept_objects, BTreeSet::from([abandoned]));
        assert!(!campaign.manifest_store().has(&abandoned)?);
        assert!(campaign.manifest_store().has(&corpus_root)?);
        assert!(campaign.manifest_store().has(&findings_root)?);
        assert_eq!(
            campaign
                .seed_next_run(&manifest, &manifest.provenance)?
                .len(),
            1
        );
        assert_eq!(campaign.findings_ledger_entries(findings_root)?.len(), 1);

        Ok(())
    }

    #[test]
    fn campaign_fat_to_thin_eviction_preserves_checkpoint_value() {
        let checkpoint = ContentHash::from_bytes(b"checkpoint-value");
        let parent = ContentHash::from_bytes(b"checkpoint-parent");
        let schedule_delta = ContentHash::from_bytes(b"checkpoint-schedule-delta");
        let materialization = ContentHash::from_bytes(b"cache-only-materialization");
        let fat = CampaignCheckpointMaterialization::fat(
            checkpoint,
            parent,
            schedule_delta,
            materialization,
        );

        let eviction = fat.evict_to_thin();

        assert!(eviction.preserves_value());
        assert_eq!(eviction.evicted_materialization, Some(materialization));
        assert_eq!(eviction.after.checkpoint, checkpoint);
        assert_eq!(eviction.after.parent, parent);
        assert_eq!(eviction.after.schedule_delta, schedule_delta);
        assert!(eviction.after.materialization.is_none());
    }

    #[test]
    fn campaign_corpus_retention_is_deterministic_seeded_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        let left_temp = tempfile::tempdir()?;
        let right_temp = tempfile::tempdir()?;
        let left_campaign = SharedCampaignStore::new(left_temp.path());
        let right_campaign = SharedCampaignStore::new(right_temp.path());
        let artifacts = [
            CampaignReplayArtifact::new(
                b"definition:retention-a".to_vec(),
                b"seed:a".to_vec(),
                b"schedule:a".to_vec(),
            ),
            CampaignReplayArtifact::new(
                b"definition:retention-b".to_vec(),
                b"seed:b".to_vec(),
                b"schedule:b".to_vec(),
            ),
            CampaignReplayArtifact::new(
                b"definition:retention-c".to_vec(),
                b"seed:c".to_vec(),
                b"schedule:c".to_vec(),
            ),
            CampaignReplayArtifact::new(
                b"definition:retention-d".to_vec(),
                b"seed:d".to_vec(),
                b"schedule:d".to_vec(),
            ),
        ];
        let left_corpus = left_campaign.persist_campaign_corpus(artifacts.iter().cloned())?;
        let right_corpus =
            right_campaign.persist_campaign_corpus(artifacts.iter().rev().cloned())?;
        let policy =
            CampaignCorpusRetentionPolicy::new(2, ContentHash::from_bytes(b"retention-seed"));
        let zero_cap_policy =
            CampaignCorpusRetentionPolicy::new(0, ContentHash::from_bytes(b"retention-seed"));

        let left_retention = left_campaign.retain_campaign_corpus_under_cap(left_corpus, policy)?;
        let left_retention_repeat =
            left_campaign.retain_campaign_corpus_under_cap(left_corpus, policy)?;
        let right_retention =
            right_campaign.retain_campaign_corpus_under_cap(right_corpus, policy)?;
        assert!(matches!(
            left_campaign.retain_campaign_corpus_under_cap(left_corpus, zero_cap_policy),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus retention cap must be greater than zero",
                ..
            })
        ));

        assert_eq!(left_corpus, right_corpus);
        assert_eq!(left_retention, left_retention_repeat);
        assert_eq!(left_retention.retained_root, right_retention.retained_root);
        assert_eq!(left_retention.retained_artifacts.len(), 2);
        assert_eq!(left_retention.evicted_artifacts.len(), 2);
        assert_eq!(
            left_campaign
                .seed_next_run_from_prior_corpus(left_retention.retained_root)?
                .len(),
            2
        );

        let coverage_root = left_campaign.persist_accumulated_coverage_map([])?;
        let finding_artifact = artifacts
            .first()
            .cloned()
            .ok_or_else(|| std::io::Error::other("missing retention artifact"))?;
        let findings_root = left_campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"retention-finding"),
            finding_artifact,
        )])?;
        let genesis_pin = left_campaign
            .manifest_store()
            .put(b"retention-genesis-pin")?;
        let provenance =
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1");
        let full_manifest = CampaignManifest::new(
            left_corpus,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance.clone(),
        );
        let retained_manifest = CampaignManifest::new(
            left_retention.retained_root,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance.clone(),
        );
        let first_head = match left_campaign.compare_and_swap_head(None, &full_manifest)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };

        assert!(matches!(
            left_campaign.compare_and_swap_head(Some(first_head.manifest_hash), &retained_manifest),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus advance would drop a prior seed artifact",
                ..
            })
        ));
        assert!(matches!(
            left_campaign.compare_and_swap_head_with_retention(
                Some(first_head.manifest_hash),
                &retained_manifest,
                CampaignCorpusRetentionPolicy::new(
                    1,
                    ContentHash::from_bytes(b"retention-seed-mismatch")
                ),
            ),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus retention policy does not match authorized retention policy",
                ..
            })
        ));

        let retained_head = match left_campaign.compare_and_swap_head_with_retention(
            Some(first_head.manifest_hash),
            &retained_manifest,
            policy,
        )? {
            CampaignCasOutcome::Advanced(head) => {
                assert_eq!(head.manifest.corpus_root, left_retention.retained_root);
                assert_eq!(head.manifest.findings_root, findings_root);
                head
            }
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("retention campaign CAS lost").into());
            }
        };
        assert!(matches!(
            left_campaign.compare_and_swap_head(Some(retained_head.manifest_hash), &full_manifest),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus retention roots require explicit retention policy",
                ..
            })
        ));
        assert_eq!(
            left_campaign.findings_ledger_entries(findings_root)?.len(),
            1
        );

        Ok(())
    }

    #[test]
    fn campaign_retention_merge_retry_does_not_expand_over_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let artifact_a = CampaignReplayArtifact::new(
            b"definition:merge-retention-a".to_vec(),
            b"seed:a".to_vec(),
            b"schedule:a".to_vec(),
        );
        let artifact_b = CampaignReplayArtifact::new(
            b"definition:merge-retention-b".to_vec(),
            b"seed:b".to_vec(),
            b"schedule:b".to_vec(),
        );
        let artifact_c = CampaignReplayArtifact::new(
            b"definition:merge-retention-c".to_vec(),
            b"seed:c".to_vec(),
            b"schedule:c".to_vec(),
        );
        let edge = ContentHash::from_bytes(b"merge-retention-edge");
        let coverage_root = campaign.persist_accumulated_coverage_map([edge])?;
        let findings_root = campaign.persist_findings_ledger([])?;
        let genesis_pin = campaign.manifest_store().put(b"merge-retention-genesis")?;
        let provenance =
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1");
        let corpus_root =
            campaign.persist_campaign_corpus([artifact_a.clone(), artifact_b.clone()])?;
        let retention = campaign.retain_campaign_corpus_under_cap(
            corpus_root,
            CampaignCorpusRetentionPolicy::new(1, ContentHash::from_bytes(b"merge-retention-seed")),
        )?;
        let full_manifest = CampaignManifest::new(
            corpus_root,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance.clone(),
        );
        let retained_manifest = CampaignManifest::new(
            retention.retained_root,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance.clone(),
        );
        let head = match campaign.compare_and_swap_head(None, &full_manifest)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };
        match campaign.compare_and_swap_head_with_retention(
            Some(head.manifest_hash),
            &retained_manifest,
            CampaignCorpusRetentionPolicy::new(1, ContentHash::from_bytes(b"merge-retention-seed")),
        )? {
            CampaignCasOutcome::Advanced(_) => {}
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("retention campaign CAS lost").into());
            }
        }
        let competing_manifest = CampaignManifest::new(
            campaign.persist_campaign_corpus([artifact_c])?,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance,
        );

        assert!(matches!(
            campaign.advance_head_with_merge(&competing_manifest, 1),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus retention roots require explicit retention policy",
                ..
            })
        ));
        assert_eq!(
            campaign
                .seed_next_run_from_prior_corpus(retention.retained_root)?
                .len(),
            1
        );

        Ok(())
    }

    #[test]
    fn campaign_head_merge_unions_typed_campaign_roots() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let artifact_a = CampaignReplayArtifact::new(
            b"definition:a".to_vec(),
            b"seed:a".to_vec(),
            b"s:a".to_vec(),
        );
        let artifact_b = CampaignReplayArtifact::new(
            b"definition:b".to_vec(),
            b"seed:b".to_vec(),
            b"s:b".to_vec(),
        );
        let edge_a = ContentHash::from_bytes(b"typed-edge-a");
        let edge_b = ContentHash::from_bytes(b"typed-edge-b");
        let finding_a = CampaignFinding::new(
            ContentHash::from_bytes(b"typed-finding-a"),
            artifact_a.clone(),
        );
        let finding_b = CampaignFinding::new(
            ContentHash::from_bytes(b"typed-finding-b"),
            artifact_b.clone(),
        );
        let provenance =
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1");
        let first = CampaignManifest::new(
            campaign.persist_campaign_corpus([artifact_a])?,
            campaign.persist_accumulated_coverage_map([edge_a])?,
            campaign.persist_findings_ledger([finding_a])?,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );
        let second = CampaignManifest::new(
            campaign.persist_campaign_corpus([artifact_b])?,
            campaign.persist_accumulated_coverage_map([edge_b])?,
            campaign.persist_findings_ledger([finding_b])?,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance,
        );

        match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(_) => {}
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        }
        let report = campaign.advance_head_with_merge(&second, 3)?;
        let mut expected_edges = vec![edge_a, edge_b];
        expected_edges.sort();

        assert_eq!(
            campaign
                .seed_next_run(&report.head.manifest, &report.head.manifest.provenance)?
                .len(),
            2
        );
        assert_eq!(
            campaign.accumulated_coverage_edges(report.head.manifest.coverage_map_root)?,
            expected_edges
        );
        assert_eq!(
            campaign
                .findings_ledger_entries(report.head.manifest.findings_root)?
                .len(),
            2
        );

        Ok(())
    }

    #[test]
    fn campaign_head_cas_rejects_typed_root_regression() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let artifact_a = CampaignReplayArtifact::new(
            b"definition:regression-a".to_vec(),
            b"seed:a".to_vec(),
            b"schedule:a".to_vec(),
        );
        let artifact_b = CampaignReplayArtifact::new(
            b"definition:regression-b".to_vec(),
            b"seed:b".to_vec(),
            b"schedule:b".to_vec(),
        );
        let edge_a = ContentHash::from_bytes(b"regression-edge-a");
        let edge_b = ContentHash::from_bytes(b"regression-edge-b");
        let finding_a = CampaignFinding::new(
            ContentHash::from_bytes(b"regression-finding-a"),
            artifact_a.clone(),
        );
        let finding_b = CampaignFinding::new(
            ContentHash::from_bytes(b"regression-finding-b"),
            artifact_b.clone(),
        );
        let provenance =
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1");
        let full_corpus = campaign.persist_campaign_corpus([artifact_a.clone(), artifact_b])?;
        let full_coverage = campaign.persist_accumulated_coverage_map([edge_a, edge_b])?;
        let full_findings =
            campaign.persist_findings_ledger([finding_a.clone(), finding_b.clone()])?;
        let first = CampaignManifest::new(
            full_corpus,
            full_coverage,
            full_findings,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );
        let corpus_regressed = CampaignManifest::new(
            campaign.persist_campaign_corpus([artifact_a.clone()])?,
            full_coverage,
            full_findings,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );
        let coverage_regressed = CampaignManifest::new(
            full_corpus,
            campaign.persist_accumulated_coverage_map([edge_a])?,
            full_findings,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );
        let findings_regressed = CampaignManifest::new(
            full_corpus,
            full_coverage,
            campaign.persist_findings_ledger([finding_a])?,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );

        let first_head = match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };

        assert!(matches!(
            campaign.compare_and_swap_head(Some(first_head.manifest_hash), &corpus_regressed),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus advance would drop a prior seed artifact",
                ..
            })
        ));
        assert!(matches!(
            campaign.compare_and_swap_head(Some(first_head.manifest_hash), &coverage_regressed),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign coverage-map advance would reduce accumulated coverage",
                ..
            })
        ));
        assert!(matches!(
            campaign.compare_and_swap_head(Some(first_head.manifest_hash), &findings_regressed),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign findings advance would drop a prior finding artifact",
                ..
            })
        ));
        assert_eq!(
            campaign
                .read_head()?
                .ok_or_else(|| std::io::Error::other("campaign head missing"))?
                .manifest_hash,
            first_head.manifest_hash
        );

        Ok(())
    }

    #[test]
    fn campaign_manifest_is_content_addressed_with_single_head()
    -> Result<(), Box<dyn std::error::Error>> {
        let left = tempfile::tempdir()?;
        let right = tempfile::tempdir()?;
        let left_store = SharedCampaignStore::new(left.path());
        let right_store = SharedCampaignStore::new(right.path());
        let manifest =
            campaign_manifest_fixture(&left_store, "corpus-a", "coverage-a", "findings-a")?;
        let right_manifest =
            campaign_manifest_fixture(&right_store, "corpus-a", "coverage-a", "findings-a")?;

        let left_hash = left_store.persist_manifest(&manifest)?;
        let right_hash = right_store.persist_manifest(&right_manifest)?;

        assert_eq!(left_hash, right_hash);
        assert_eq!(manifest, right_manifest);
        assert_eq!(left_store.head_path(), left.path().join("campaign-head"));
        assert_ne!(
            left_store.head_path(),
            left_store.manifest_store().object_path(&left_hash)
        );

        Ok(())
    }

    #[test]
    fn campaign_head_cas_loses_only_bookkeeping() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = campaign_manifest_fixture(&campaign, "corpus-a", "coverage-a", "findings-a")?;
        let second = campaign_manifest_fixture(&campaign, "corpus-b", "coverage-b", "findings-b")?;

        let first_head = match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };
        let lost = match campaign.compare_and_swap_head(None, &second)? {
            CampaignCasOutcome::LostUpdate {
                current,
                proposed_manifest_hash,
                ..
            } => {
                assert_eq!(current, Some(first_head.manifest_hash));
                assert!(campaign.manifest_store().has(&proposed_manifest_hash)?);
                proposed_manifest_hash
            }
            CampaignCasOutcome::Advanced(_) => {
                return Err(std::io::Error::other("stale campaign CAS advanced").into());
            }
        };
        assert_eq!(
            campaign
                .read_head()?
                .ok_or_else(|| std::io::Error::other("campaign head missing"))?
                .manifest_hash,
            first_head.manifest_hash
        );
        assert!(campaign.manifest_store().has(&lost)?);

        Ok(())
    }

    #[test]
    fn campaign_head_ignores_torn_final_log_entry() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = campaign_manifest_fixture(&campaign, "corpus-a", "coverage-a", "findings-a")?;
        let second = campaign_manifest_fixture(&campaign, "corpus-b", "coverage-b", "findings-b")?;

        let first_head = match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };
        let mut head_file = OpenOptions::new().append(true).open(campaign.head_path())?;
        head_file.write_all(b"entry generation=2 manifest=partial")?;
        drop(head_file);

        assert_eq!(
            campaign
                .read_head()?
                .ok_or_else(|| std::io::Error::other("campaign head missing after torn append"))?
                .manifest_hash,
            first_head.manifest_hash
        );
        match campaign.compare_and_swap_head(Some(first_head.manifest_hash), &second)? {
            CampaignCasOutcome::Advanced(head) => {
                assert_ne!(head.manifest_hash, first_head.manifest_hash);
                assert_eq!(head.manifest, second);
            }
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("campaign CAS lost after torn append").into());
            }
        }

        Ok(())
    }

    #[test]
    fn campaign_head_recovers_from_torn_initial_log_entry() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = campaign_manifest_fixture(&campaign, "corpus-a", "coverage-a", "findings-a")?;
        fs::write(campaign.head_path(), b"entry generation=1 manifest=partial")?;

        match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(head) => {
                assert_eq!(head.manifest, first);
            }
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(
                    std::io::Error::other("campaign CAS lost after torn initial log").into(),
                );
            }
        }
        assert!(campaign.read_head()?.is_some());

        Ok(())
    }

    #[test]
    fn campaign_head_cas_serializes_contending_writers() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let workers = 12;
        let barrier = Arc::new(Barrier::new(workers));
        let mut manifests = Vec::new();
        for worker in 0..workers {
            manifests.push(campaign_manifest_fixture(
                &campaign,
                &format!("corpus-{worker}"),
                &format!("coverage-{worker}"),
                &format!("findings-{worker}"),
            )?);
        }

        let mut handles = Vec::new();
        for manifest in manifests {
            let campaign = campaign.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                campaign.compare_and_swap_head(None, &manifest)
            }));
        }

        let mut advanced = 0;
        let mut lost = 0;
        for handle in handles {
            match handle
                .join()
                .map_err(|_| std::io::Error::other("campaign CAS worker panicked"))??
            {
                CampaignCasOutcome::Advanced(_) => advanced += 1,
                CampaignCasOutcome::LostUpdate {
                    proposed_manifest_hash,
                    ..
                } => {
                    lost += 1;
                    assert!(campaign.manifest_store().has(&proposed_manifest_hash)?);
                }
            }
        }

        assert_eq!(advanced, 1);
        assert_eq!(lost, workers - 1);
        assert!(campaign.read_head()?.is_some());

        Ok(())
    }

    #[test]
    fn campaign_head_read_merge_retry_advances_union_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = campaign_manifest_fixture(&campaign, "corpus-a", "coverage-a", "findings-a")?;
        let second = campaign_manifest_fixture(&campaign, "corpus-b", "coverage-b", "findings-b")?;
        let first_hash = campaign.persist_manifest(&first)?;

        match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(_) => {}
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        }
        let report = campaign.advance_head_with_merge(&second, 3)?;

        assert_eq!(report.attempts, 1);
        assert_ne!(report.head.manifest_hash, first_hash);
        let expected_corpus =
            campaign_root_merge_hash("corpus", first.corpus_root, second.corpus_root);
        let expected_coverage = campaign_root_merge_hash(
            "coverage-map",
            first.coverage_map_root,
            second.coverage_map_root,
        );
        let expected_findings =
            campaign_root_merge_hash("findings", first.findings_root, second.findings_root);
        assert_eq!(report.head.manifest.corpus_root, expected_corpus);
        assert_eq!(report.head.manifest.coverage_map_root, expected_coverage);
        assert_eq!(report.head.manifest.findings_root, expected_findings);
        assert!(campaign.manifest_store().has(&expected_corpus)?);
        assert!(campaign.manifest_store().has(&expected_coverage)?);
        assert!(campaign.manifest_store().has(&expected_findings)?);
        assert_eq!(report.head.manifest.genesis_pin, first.genesis_pin);
        assert_eq!(report.head.manifest.provenance, first.provenance);
        assert_eq!(
            campaign
                .read_head()?
                .ok_or_else(|| std::io::Error::other("campaign head missing"))?
                .manifest_hash,
            report.head.manifest_hash
        );

        Ok(())
    }

    fn campaign_manifest_fixture(
        campaign: &SharedCampaignStore,
        corpus: &str,
        coverage: &str,
        findings: &str,
    ) -> Result<CampaignManifest, CasError> {
        Ok(CampaignManifest::new(
            campaign_root_fixture(campaign, "corpus", corpus)?,
            campaign_root_fixture(campaign, "coverage-map", coverage)?,
            campaign_root_fixture(campaign, "findings", findings)?,
            ContentHash::from_bytes(b"genesis-pin"),
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1"),
        ))
    }

    fn campaign_root_fixture(
        campaign: &SharedCampaignStore,
        label: &str,
        value: &str,
    ) -> Result<ContentHash, CasError> {
        campaign.manifest_store().put(
            format!("format=crucible.campaign-root-fixture.v1\nlabel={label}\nvalue={value}\n")
                .as_bytes(),
        )
    }

    #[test]
    fn shared_frontier_affinity_reorders_without_filtering()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let frontier = SharedFrontier::new(temp.path().join("frontier"));
        for payload in [b"frontier-a", b"frontier-b", b"frontier-c"] {
            frontier.admit(&store.put(payload)?)?;
        }

        let without_affinity = frontier.ordered_claimable_nodes(1, &SoftHashAffinity::off())?;
        let preferred_node = without_affinity
            .last()
            .copied()
            .ok_or_else(|| std::io::Error::other("frontier should contain nodes"))?;
        let with_affinity =
            frontier.ordered_claimable_nodes(1, &SoftHashAffinity::prefer([preferred_node]))?;

        let mut without_set = without_affinity.clone();
        without_set.sort();
        let mut with_set = with_affinity.clone();
        with_set.sort();
        assert_eq!(with_set, without_set);
        assert_eq!(with_affinity.first().copied(), Some(preferred_node));

        let lease = frontier
            .claim_next(
                &FrontierClaimRequest::new("host-affine", 1, 10)
                    .with_affinity(SoftHashAffinity::prefer([preferred_node])),
            )?
            .ok_or_else(|| std::io::Error::other("affine claim did not lease a node"))?;
        assert_eq!(lease.node, preferred_node);
        let remaining = frontier.claimable_nodes(2)?;
        assert_eq!(remaining.len(), without_set.len() - 1);
        assert!(!remaining.contains(&preferred_node));

        Ok(())
    }

    #[test]
    fn invalidation_is_gated_by_dependency_hash_changes() {
        let kernel_a = ContentHash::from_bytes(b"kernel-a");
        let kernel_b = ContentHash::from_bytes(b"kernel-b");
        let rootfs = ContentHash::from_bytes(b"rootfs");

        let mut baseline = DependencySnapshot::new();
        baseline.insert("kernel", kernel_a);
        baseline.insert("rootfs", rootfs);
        let query = InvalidationQuery::new(baseline);

        let mut unchanged = DependencySnapshot::new();
        unchanged.insert("kernel", kernel_a);
        unchanged.insert("rootfs", rootfs);
        assert!(!query.is_invalid(&unchanged));

        let mut changed = DependencySnapshot::new();
        changed.insert("kernel", kernel_b);
        changed.insert("rootfs", rootfs);
        let decision = query.evaluate(&changed);
        assert!(decision.is_invalid());
        assert_eq!(
            decision.changed_inputs().get("kernel"),
            Some(&DependencyChange {
                before: Some(kernel_a),
                after: Some(kernel_b),
            })
        );
    }
}

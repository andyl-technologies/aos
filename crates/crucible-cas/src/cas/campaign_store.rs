//! Persistent campaign-store layout, locking, and manifest updates.

use super::*;

/// Persistent campaign store with a content-addressed manifest and CAS head.
///
/// Campaign manifests are immutable objects in the same [`SharedDagStore`] used
/// by the fleet. The only durable non-content-addressed path owned by this type is
/// [`Self::head_path`], a tiny mutable ref containing the current manifest hash.
/// Concurrent writers serialize through an advisory lock on that same file.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SharedCampaignStore {
    root: PathBuf,
    store: SharedDagStore,
}

impl SharedCampaignStore {
    /// Builds a persistent campaign store rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let store = SharedDagStore::new(root.join("objects"));
        Self { root, store }
    }

    /// Returns the campaign store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the content-addressed manifest object store.
    #[must_use]
    pub fn manifest_store(&self) -> &SharedDagStore {
        &self.store
    }

    /// Returns the single mutable campaign head path.
    #[must_use]
    pub fn head_path(&self) -> PathBuf {
        self.root.join("campaign-head")
    }

    /// Persists `manifest` as an immutable content-addressed object.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the manifest is invalid or cannot be stored.
    pub fn persist_manifest(&self, manifest: &CampaignManifest) -> Result<ContentHash, CasError> {
        validate_campaign_manifest(manifest)?;
        self.validate_manifest_roots(manifest)?;
        self.store
            .put(manifest_record_material(manifest).as_bytes())
    }

    /// Reads the current campaign head, if one exists.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the head or named manifest cannot be read or
    /// parsed.
    pub fn read_head(&self) -> Result<Option<CampaignHead>, CasError> {
        let _guard = self.acquire_head_lock(FlockOperation::LockShared)?;
        self.read_head_unlocked()
    }

    fn read_head_unlocked(&self) -> Result<Option<CampaignHead>, CasError> {
        let Some(manifest_hash) = self.read_head_hash()? else {
            return Ok(None);
        };
        let manifest = self.read_manifest_object(manifest_hash)?;
        Ok(Some(CampaignHead {
            manifest_hash,
            manifest,
        }))
    }

    /// Compares the current head to `expected` and swaps it to `manifest`.
    ///
    /// The proposed manifest is persisted before the compare step. If the compare
    /// fails, the proposed manifest remains content-addressed and recoverable, so
    /// the lost CAS loses only manifest-head bookkeeping.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the current or proposed manifest cannot be read,
    /// parsed, stored, or written to the head.
    pub fn compare_and_swap_head(
        &self,
        expected: Option<ContentHash>,
        manifest: &CampaignManifest,
    ) -> Result<CampaignCasOutcome, CasError> {
        self.compare_and_swap_head_with_storage_policy(expected, manifest, None)
    }

    /// Compares and swaps the campaign head through an explicit retention policy.
    ///
    /// This is the storage-bounding form of [`Self::compare_and_swap_head`].
    /// Ordinary head advancement remains grow-only for corpus roots; bounded
    /// corpus pruning is accepted only when the proposed retained root proves the
    /// supplied nonzero policy against the current head's corpus root.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the current or proposed manifest cannot be read,
    /// parsed, stored, or written to the head, or when the proposed retained
    /// corpus root does not match `policy`.
    pub fn compare_and_swap_head_with_retention(
        &self,
        expected: Option<ContentHash>,
        manifest: &CampaignManifest,
        policy: CampaignCorpusRetentionPolicy,
    ) -> Result<CampaignCasOutcome, CasError> {
        validate_campaign_corpus_retention_policy(&policy, self.head_path())?;
        self.compare_and_swap_head_with_storage_policy(expected, manifest, Some(policy))
    }

    fn compare_and_swap_head_with_storage_policy(
        &self,
        expected: Option<ContentHash>,
        manifest: &CampaignManifest,
        retention_policy: Option<CampaignCorpusRetentionPolicy>,
    ) -> Result<CampaignCasOutcome, CasError> {
        let proposed_manifest_hash = self.persist_manifest(manifest)?;
        let mut guard = self.acquire_head_lock(FlockOperation::LockExclusive)?;
        let current_pointer = self.read_head_pointer()?;
        let current = current_pointer.map(|pointer| pointer.manifest_hash);
        if current != expected {
            return Ok(CampaignCasOutcome::LostUpdate {
                expected,
                current,
                proposed_manifest_hash,
            });
        }
        if let Some(current_manifest_hash) = current {
            let current_manifest = self.read_manifest_object(current_manifest_hash)?;
            self.validate_monotone_manifest_advance(
                &current_manifest,
                manifest,
                retention_policy.as_ref(),
            )?;
        }
        self.write_head(&mut guard, current_pointer, proposed_manifest_hash)?;
        let head = self
            .read_head_unlocked()?
            .ok_or_else(|| CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "campaign head disappeared after CAS",
            })?;
        Ok(CampaignCasOutcome::Advanced(head))
    }

    /// Advances the campaign head with read-merge-retry semantics.
    ///
    /// On CAS conflict, this reads the winning head, merges the proposed roots
    /// into it, and retries. Provenance and genesis pins must match; changed
    /// provenance is handled by the campaign-continuity fresh-lineage fork path.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the head cannot be read or advanced, when
    /// compatible roots cannot be merged, or when `max_attempts` is exhausted.
    pub fn advance_head_with_merge(
        &self,
        proposed: &CampaignManifest,
        max_attempts: usize,
    ) -> Result<CampaignAdvanceReport, CasError> {
        if max_attempts == 0 {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "campaign head merge retry requires at least one attempt",
            });
        }
        let mut attempts = 0;
        loop {
            attempts += 1;
            let current = self.read_head()?;
            let expected = current.as_ref().map(|head| head.manifest_hash);
            let next = match current {
                Some(head) => self.merge_manifests(&head.manifest, proposed)?,
                None => proposed.clone(),
            };
            match self.compare_and_swap_head(expected, &next)? {
                CampaignCasOutcome::Advanced(head) => {
                    return Ok(CampaignAdvanceReport { attempts, head });
                }
                CampaignCasOutcome::LostUpdate { .. } if attempts < max_attempts => continue,
                CampaignCasOutcome::LostUpdate { .. } => {
                    return Err(CasError::InvalidCampaignRecord {
                        path: self.head_path(),
                        reason: "campaign head CAS retry budget exhausted",
                    });
                }
            }
        }
    }

    /// Persists a self-contained replay artifact as an immutable object.
    ///
    /// The stored artifact contains the definition, seed, and schedule bytes
    /// needed to reproduce the entry without resuming a producing run.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the artifact cannot be stored.
    pub fn persist_replay_artifact(
        &self,
        artifact: &CampaignReplayArtifact,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_replay_artifact_material(artifact).as_bytes())
    }

    /// Reads and validates a self-contained replay artifact.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the artifact is missing, corrupt, or has an
    /// invalid replay hash.
    pub fn read_replay_artifact(
        &self,
        artifact_hash: ContentHash,
    ) -> Result<CampaignReplayArtifact, CasError> {
        let material = self.read_campaign_object_text(artifact_hash)?;
        parse_replay_artifact_record(&self.store.object_path(&artifact_hash), &material)
    }

    /// Persists a retained campaign corpus root.
    ///
    /// Each supplied artifact is stored first, then the corpus root records the
    /// artifact hash and replay hash. Duplicate artifacts collapse to one corpus
    /// entry by content address.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when an artifact or corpus root cannot be stored.
    pub fn persist_campaign_corpus<I>(&self, artifacts: I) -> Result<ContentHash, CasError>
    where
        I: IntoIterator<Item = CampaignReplayArtifact>,
    {
        let mut entries = BTreeMap::new();
        for artifact in artifacts {
            let artifact_hash = self.persist_replay_artifact(&artifact)?;
            entries.insert(artifact_hash, artifact.replay_hash());
        }
        self.persist_campaign_corpus_entries(&entries)
    }

    /// Loads the corpus named by `manifest` as the seed plan for run N+1.
    ///
    /// The caller must provide the provenance for the run being seeded. This API
    /// refuses drift; use [`SharedCampaignStore::seed_next_run_for_provenance`]
    /// when a changed provenance should fork a fresh campaign lineage.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the corpus root or any replay artifact is
    /// missing, corrupt, not self-validating, or keyed to different provenance
    /// than `run_provenance`.
    pub fn seed_next_run(
        &self,
        manifest: &CampaignManifest,
        run_provenance: &CampaignProvenance,
    ) -> Result<Vec<CampaignCorpusSeed>, CasError> {
        validate_campaign_manifest(manifest)?;
        validate_campaign_provenance(run_provenance)?;
        if manifest.provenance != *run_provenance {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&manifest.corpus_root),
                reason: "campaign seed provenance does not match manifest provenance",
            });
        }
        self.seed_next_run_from_prior_corpus(manifest.corpus_root)
    }

    /// Decides whether `manifest` may seed a run with `run_provenance`.
    ///
    /// Matching provenance loads the prior corpus as self-contained seed
    /// artifacts. Mismatched provenance refuses reuse, persists a fresh lineage
    /// manifest from `fresh_lineage_roots`, and returns a baseline event for the
    /// new lineage.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when campaign roots are malformed, a same-provenance
    /// seed artifact cannot reproduce its recorded replay hash, or a
    /// cross-provenance fresh lineage would reuse prior campaign roots or entries.
    pub fn seed_next_run_for_provenance(
        &self,
        manifest: &CampaignManifest,
        run_provenance: &CampaignProvenance,
        fresh_lineage_roots: CampaignFreshLineageRoots,
    ) -> Result<CampaignContinuitySeedDecision, CasError> {
        validate_campaign_manifest(manifest)?;
        validate_campaign_provenance(run_provenance)?;
        if manifest.provenance == *run_provenance {
            return Ok(CampaignContinuitySeedDecision::SeedPriorCorpus {
                seeds: self.seed_next_run(manifest, run_provenance)?,
                lineage_id: campaign_lineage_id(manifest)?,
                provenance_key: campaign_provenance_key(run_provenance)?,
            });
        }

        self.fork_fresh_campaign_lineage(manifest, run_provenance.clone(), fresh_lineage_roots)
            .map(|event| {
                CampaignContinuitySeedDecision::RefuseCrossProvenanceReuse(Box::new(event))
            })
    }

    pub(super) fn seed_next_run_from_prior_corpus(
        &self,
        corpus_root: ContentHash,
    ) -> Result<Vec<CampaignCorpusSeed>, CasError> {
        self.corpus_seed_map(corpus_root)
            .map(|entries| entries.into_values().collect())
    }

    /// Persists a fresh campaign lineage after provenance drift.
    ///
    /// The fresh lineage uses new corpus, coverage, findings, and genesis roots
    /// and records `run_provenance`; the fresh manifest is installed as the
    /// campaign head when `prior` is the current head. The prior lineage remains
    /// untouched and reproducible through its original manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when provenance did not change, any fresh root is
    /// malformed or missing, the prior manifest is not the current head, or the
    /// fresh roots silently reuse prior campaign corpus, coverage, or findings
    /// entries.
    pub fn fork_fresh_campaign_lineage(
        &self,
        prior: &CampaignManifest,
        run_provenance: CampaignProvenance,
        fresh_roots: CampaignFreshLineageRoots,
    ) -> Result<CampaignFreshLineageBaselineEvent, CasError> {
        validate_campaign_manifest(prior)?;
        validate_campaign_provenance(&run_provenance)?;
        if prior.provenance == run_provenance {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires changed provenance",
            });
        }
        self.validate_fresh_lineage_roots(prior, &fresh_roots)?;
        self.require_fresh_lineage_current_head(prior)?;

        let fresh_manifest = CampaignManifest::new(
            fresh_roots.corpus_root,
            fresh_roots.coverage_map_root,
            fresh_roots.findings_root,
            fresh_roots.genesis_pin,
            run_provenance,
        );
        let fresh_manifest_hash = self.persist_manifest(&fresh_manifest)?;
        let mut event = CampaignFreshLineageBaselineEvent {
            baseline_event_hash: ContentHash::default(),
            schema_version: CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA.to_owned(),
            reason: CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON.to_owned(),
            refused_corpus_root: prior.corpus_root,
            previous_lineage_id: campaign_lineage_id(prior)?,
            fresh_lineage_id: campaign_lineage_id(&fresh_manifest)?,
            previous_provenance_key: campaign_provenance_key(&prior.provenance)?,
            run_provenance_key: campaign_provenance_key(&fresh_manifest.provenance)?,
            fresh_manifest_hash,
            fresh_manifest,
        };
        event.baseline_event_hash = self
            .store
            .put(campaign_fresh_lineage_baseline_event_material(&event).as_bytes())?;
        self.install_fresh_lineage_head(prior, event.fresh_manifest_hash)?;
        Ok(event)
    }

    /// Reads a persisted fresh-lineage baseline event.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when `event_hash` is missing, malformed, or does not
    /// describe a valid fresh-lineage baseline event.
    pub fn read_fresh_lineage_baseline_event(
        &self,
        event_hash: ContentHash,
    ) -> Result<CampaignFreshLineageBaselineEvent, CasError> {
        let material = self.read_campaign_object_text(event_hash)?;
        let event = parse_fresh_lineage_baseline_event(
            &self.store.object_path(&event_hash),
            event_hash,
            &material,
        )?;
        let fresh_manifest = self.read_manifest_object(event.fresh_manifest_hash)?;
        if fresh_manifest != event.fresh_manifest {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&event.fresh_manifest_hash),
                reason: "fresh-lineage baseline event manifest hash does not match manifest",
            });
        }
        Ok(event)
    }

    /// Persists an accumulated coverage map root.
    ///
    /// Coverage maps are grow-only sets. Duplicate edges collapse by content
    /// address before the root object is written.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the coverage root cannot be stored.
    pub fn persist_accumulated_coverage_map<I>(&self, edges: I) -> Result<ContentHash, CasError>
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let edges = edges.into_iter().collect::<BTreeSet<_>>();
        self.persist_coverage_edges(&edges)
    }

    /// Returns the sorted coverage edges named by an accumulated coverage root.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the coverage root is missing or corrupt.
    pub fn accumulated_coverage_edges(
        &self,
        coverage_map_root: ContentHash,
    ) -> Result<Vec<ContentHash>, CasError> {
        Ok(self
            .coverage_edge_set(coverage_map_root)?
            .into_iter()
            .collect())
    }

    /// Computes novelty against the accumulated coverage map.
    ///
    /// Candidate edges are novel exactly when they are absent from the accumulated
    /// map named by `coverage_map_root`.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the accumulated coverage root is missing or
    /// corrupt.
    pub fn accumulated_coverage_delta<I>(
        &self,
        coverage_map_root: ContentHash,
        candidate_edges: I,
    ) -> Result<CampaignCoverageDelta, CasError>
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let accumulated = self.coverage_edge_set(coverage_map_root)?;
        let mut new_edges = Vec::new();
        let mut known_edges = Vec::new();
        for edge in candidate_edges.into_iter().collect::<BTreeSet<_>>() {
            if accumulated.contains(&edge) {
                known_edges.push(edge);
            } else {
                new_edges.push(edge);
            }
        }
        Ok(CampaignCoverageDelta {
            coverage_map_root,
            new_edges,
            known_edges,
        })
    }

    /// Merges two accumulated coverage roots by grow-only set union.
    ///
    /// The operation is commutative, associative, and idempotent because the root
    /// material is the sorted set union of both inputs.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when either root is missing, corrupt, or cannot be
    /// stored.
    pub fn merge_accumulated_coverage_maps(
        &self,
        left: ContentHash,
        right: ContentHash,
    ) -> Result<ContentHash, CasError> {
        let mut edges = self.coverage_edge_set(left)?;
        edges.extend(self.coverage_edge_set(right)?);
        self.persist_coverage_edges(&edges)
    }

    /// Persists a grow-only findings ledger root.
    ///
    /// Finding artifacts are content-addressed before the ledger is written. If
    /// multiple runs rediscover the same finding artifact, the ledger retains
    /// one entry keyed by that artifact's content address.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when a finding artifact, finding entry, or ledger root
    /// cannot be stored.
    pub fn persist_findings_ledger<I>(&self, findings: I) -> Result<ContentHash, CasError>
    where
        I: IntoIterator<Item = CampaignFinding>,
    {
        let mut entries = BTreeMap::new();
        for finding in findings {
            let (artifact_hash, finding_hash) = self.persist_finding(&finding)?;
            insert_deduped_finding_entry(&mut entries, artifact_hash, finding_hash);
        }
        self.persist_findings_entries(&entries)
    }

    /// Returns the sorted persisted findings named by a ledger root.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the ledger or any finding artifact is missing,
    /// corrupt, or not self-validating.
    pub fn findings_ledger_entries(
        &self,
        findings_root: ContentHash,
    ) -> Result<Vec<PersistedCampaignFinding>, CasError> {
        self.findings_entry_map(findings_root)
            .map(|entries| entries.into_values().collect())
    }

    /// Merges two findings ledgers by grow-only set union.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when either ledger root is missing, corrupt, or cannot
    /// be stored.
    pub fn merge_findings_ledgers(
        &self,
        left: ContentHash,
        right: ContentHash,
    ) -> Result<ContentHash, CasError> {
        let mut entries = self.finding_entry_hashes(left)?;
        for (artifact_hash, finding_hash) in self.finding_entry_hashes(right)? {
            insert_deduped_finding_entry(&mut entries, artifact_hash, finding_hash);
        }
        self.persist_findings_entries(&entries)
    }

    /// Returns the campaign garbage-collection roots named by `manifest`.
    ///
    /// The roots are exactly the manifest's corpus, coverage-map, findings, and
    /// genesis pins. The manifest object itself is owned by the mutable head log;
    /// this root set describes the storage graph below that manifest.
    #[must_use]
    pub fn campaign_gc_roots(&self, manifest: &CampaignManifest) -> CampaignGcRoots {
        CampaignGcRoots {
            corpus_root: manifest.corpus_root,
            coverage_map_root: manifest.coverage_map_root,
            findings_root: manifest.findings_root,
            genesis_pin: manifest.genesis_pin,
        }
    }

    /// Plans campaign object garbage collection for a candidate object set.
    ///
    /// Reachability starts at the manifest's corpus, coverage-map, findings, and
    /// genesis roots. Retained corpus replay artifacts and all finding replay
    /// artifacts stay live; candidates outside that closure are returned as
    /// sweep candidates.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when any manifest root is missing, malformed, or
    /// refers to malformed campaign objects.
    pub fn campaign_gc_plan<I>(
        &self,
        manifest: &CampaignManifest,
        candidates: I,
    ) -> Result<CampaignGcPlan, CasError>
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let roots = self.campaign_gc_roots(manifest);
        let retained_objects = self.campaign_reachable_objects(&roots)?;
        let sweep_candidates = candidates
            .into_iter()
            .collect::<BTreeSet<_>>()
            .difference(&retained_objects)
            .copied()
            .collect();
        Ok(CampaignGcPlan {
            roots,
            retained_objects,
            sweep_candidates,
        })
    }

    /// Sweeps unpinned campaign object candidates outside the manifest root closure.
    ///
    /// The caller supplies the candidate set, typically from a store inventory.
    /// This method deletes only candidates that are not reachable from the
    /// manifest roots; retained roots, retained corpus artifacts, and findings
    /// ledger entries are never deleted by this pass.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the reachability plan cannot be computed or a
    /// sweep candidate cannot be removed from the filesystem-backed store.
    pub fn garbage_collect_campaign_candidates<I>(
        &self,
        manifest: &CampaignManifest,
        candidates: I,
    ) -> Result<CampaignGcReport, CasError>
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let plan = self.campaign_gc_plan(manifest, candidates)?;
        let mut swept_objects = BTreeSet::new();
        let mut missing_objects = BTreeSet::new();
        for candidate in &plan.sweep_candidates {
            let path = self.store.object_path(candidate);
            match fs::remove_file(&path) {
                Ok(()) => {
                    swept_objects.insert(*candidate);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    missing_objects.insert(*candidate);
                }
                Err(source) => {
                    return Err(CasError::Io {
                        operation: "remove",
                        path,
                        source,
                    });
                }
            }
        }
        Ok(CampaignGcReport {
            plan,
            swept_objects,
            missing_objects,
        })
    }

    /// Persists a deterministic retained corpus root under `policy`.
    ///
    /// The retained corpus is selected by a stable seeded ordering over the
    /// source corpus entries. The resulting root records the source, cap, seed,
    /// and retained entries so campaign-head advancement can distinguish
    /// authorized pruning from an unproven corpus regression.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the source corpus cannot be read or the retained
    /// root cannot be persisted.
    pub fn retain_campaign_corpus_under_cap(
        &self,
        corpus_root: ContentHash,
        policy: CampaignCorpusRetentionPolicy,
    ) -> Result<CampaignCorpusRetentionReport, CasError> {
        validate_campaign_corpus_retention_policy(&policy, self.store.object_path(&corpus_root))?;
        let source_entries = self.corpus_entry_hashes(corpus_root)?;
        let retained_entries = retain_campaign_corpus_entries(&source_entries, &policy);
        let retained_root =
            self.persist_campaign_corpus_retention(corpus_root, &policy, &retained_entries)?;
        let retained_artifacts = retained_entries.keys().copied().collect::<Vec<_>>();
        let evicted_artifacts = source_entries
            .keys()
            .filter(|artifact_hash| !retained_entries.contains_key(artifact_hash))
            .copied()
            .collect();
        Ok(CampaignCorpusRetentionReport {
            source_root: corpus_root,
            retained_root,
            cap: policy.cap,
            seed: policy.seed,
            retained_artifacts,
            evicted_artifacts,
        })
    }

    fn validate_manifest_roots(&self, manifest: &CampaignManifest) -> Result<(), CasError> {
        self.require_manifest_root("corpus_root", manifest.corpus_root)?;
        self.require_manifest_root("coverage_map_root", manifest.coverage_map_root)?;
        self.require_manifest_root("findings_root", manifest.findings_root)?;
        Ok(())
    }

    fn read_manifest_object(
        &self,
        manifest_hash: ContentHash,
    ) -> Result<CampaignManifest, CasError> {
        let material = String::from_utf8(self.store.get(&manifest_hash)?).map_err(|_| {
            CasError::InvalidCampaignRecord {
                path: self.store.object_path(&manifest_hash),
                reason: "campaign manifest object is not UTF-8",
            }
        })?;
        let manifest = parse_manifest_record(&self.store.object_path(&manifest_hash), &material)?;
        self.validate_manifest_roots(&manifest)?;
        Ok(manifest)
    }

    fn validate_monotone_manifest_advance(
        &self,
        current: &CampaignManifest,
        proposed: &CampaignManifest,
        retention_policy: Option<&CampaignCorpusRetentionPolicy>,
    ) -> Result<(), CasError> {
        validate_campaign_lineage(current, proposed)?;
        self.validate_monotone_root(
            "corpus",
            current.corpus_root,
            proposed.corpus_root,
            retention_policy,
        )?;
        self.validate_monotone_root(
            "coverage-map",
            current.coverage_map_root,
            proposed.coverage_map_root,
            None,
        )?;
        self.validate_monotone_root(
            "findings",
            current.findings_root,
            proposed.findings_root,
            None,
        )?;
        Ok(())
    }

    fn validate_monotone_root(
        &self,
        label: &'static str,
        current: ContentHash,
        proposed: ContentHash,
        retention_policy: Option<&CampaignCorpusRetentionPolicy>,
    ) -> Result<(), CasError> {
        if current == proposed {
            return Ok(());
        }
        if !self.supports_typed_campaign_root(label, current)? {
            return Ok(());
        }
        if !self.supports_typed_campaign_root(label, proposed)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: campaign_root_regression_reason(label),
            });
        }
        match label {
            "corpus" => self.validate_campaign_corpus_superset(current, proposed, retention_policy),
            "coverage-map" => self.validate_coverage_superset(current, proposed),
            "findings" => self.validate_findings_superset(current, proposed),
            _ => Ok(()),
        }
    }

    fn validate_campaign_corpus_superset(
        &self,
        current: ContentHash,
        proposed: ContentHash,
        retention_policy: Option<&CampaignCorpusRetentionPolicy>,
    ) -> Result<(), CasError> {
        if self.corpus_retention_record(current)?.is_some() {
            let Some(policy) = retention_policy else {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&proposed),
                    reason: "campaign corpus retention roots require explicit retention policy",
                });
            };
            return self.validate_campaign_corpus_retention_advance(current, proposed, policy);
        }
        let current_entries = self.corpus_entry_hashes(current)?;
        let proposed_entries = self.corpus_entry_hashes(proposed)?;
        let mut dropped_prior_seed = false;
        for (artifact_hash, replay_hash) in current_entries {
            if proposed_entries.get(&artifact_hash) != Some(&replay_hash) {
                dropped_prior_seed = true;
                break;
            }
        }
        if dropped_prior_seed {
            let Some(policy) = retention_policy else {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&proposed),
                    reason: "campaign corpus advance would drop a prior seed artifact",
                });
            };
            return self.validate_campaign_corpus_retention_advance(current, proposed, policy);
        }
        Ok(())
    }

    fn validate_campaign_corpus_retention_advance(
        &self,
        current: ContentHash,
        proposed: ContentHash,
        policy: &CampaignCorpusRetentionPolicy,
    ) -> Result<(), CasError> {
        validate_campaign_corpus_retention_policy(policy, self.store.object_path(&proposed))?;
        let Some(retention) = self.corpus_retention_record(proposed)? else {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign corpus advance would drop a prior seed artifact",
            });
        };
        if retention.policy != *policy {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign corpus retention policy does not match authorized retention policy",
            });
        }
        if retention.source_root != current {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign corpus retention source does not match current root",
            });
        }
        let current_entries = self.corpus_entry_hashes(current)?;
        let expected_entries = retain_campaign_corpus_entries(&current_entries, &retention.policy);
        if retention.entries != expected_entries {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign corpus retention root does not match deterministic seeded cap",
            });
        }
        Ok(())
    }

    fn validate_coverage_superset(
        &self,
        current: ContentHash,
        proposed: ContentHash,
    ) -> Result<(), CasError> {
        let current_edges = self.coverage_edge_set(current)?;
        let proposed_edges = self.coverage_edge_set(proposed)?;
        if !current_edges.is_subset(&proposed_edges) {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign coverage-map advance would reduce accumulated coverage",
            });
        }
        Ok(())
    }

    fn validate_findings_superset(
        &self,
        current: ContentHash,
        proposed: ContentHash,
    ) -> Result<(), CasError> {
        let current_entries = self.finding_entry_hashes(current)?;
        let proposed_entries = self.finding_entry_hashes(proposed)?;
        for artifact_hash in current_entries.keys() {
            if !proposed_entries.contains_key(artifact_hash) {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&proposed),
                    reason: "campaign findings advance would drop a prior finding artifact",
                });
            }
        }
        Ok(())
    }

    fn require_manifest_root(
        &self,
        field: &'static str,
        root: ContentHash,
    ) -> Result<(), CasError> {
        if self.store.has(&root)? {
            return Ok(());
        }
        Err(CasError::InvalidCampaignRecord {
            path: self.store.object_path(&root),
            reason: match field {
                "corpus_root" => "campaign corpus root object is missing",
                "coverage_map_root" => "campaign coverage-map root object is missing",
                "findings_root" => "campaign findings root object is missing",
                _ => "campaign manifest root object is missing",
            },
        })
    }

    fn validate_fresh_lineage_roots(
        &self,
        prior: &CampaignManifest,
        fresh_roots: &CampaignFreshLineageRoots,
    ) -> Result<(), CasError> {
        if prior.corpus_root == fresh_roots.corpus_root {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.corpus_root),
                reason: "fresh campaign lineage must use a new corpus root",
            });
        }
        if prior.coverage_map_root == fresh_roots.coverage_map_root {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.coverage_map_root),
                reason: "fresh campaign lineage must use a new coverage-map root",
            });
        }
        if prior.findings_root == fresh_roots.findings_root {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.findings_root),
                reason: "fresh campaign lineage must use a new findings root",
            });
        }
        if prior.genesis_pin == fresh_roots.genesis_pin {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.genesis_pin),
                reason: "fresh campaign lineage must use a new genesis pin",
            });
        }
        if !self.supports_typed_campaign_root("corpus", fresh_roots.corpus_root)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.corpus_root),
                reason: "fresh campaign lineage corpus root is not a typed corpus root",
            });
        }
        if !self.supports_typed_campaign_root("coverage-map", fresh_roots.coverage_map_root)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.coverage_map_root),
                reason: "fresh campaign lineage coverage-map root is not a typed coverage root",
            });
        }
        if !self.supports_typed_campaign_root("findings", fresh_roots.findings_root)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.findings_root),
                reason: "fresh campaign lineage findings root is not a typed findings root",
            });
        }
        if !self.store.has(&fresh_roots.genesis_pin)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.genesis_pin),
                reason: "fresh campaign lineage genesis pin is missing",
            });
        }

        let prior_corpus = self.corpus_entry_hashes(prior.corpus_root)?;
        let fresh_corpus = self.corpus_entry_hashes(fresh_roots.corpus_root)?;
        if fresh_corpus
            .keys()
            .any(|artifact_hash| prior_corpus.contains_key(artifact_hash))
        {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.corpus_root),
                reason: "fresh campaign lineage corpus must not reuse prior corpus entries",
            });
        }

        let prior_coverage = self.coverage_edge_set(prior.coverage_map_root)?;
        let fresh_coverage = self.coverage_edge_set(fresh_roots.coverage_map_root)?;
        if fresh_coverage
            .iter()
            .any(|edge| prior_coverage.contains(edge))
        {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.coverage_map_root),
                reason: "fresh campaign lineage coverage must not reuse prior coverage edges",
            });
        }

        let prior_findings = self.finding_entry_hashes(prior.findings_root)?;
        let fresh_findings = self.finding_entry_hashes(fresh_roots.findings_root)?;
        if fresh_findings
            .keys()
            .any(|artifact_hash| prior_findings.contains_key(artifact_hash))
        {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.findings_root),
                reason: "fresh campaign lineage findings must not reuse prior finding artifacts",
            });
        }

        Ok(())
    }

    fn install_fresh_lineage_head(
        &self,
        prior: &CampaignManifest,
        fresh_manifest_hash: ContentHash,
    ) -> Result<(), CasError> {
        let mut guard = self.acquire_head_lock(FlockOperation::LockExclusive)?;
        let current_pointer = self.read_head_pointer()?;
        let Some(pointer) = current_pointer else {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires prior manifest to be current head",
            });
        };
        let current_manifest = self.read_manifest_object(pointer.manifest_hash)?;
        if current_manifest != *prior {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires prior manifest to be current head",
            });
        }
        let current_pointer = Some(pointer);
        self.write_head(&mut guard, current_pointer, fresh_manifest_hash)
    }

    fn require_fresh_lineage_current_head(&self, prior: &CampaignManifest) -> Result<(), CasError> {
        let Some(pointer) = self.read_head_pointer()? else {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires prior manifest to be current head",
            });
        };
        let current_manifest = self.read_manifest_object(pointer.manifest_hash)?;
        if current_manifest != *prior {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires prior manifest to be current head",
            });
        }
        Ok(())
    }

    fn merge_manifests(
        &self,
        current: &CampaignManifest,
        proposed: &CampaignManifest,
    ) -> Result<CampaignManifest, CasError> {
        validate_campaign_lineage(current, proposed)?;
        Ok(CampaignManifest {
            corpus_root: self.merge_manifest_root(
                "corpus",
                current.corpus_root,
                proposed.corpus_root,
            )?,
            coverage_map_root: self.merge_manifest_root(
                "coverage-map",
                current.coverage_map_root,
                proposed.coverage_map_root,
            )?,
            findings_root: self.merge_manifest_root(
                "findings",
                current.findings_root,
                proposed.findings_root,
            )?,
            genesis_pin: current.genesis_pin,
            provenance: current.provenance.clone(),
        })
    }

    fn merge_manifest_root(
        &self,
        label: &'static str,
        left: ContentHash,
        right: ContentHash,
    ) -> Result<ContentHash, CasError> {
        self.require_manifest_root(campaign_root_field(label), left)?;
        self.require_manifest_root(campaign_root_field(label), right)?;
        if left == right {
            return Ok(left);
        }
        if let Some(merged) = self.try_merge_typed_manifest_root(label, left, right)? {
            return Ok(merged);
        }
        let (first, second) = ordered_manifest_roots(left, right);
        let merged = self
            .store
            .put(campaign_root_merge_record_material(label, first, second).as_bytes())?;
        debug_assert_eq!(merged, campaign_root_merge_hash(label, left, right));
        Ok(merged)
    }

    fn try_merge_typed_manifest_root(
        &self,
        label: &'static str,
        left: ContentHash,
        right: ContentHash,
    ) -> Result<Option<ContentHash>, CasError> {
        if !self.supports_typed_campaign_root(label, left)?
            || !self.supports_typed_campaign_root(label, right)?
        {
            return Ok(None);
        }
        let merged = match label {
            "corpus" => {
                if self.corpus_retention_record(left)?.is_some()
                    || self.corpus_retention_record(right)?.is_some()
                {
                    return Err(CasError::InvalidCampaignRecord {
                        path: self.store.object_path(&right),
                        reason: "campaign corpus retention roots require explicit retention policy",
                    });
                }
                let mut entries = self.corpus_entry_hashes(left)?;
                entries.extend(self.corpus_entry_hashes(right)?);
                self.persist_campaign_corpus_entries(&entries)?
            }
            "coverage-map" => self.merge_accumulated_coverage_maps(left, right)?,
            "findings" => self.merge_findings_ledgers(left, right)?,
            _ => return Ok(None),
        };
        Ok(Some(merged))
    }

    fn supports_typed_campaign_root(
        &self,
        label: &'static str,
        root: ContentHash,
    ) -> Result<bool, CasError> {
        let material = self.read_campaign_object_text(root)?;
        let format = record_format(&material);
        if matches!(format, Some(format) if is_typed_campaign_root_format(label, format)) {
            return Ok(true);
        }
        if format != Some("crucible.campaign-root-merge.v1") {
            return Ok(false);
        }
        let merge = parse_campaign_root_merge_record(&self.store.object_path(&root), &material)?;
        if merge.label != label {
            return Ok(false);
        }
        Ok(self.supports_typed_campaign_root(label, merge.left)?
            && self.supports_typed_campaign_root(label, merge.right)?)
    }

    fn campaign_reachable_objects(
        &self,
        roots: &CampaignGcRoots,
    ) -> Result<BTreeSet<ContentHash>, CasError> {
        let mut retained = BTreeSet::from([roots.genesis_pin]);
        self.collect_campaign_root_closure("corpus", roots.corpus_root, &mut retained)?;
        self.collect_campaign_root_closure("coverage-map", roots.coverage_map_root, &mut retained)?;
        self.collect_campaign_root_closure("findings", roots.findings_root, &mut retained)?;
        Ok(retained)
    }

    fn collect_campaign_root_closure(
        &self,
        label: &'static str,
        root: ContentHash,
        retained: &mut BTreeSet<ContentHash>,
    ) -> Result<(), CasError> {
        if !retained.insert(root) {
            return Ok(());
        }
        let material = self.read_campaign_object_text(root)?;
        let path = self.store.object_path(&root);
        match record_format(&material) {
            Some("crucible.campaign-root-merge.v1") => {
                let merge = parse_campaign_root_merge_record(&path, &material)?;
                if merge.label != label {
                    return Err(CasError::InvalidCampaignRecord {
                        path,
                        reason: "campaign root merge label does not match manifest field",
                    });
                }
                self.collect_campaign_root_closure(label, merge.left, retained)?;
                self.collect_campaign_root_closure(label, merge.right, retained)
            }
            Some("crucible.campaign-corpus.v1") | Some("crucible.campaign-corpus-retention.v1")
                if label == "corpus" =>
            {
                for artifact_hash in self.corpus_entry_hashes(root)?.keys() {
                    retained.insert(*artifact_hash);
                }
                Ok(())
            }
            Some("crucible.campaign-coverage-map.v1") if label == "coverage-map" => {
                retained.extend(self.coverage_edge_set(root)?);
                Ok(())
            }
            Some("crucible.campaign-findings-ledger.v1") if label == "findings" => {
                for (artifact_hash, finding_hash) in self.finding_entry_hashes(root)? {
                    retained.insert(artifact_hash);
                    retained.insert(finding_hash);
                }
                Ok(())
            }
            _ => Err(CasError::InvalidCampaignRecord {
                path,
                reason: "campaign manifest root format is unsupported for GC",
            }),
        }
    }

    fn persist_campaign_corpus_entries(
        &self,
        entries: &BTreeMap<ContentHash, ContentHash>,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_corpus_record_material(entries).as_bytes())
    }

    fn persist_campaign_corpus_retention(
        &self,
        source_root: ContentHash,
        policy: &CampaignCorpusRetentionPolicy,
        entries: &BTreeMap<ContentHash, ContentHash>,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_corpus_retention_record_material(source_root, policy, entries).as_bytes())
    }

    fn persist_coverage_edges(
        &self,
        edges: &BTreeSet<ContentHash>,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_coverage_map_record_material(edges).as_bytes())
    }

    fn persist_finding(
        &self,
        finding: &CampaignFinding,
    ) -> Result<(ContentHash, ContentHash), CasError> {
        let artifact_hash = self.persist_replay_artifact(&finding.artifact)?;
        let finding_hash = self
            .store
            .put(campaign_finding_record_material(finding, artifact_hash).as_bytes())?;
        Ok((artifact_hash, finding_hash))
    }

    fn persist_findings_entries(
        &self,
        entries: &BTreeMap<ContentHash, ContentHash>,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_findings_ledger_record_material(entries).as_bytes())
    }

    fn corpus_seed_map(
        &self,
        root: ContentHash,
    ) -> Result<BTreeMap<ContentHash, CampaignCorpusSeed>, CasError> {
        let entries = self.corpus_entry_hashes(root)?;
        let mut seeds = BTreeMap::new();
        for (artifact_hash, expected_replay_hash) in entries {
            let artifact = self.read_replay_artifact(artifact_hash)?;
            let replay_hash = artifact.replay_hash();
            if replay_hash != expected_replay_hash {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&artifact_hash),
                    reason: "campaign corpus replay hash does not match artifact",
                });
            }
            seeds.insert(
                artifact_hash,
                CampaignCorpusSeed {
                    artifact_hash,
                    replay_hash,
                    artifact,
                },
            );
        }
        Ok(seeds)
    }

    fn corpus_entry_hashes(
        &self,
        root: ContentHash,
    ) -> Result<BTreeMap<ContentHash, ContentHash>, CasError> {
        let material = self.read_campaign_object_text(root)?;
        let path = self.store.object_path(&root);
        match record_format(&material) {
            Some("crucible.campaign-corpus.v1") => parse_campaign_corpus_record(&path, &material),
            Some("crucible.campaign-corpus-retention.v1") => {
                parse_campaign_corpus_retention_record(&path, &material)
                    .map(|retention| retention.entries)
            }
            Some("crucible.campaign-root-merge.v1") => {
                let merge = parse_campaign_root_merge_record(&path, &material)?;
                if merge.label != "corpus" {
                    return Err(CasError::InvalidCampaignRecord {
                        path,
                        reason: "campaign root merge label is not corpus",
                    });
                }
                let mut entries = self.corpus_entry_hashes(merge.left)?;
                entries.extend(self.corpus_entry_hashes(merge.right)?);
                Ok(entries)
            }
            _ => Err(CasError::InvalidCampaignRecord {
                path,
                reason: "campaign corpus root format is unsupported",
            }),
        }
    }

    fn corpus_retention_record(
        &self,
        root: ContentHash,
    ) -> Result<Option<CampaignCorpusRetentionRecord>, CasError> {
        let material = self.read_campaign_object_text(root)?;
        if record_format(&material) != Some("crucible.campaign-corpus-retention.v1") {
            return Ok(None);
        }
        parse_campaign_corpus_retention_record(&self.store.object_path(&root), &material).map(Some)
    }

    fn coverage_edge_set(&self, root: ContentHash) -> Result<BTreeSet<ContentHash>, CasError> {
        let material = self.read_campaign_object_text(root)?;
        let path = self.store.object_path(&root);
        match record_format(&material) {
            Some("crucible.campaign-coverage-map.v1") => {
                parse_campaign_coverage_map_record(&path, &material)
            }
            Some("crucible.campaign-root-merge.v1") => {
                let merge = parse_campaign_root_merge_record(&path, &material)?;
                if merge.label != "coverage-map" {
                    return Err(CasError::InvalidCampaignRecord {
                        path,
                        reason: "campaign root merge label is not coverage-map",
                    });
                }
                let mut entries = self.coverage_edge_set(merge.left)?;
                entries.extend(self.coverage_edge_set(merge.right)?);
                Ok(entries)
            }
            _ => Err(CasError::InvalidCampaignRecord {
                path,
                reason: "campaign coverage-map root format is unsupported",
            }),
        }
    }

    fn findings_entry_map(
        &self,
        root: ContentHash,
    ) -> Result<BTreeMap<ContentHash, PersistedCampaignFinding>, CasError> {
        let entries = self.finding_entry_hashes(root)?;
        let mut findings = BTreeMap::new();
        for (artifact_hash, finding_hash) in entries {
            let material = self.read_campaign_object_text(finding_hash)?;
            let persisted = parse_campaign_finding_record(
                &self.store.object_path(&finding_hash),
                finding_hash,
                &material,
            )?;
            if persisted.artifact_hash != artifact_hash {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&finding_hash),
                    reason: "campaign findings ledger artifact does not match finding record",
                });
            }
            let artifact = self.read_replay_artifact(persisted.artifact_hash)?;
            if persisted.replay_hash != artifact.replay_hash() {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&finding_hash),
                    reason: "campaign finding replay hash does not match artifact",
                });
            }
            findings.insert(finding_hash, persisted);
        }
        Ok(findings)
    }

    fn finding_entry_hashes(
        &self,
        root: ContentHash,
    ) -> Result<BTreeMap<ContentHash, ContentHash>, CasError> {
        let material = self.read_campaign_object_text(root)?;
        let path = self.store.object_path(&root);
        match record_format(&material) {
            Some("crucible.campaign-findings-ledger.v1") => {
                parse_campaign_findings_ledger_record(&path, &material)
            }
            Some("crucible.campaign-root-merge.v1") => {
                let merge = parse_campaign_root_merge_record(&path, &material)?;
                if merge.label != "findings" {
                    return Err(CasError::InvalidCampaignRecord {
                        path,
                        reason: "campaign root merge label is not findings",
                    });
                }
                let mut entries = self.finding_entry_hashes(merge.left)?;
                for (artifact_hash, finding_hash) in self.finding_entry_hashes(merge.right)? {
                    insert_deduped_finding_entry(&mut entries, artifact_hash, finding_hash);
                }
                Ok(entries)
            }
            _ => Err(CasError::InvalidCampaignRecord {
                path,
                reason: "campaign findings root format is unsupported",
            }),
        }
    }

    fn read_campaign_object_text(&self, key: ContentHash) -> Result<String, CasError> {
        String::from_utf8(self.store.get(&key)?).map_err(|_| CasError::InvalidCampaignRecord {
            path: self.store.object_path(&key),
            reason: "campaign object is not UTF-8",
        })
    }

    fn acquire_head_lock(&self, operation: FlockOperation) -> Result<CampaignHeadLock, CasError> {
        let path = self.head_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| CasError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| CasError::Io {
                operation: "open",
                path: path.clone(),
                source,
            })?;
        flock(&file, operation).map_err(|source| CasError::Io {
            operation: "lock",
            path,
            source: source.into(),
        })?;
        Ok(CampaignHeadLock { file })
    }

    fn read_head_hash(&self) -> Result<Option<ContentHash>, CasError> {
        Ok(self
            .read_head_pointer()?
            .map(|pointer| pointer.manifest_hash))
    }

    fn read_head_pointer(&self) -> Result<Option<CampaignHeadPointer>, CasError> {
        let path = self.head_path();
        let material = match fs::read_to_string(&path) {
            Ok(material) => material,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CasError::Io {
                    operation: "read",
                    path,
                    source,
                });
            }
        };
        if material.trim().is_empty() {
            return Ok(None);
        }
        parse_campaign_head_record(&path, &material)
    }

    fn write_head(
        &self,
        lock: &mut CampaignHeadLock,
        current: Option<CampaignHeadPointer>,
        manifest_hash: ContentHash,
    ) -> Result<(), CasError> {
        let path = self.head_path();
        let next_generation = current
            .map(|pointer| pointer.generation)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| CasError::InvalidCampaignRecord {
                path: path.clone(),
                reason: "campaign head generation overflows u64",
            })?;
        let metadata = lock.file.metadata().map_err(|source| CasError::Io {
            operation: "stat",
            path: path.clone(),
            source,
        })?;
        lock.file
            .seek(SeekFrom::End(0))
            .map_err(|source| CasError::Io {
                operation: "seek",
                path: path.clone(),
                source,
            })?;
        if metadata.len() != 0 {
            lock.file
                .seek(SeekFrom::End(-1))
                .map_err(|source| CasError::Io {
                    operation: "seek",
                    path: path.clone(),
                    source,
                })?;
            let mut last_byte = [0_u8; 1];
            lock.file
                .read_exact(&mut last_byte)
                .map_err(|source| CasError::Io {
                    operation: "read",
                    path: path.clone(),
                    source,
                })?;
            lock.file
                .seek(SeekFrom::End(0))
                .map_err(|source| CasError::Io {
                    operation: "seek",
                    path: path.clone(),
                    source,
                })?;
            if last_byte != *b"\n" {
                lock.file.write_all(b"\n").map_err(|source| CasError::Io {
                    operation: "write",
                    path: path.clone(),
                    source,
                })?;
            }
        }
        lock.file
            .write_all(campaign_head_entry_material(next_generation, manifest_hash).as_bytes())
            .map_err(|source| CasError::Io {
                operation: "write",
                path: path.clone(),
                source,
            })?;
        lock.file.sync_data().map_err(|source| CasError::Io {
            operation: "sync",
            path,
            source,
        })
    }
}

#[derive(Debug)]
pub(super) struct CampaignHeadLock {
    file: fs::File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CampaignHeadPointer {
    pub(super) generation: u64,
    pub(super) manifest_hash: ContentHash,
}

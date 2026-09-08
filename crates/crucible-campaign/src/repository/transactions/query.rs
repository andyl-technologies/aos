//! Authenticated campaign head, state, and proof queries.

use super::*;

impl CampaignRepository {
    /// Resolves and authenticates the current campaign head and its lineage and
    /// policy references.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent name or an
    /// integrity/store error for an invalid reachable closure.
    pub fn head(&self, name: &str) -> Result<CampaignHead, CampaignRepositoryError> {
        let campaign_ref = campaign_ref(name)?;
        let content_id = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let loaded = self.read_snapshot(content_id)?;
        self.validate_complete_head(content_id)?;
        Ok(CampaignHead {
            name: name.to_owned(),
            snapshot_id: CampaignSnapshotId::from_content_id(content_id)?,
            snapshot: loaded.snapshot,
        })
    }

    /// Returns one bounded ordered page of authenticated named campaign heads.
    ///
    /// The mutable-ref backend holds its ordinary shared namespace fence for
    /// the scan, so every returned binding comes from one stable ref view. Head
    /// bodies remain immutable after that fence is released and are completely
    /// authenticated before this method returns.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid cursor or limit, excessive ref scan,
    /// malformed campaign ref, invalid snapshot target, or incomplete head.
    pub fn list_heads(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<CampaignHeadPage, CampaignRepositoryError> {
        let namespace = RefName::new("campaigns")?;
        let after_ref = after.map(campaign_ref).transpose()?;
        let page = self.refs.scan_refs(&namespace, after_ref.as_ref(), limit)?;
        let mut heads = Vec::with_capacity(page.entries().len());
        for entry in page.entries() {
            let name = entry
                .name()
                .as_str()
                .strip_prefix("campaigns/")
                .ok_or_else(|| integrity("campaign-ref-scan-namespace-mismatch"))?
                .to_owned();
            if campaign_ref(&name)?.as_str() != entry.name().as_str() {
                return Err(integrity("campaign-ref-scan-name-is-not-canonical"));
            }
            let snapshot_id = CampaignSnapshotId::from_content_id(entry.target())?;
            let loaded = self.read_snapshot(entry.target())?;
            self.validate_complete_head(entry.target())?;
            heads.push(CampaignHead {
                name,
                snapshot_id,
                snapshot: loaded.snapshot,
            });
        }
        let next_after = page
            .next_after()
            .map(|cursor| {
                cursor
                    .as_str()
                    .strip_prefix("campaigns/")
                    .ok_or_else(|| integrity("campaign-ref-scan-cursor-namespace-mismatch"))
                    .map(str::to_owned)
            })
            .transpose()?;
        Ok(CampaignHeadPage {
            heads,
            next_after,
            visited_refs: page.visited(),
        })
    }

    /// Loads one exact snapshot from the authenticated history of `name`.
    ///
    /// The lookup validates the named current head before walking immutable
    /// parent links. A snapshot from another campaign is rejected even when its
    /// object is present in the same store.
    ///
    /// # Errors
    ///
    /// Returns an error when the campaign is absent, its head is invalid, the
    /// snapshot is not in that history, the ancestry bound is exceeded, or an
    /// immutable object cannot be read.
    pub fn snapshot_in_campaign(
        &self,
        name: &str,
        snapshot: CampaignSnapshotId,
    ) -> Result<CampaignSnapshot, CampaignRepositoryError> {
        let head = self.head(name)?;
        self.load_named_ancestor_snapshot(head.snapshot_id().content_id(), snapshot)
            .map(|loaded| loaded.snapshot)
    }

    pub(crate) fn scan_graph_page(
        &self,
        root: ContentId,
        after: Option<CampaignHash>,
        limit: usize,
    ) -> Result<(MerkleMapPage, MerkleMapPageProof), CampaignRepositoryError> {
        self.merkle
            .scan_with_proof(root, after, limit)
            .map_err(|error| match error {
                CampaignStoreError::InvalidMerkle {
                    reason: "page-cursor-not-in-root",
                } => CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-query-cursor-is-not-in-graph",
                },
                error => error.into(),
            })
    }

    pub(crate) fn scan_findings_page(
        &self,
        root: ContentId,
        after: Option<CampaignHash>,
        limit: usize,
    ) -> Result<(MerkleMapPage, MerkleMapPageProof), CampaignRepositoryError> {
        self.merkle
            .scan_with_proof(root, after, limit)
            .map_err(|error| match error {
                CampaignStoreError::InvalidMerkle {
                    reason: "page-cursor-not-in-root",
                } => CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-finding-query-cursor-is-not-in-index",
                },
                error => error.into(),
            })
    }

    pub(crate) fn finding_with_proof(
        &self,
        root: ContentId,
        finding: FindingId,
    ) -> Result<(Finding, MerkleMapLookupProof), CampaignRepositoryError> {
        let value = self.read_finding(finding.content_id())?;
        let key = finding_signature_key(value.signature().cluster_key());
        let (indexed, proof) = self.merkle.get_with_proof(root, key)?;
        if indexed != Some(finding.content_id()) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-finding-is-not-in-snapshot",
            });
        }
        Ok((value, proof))
    }

    pub(crate) fn attempt_with_proof(
        &self,
        root: ContentId,
        attempt: AttemptId,
    ) -> Result<(Attempt, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, attempt_index_key(attempt))?;
        if indexed != Some(attempt.content_id()) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-attempt-is-not-in-snapshot",
            });
        }
        Ok((self.load_attempt(attempt)?, proof))
    }

    pub(crate) fn attempt_execution_basis_with_proof(
        &self,
        root: ContentId,
        attempt: AttemptId,
    ) -> Result<(AttemptAdmission, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, attempt_execution_basis_key(attempt))?;
        let admission = AttemptAdmissionId::from_content_id(indexed.ok_or(
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-attempt-execution-basis-is-not-in-snapshot",
            },
        )?)?;
        Ok((self.load_attempt_admission(admission)?, proof))
    }

    pub(crate) fn proposal_with_proof(
        &self,
        root: ContentId,
        proposal: ProposalId,
    ) -> Result<(Proposal, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, proposal_index_key(proposal))?;
        if indexed != Some(proposal.content_id()) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-proposal-is-not-in-snapshot",
            });
        }
        Ok((self.load_proposal(proposal)?, proof))
    }

    pub(crate) fn planner_step_for_invocation_with_proof(
        &self,
        root: ContentId,
        invocation: PlannerInvocationId,
    ) -> Result<(PlannerStep, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, planner_invocation_result_key(invocation))?;
        let step = PlannerStepId::from_content_id(indexed.ok_or(
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-planner-invocation-is-not-in-snapshot",
            },
        )?)?;
        let step = self.read_planner_step(step.content_id())?;
        if step.invocation() != invocation {
            return Err(integrity(
                "campaign-planner-invocation-result-step-mismatch",
            ));
        }
        Ok((step, proof))
    }

    pub(crate) fn planner_step_with_proof(
        &self,
        root: ContentId,
        step: PlannerStepId,
    ) -> Result<(PlannerStep, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self.merkle.get_with_proof(root, planner_step_key(step))?;
        if indexed != Some(step.content_id()) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-planner-step-is-not-in-snapshot",
            });
        }
        Ok((self.read_planner_step(step.content_id())?, proof))
    }

    pub(crate) fn attempt_observation_with_proof(
        &self,
        root: ContentId,
        attempt: AttemptId,
    ) -> Result<(Option<Observation>, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, attempt_observation_key(attempt))?;
        let observation = indexed
            .map(ObservationId::from_content_id)
            .transpose()?
            .map(|id| self.load_observation(id))
            .transpose()?;
        Ok((observation, proof))
    }

    pub(crate) fn graph_object_with_proof(
        &self,
        root: ContentId,
        key: CampaignHash,
    ) -> Result<(ObjectEnvelope, MerkleMapLookupProof), CampaignRepositoryError> {
        let (object, proof) = self.merkle.get_with_proof(root, key)?;
        let object = object.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-graph-object-key-is-not-present",
        })?;
        Ok((self.read_envelope(object)?, proof))
    }

    pub(crate) fn scan_choice_page(
        &self,
        graph_root: ContentId,
        after: Option<ChoiceOpportunityId>,
        limit: usize,
    ) -> Result<(MerkleMapPage, MerkleMapLookupProof, MerkleMapPageProof), CampaignRepositoryError>
    {
        let (choice_index, index_proof) = self
            .merkle
            .get_with_proof(graph_root, choice_index_anchor_key())?;
        let choice_index = choice_index.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-snapshot-has-no-choice-index",
        })?;
        let (page, page_proof) = self
            .merkle
            .scan_with_proof(choice_index, after.map(choice_index_order_key), limit)
            .map_err(|error| match error {
                CampaignStoreError::InvalidMerkle {
                    reason: "page-cursor-not-in-root",
                } => CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-choice-query-cursor-is-not-in-index",
                },
                error => error.into(),
            })?;
        Ok((page, index_proof, page_proof))
    }

    pub(crate) fn scan_frontier_page(
        &self,
        exploration_root: ContentId,
        after: Option<BranchRequestId>,
        limit: usize,
    ) -> Result<(MerkleMapPage, MerkleMapLookupProof, MerkleMapPageProof), CampaignRepositoryError>
    {
        let (frontier_index, index_proof) = self
            .merkle
            .get_with_proof(exploration_root, frontier_index_anchor_key())?;
        let frontier_index = frontier_index.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-snapshot-has-no-frontier-index",
        })?;
        let (page, page_proof) = self
            .merkle
            .scan_with_proof(frontier_index, after.map(frontier_index_order_key), limit)
            .map_err(|error| match error {
                CampaignStoreError::InvalidMerkle {
                    reason: "page-cursor-not-in-root",
                } => CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-frontier-query-cursor-is-not-in-index",
                },
                error => error.into(),
            })?;
        Ok((page, index_proof, page_proof))
    }

    pub(crate) fn lookup_frontier_projection(
        &self,
        exploration_root: ContentId,
        request: BranchRequestId,
    ) -> Result<(ContentId, MerkleMapLookupProof, MerkleMapLookupProof), CampaignRepositoryError>
    {
        let (frontier_index, index_proof) = self
            .merkle
            .get_with_proof(exploration_root, frontier_index_anchor_key())?;
        let frontier_index = frontier_index.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-snapshot-has-no-frontier-index",
        })?;
        let (projection, object_proof) = self
            .merkle
            .get_with_proof(frontier_index, frontier_index_order_key(request))?;
        let projection = projection.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-branch-request-is-not-in-frontier-index",
        })?;
        Ok((projection, index_proof, object_proof))
    }

    /// Projects durable lifecycle intent from authenticated snapshot ancestry.
    ///
    /// # Errors
    ///
    /// Returns an integrity error for a cycle, excessive ancestry, malformed
    /// transition, or invalid historical state transition.
    pub fn state(&self, name: &str) -> Result<CampaignState, CampaignRepositoryError> {
        self.head_with_state(name).map(|(_, state)| state)
    }

    /// Resolves one authenticated head and its lifecycle state from the same snapshot.
    ///
    /// Unlike independent [`Self::head`] and [`Self::state`] calls, this method
    /// cannot mix fields across a concurrent ref advance: lifecycle projection
    /// is anchored to the exact content ID returned in the head.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent name or an
    /// integrity/store error for an invalid reachable closure or lifecycle.
    pub fn head_with_state(
        &self,
        name: &str,
    ) -> Result<(CampaignHead, CampaignState), CampaignRepositoryError> {
        self.head_with_lifecycle(name)
            .map(|(head, lifecycle)| (head, lifecycle.state()))
    }

    /// Resolves one authenticated head and its active campaign policy.
    ///
    /// The policy is loaded through the exact identity carried by the returned
    /// head, so a concurrent ref advance cannot pair a head with a policy from
    /// a different snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent name or an
    /// integrity/store error for an invalid reachable head or policy record.
    pub fn head_with_policy(
        &self,
        name: &str,
    ) -> Result<(CampaignHead, CampaignPolicy), CampaignRepositoryError> {
        let head = self.head(name)?;
        let policy = self.read_policy(head.snapshot().active_policy().content_id())?;

        Ok((head, policy))
    }

    /// Resolves one authenticated head and its complete lifecycle intent.
    ///
    /// The state and active-attempt policy are projected from the same exact
    /// content ID returned in the head, so a concurrent ref advance cannot mix
    /// lifecycle fields from different snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent name or an
    /// integrity/store error for an invalid reachable closure or lifecycle.
    pub fn head_with_lifecycle(
        &self,
        name: &str,
    ) -> Result<(CampaignHead, CampaignLifecycle), CampaignRepositoryError> {
        let head = self.head(name)?;
        let lifecycle = self.lifecycle_at_snapshot(head.snapshot_id())?;
        Ok((head, lifecycle))
    }

    /// Resolves the authenticated genesis snapshot of one named campaign.
    ///
    /// The validated-head checkpoint retains the exact genesis content ID, so
    /// repeated creation replay remains constant-time after ordinary head
    /// validation instead of walking the complete campaign history again.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent campaign or
    /// an integrity/store error for an invalid current head or genesis record.
    pub fn genesis(&self, name: &str) -> Result<CampaignHead, CampaignRepositoryError> {
        let current = self.head(name)?;
        let checkpoint = self.load_validation_checkpoint(current.content_id())?;
        let loaded = self.read_snapshot(checkpoint.genesis)?;
        Ok(CampaignHead {
            name: name.to_owned(),
            snapshot_id: CampaignSnapshotId::from_content_id(checkpoint.genesis)?,
            snapshot: loaded.snapshot,
        })
    }

    /// Projects lifecycle state from one exact authenticated snapshot.
    ///
    /// # Errors
    ///
    /// Returns an integrity/store error when the snapshot or its reachable
    /// ancestry is absent, malformed, excessive, or semantically invalid.
    pub fn state_at_snapshot(
        &self,
        snapshot: CampaignSnapshotId,
    ) -> Result<CampaignState, CampaignRepositoryError> {
        self.lifecycle_at_snapshot(snapshot)
            .map(CampaignLifecycle::state)
    }

    /// Projects complete lifecycle intent from one exact authenticated snapshot.
    ///
    /// # Errors
    ///
    /// Returns an integrity/store error when the snapshot or its reachable
    /// ancestry is absent, malformed, excessive, or semantically invalid.
    pub fn lifecycle_at_snapshot(
        &self,
        snapshot: CampaignSnapshotId,
    ) -> Result<CampaignLifecycle, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        self.current_lifecycle(snapshot.content_id())
            .map(|state| CampaignLifecycle {
                state: state.visible,
                active_attempt_policy: state.active_attempt_policy,
            })
    }
}

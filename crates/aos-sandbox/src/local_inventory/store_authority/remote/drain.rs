//! Protected fleet draining and reassignment-ready admission orchestration.
//!
//! This selected child retains the original protected-store enclosure. It
//! does not expose a backend, signer, or independent authority constructor.

use super::*;

impl ProtectedMultiNodeAuthorityOwnerV1 {
    /// Durably admits the fixed owner's first cordon-only drain generation.
    ///
    /// The dormant fixed owner derives every field from its protected identity,
    /// current clock floor, and current root. It accepts no caller directive.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when a drain projection
    /// already exists or protected replay and persistence cannot prove the edge.
    pub fn admit_fixed_cordon_once(
        &mut self,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let accepted_at_unix_seconds = self.observe_current_time()?;
        if self
            .current_domain_projection(MultiNodeJournalDomainV1::Drain)?
            .is_some()
        {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        let operation = protected_outbound_operation(
            self.clock.config_digest,
            self.store.backend.protected_root_digest,
            self.store.backend.authenticated_context,
            accepted_at_unix_seconds,
            b"fixed-cordon",
        )?;
        let directive = DrainDirectiveV1::new(
            operation,
            self.store.backend.authenticated_context.node(),
            1,
            NodeDrainModeV1::CordonOnly,
            accepted_at_unix_seconds,
            None,
            Vec::new(),
        )?;
        let state = DrainJournalStateV1::new(directive.clone(), None)?;
        let payload = crate::local_inventory::journal::CanonicalJournalPayloadV1::new(
            MultiNodeReducerStateV1::Drain(state),
        )?;
        let directive_digest = drain_directive_digest(&directive);
        let record = MultiNodeJournalRecordV1::new(
            MultiNodeJournalDomainV1::Drain,
            operation,
            1,
            self.store
                .backend
                .domain_genesis_digest(MultiNodeJournalDomainV1::Drain),
            directive_digest,
            payload,
            JournalEffectStateV1::IntentCommitted,
            directive_digest,
        )?;
        self.store
            .commit_record_once(record, accepted_at_unix_seconds)
            .map_err(Into::into)
    }

    /// Durably admits a fixed-root evacuation of the current assignment.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless protected replay has
    /// one nonempty current assignment and the next drain generation can require
    /// snapshot, stop, containment, and replacement readiness.
    pub fn admit_fixed_evacuation_once(
        &mut self,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.admit_fixed_assignment_drain(NodeDrainModeV1::Evacuate, b"fixed-evacuate")
    }

    /// Durably admits fixed-root decommissioning of the current assignment.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless protected replay has
    /// one nonempty current assignment and every selected row uses the required
    /// snapshot-stop-and-replace workflow.
    pub fn admit_fixed_decommission_once(
        &mut self,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.admit_fixed_assignment_drain(NodeDrainModeV1::Decommission, b"fixed-decommission")
    }

    pub(in crate::local_inventory::store_authority) fn admit_fixed_assignment_drain(
        &mut self,
        mode: NodeDrainModeV1,
        purpose: &[u8],
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let accepted_at_unix_seconds = self.observe_current_time()?;
        let assignment =
            match self.current_domain_projection(MultiNodeJournalDomainV1::Assignment)? {
                Some(MultiNodeReducerStateV1::Assignment(state)) => state,
                _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
            };
        let current_drain = match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
            Some(MultiNodeReducerStateV1::Drain(state)) => Some(state),
            None => None,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current_drain.as_ref().is_some_and(|state| {
            let phase = state.observation().map(DurableDrainObservationV1::phase);
            match (state.directive().mode(), mode) {
                (NodeDrainModeV1::CordonOnly, _) => !matches!(
                    phase,
                    Some(crate::local_inventory::draining::DrainPhaseV1::Cordoned)
                        | Some(crate::local_inventory::draining::DrainPhaseV1::Complete)
                ),
                (NodeDrainModeV1::Evacuate, NodeDrainModeV1::Decommission) => {
                    phase != Some(crate::local_inventory::draining::DrainPhaseV1::Complete)
                }
                _ => true,
            }
        }) {
            return Err(InvalidDrainModel::InvalidPhaseTransition.into());
        }
        let generation = match current_drain.as_ref() {
            Some(state) => state
                .directive()
                .generation()
                .checked_add(1)
                .ok_or(InvalidDrainModel::InvalidPhaseTransition)?,
            None => 1,
        };
        let deadline_unix_seconds = accepted_at_unix_seconds
            .checked_add(3_600)
            .ok_or(InvalidDrainModel::InvalidDeadline)?;
        let operation = protected_outbound_operation(
            self.clock.config_digest,
            self.store.backend.protected_root_digest,
            self.store.backend.authenticated_context,
            accepted_at_unix_seconds,
            purpose,
        )?;
        let assignments = vec![DrainAssignmentPlanV1::from_intent(
            assignment.intent(),
            DrainAssignmentStrategyV1::SnapshotStopAndReplace,
        )];
        let directive = DrainDirectiveV1::new(
            operation,
            self.store.backend.authenticated_context.node(),
            generation,
            mode,
            accepted_at_unix_seconds,
            Some(deadline_unix_seconds),
            assignments,
        )?;
        let state = DrainJournalStateV1::new(directive.clone(), None)?;
        let payload = crate::local_inventory::journal::CanonicalJournalPayloadV1::new(
            MultiNodeReducerStateV1::Drain(state),
        )?;
        let directive_digest = drain_directive_digest(&directive);
        let (sequence, predecessor_digest) = self
            .store
            .backend
            .next_domain_boundary(MultiNodeJournalDomainV1::Drain)?;
        let record = MultiNodeJournalRecordV1::new(
            MultiNodeJournalDomainV1::Drain,
            operation,
            sequence,
            predecessor_digest,
            directive_digest,
            payload,
            JournalEffectStateV1::IntentCommitted,
            directive_digest,
        )?;
        self.store
            .commit_record_once(record, accepted_at_unix_seconds)
            .map_err(Into::into)
    }

    /// Builds a drain reconciliation request from the protected current directive.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless a current durable
    /// drain exists and the authenticated session belongs to the same owner.
    pub fn prepare_current_drain_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let state = match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
            Some(MultiNodeReducerStateV1::Drain(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::ReconcileDrain(Box::new(state.directive().clone())),
            b"reconcile-drain",
        )
        .map_err(Into::into)
    }

    /// Durably commits a current carrier-authenticated cordon observation.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the response matches
    /// the exact current fixed cordon and advances its sequence and phase.
    pub fn commit_current_drain_observation(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
            Some(MultiNodeReducerStateV1::Drain(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let NodeResponseBodyV1::Drain(observation) = response.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        if !observation.matches(current.directive())
            || !observation
                .context()
                .is_current_at(verified_at_unix_seconds)
            || observation.context() != self.store.backend.authenticated_context
            || !observation.assignments().is_empty()
            || !current.directive().assignments().is_empty()
            || current.observation().is_some_and(|retained| {
                observation.sequence() <= retained.sequence()
                    || !retained.phase().can_transition_to(observation.phase())
                    || observation.observed_at_unix_seconds() < retained.observed_at_unix_seconds()
            })
        {
            return Err(InvalidDrainModel::InvalidPhaseTransition.into());
        }
        let context = observation.context();
        let evidence = DurableEvidenceBindingV1::new(
            context.node(),
            context.lineage(),
            context.audience_digest(),
            context.disclosure_domain_digest(),
            context.carrier_binding_digest(),
            context.canonical_frame_digest(),
            context.canonical_frame_bytes(),
            context.coordinator_epoch(),
            context.verified_at_unix_seconds(),
            context.valid_until_unix_seconds(),
            context.replay_fence(),
        )?;
        let durable = DurableDrainObservationV1::new(
            observation.sequence(),
            observation.phase(),
            Vec::new(),
            observation.observed_at_unix_seconds(),
            evidence,
        )?;
        let state = DrainJournalStateV1::new(current.directive().clone(), Some(durable))?;
        self.commit_domain_projection(
            MultiNodeReducerStateV1::Drain(state),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Resolves only an exact ambiguous drain transition by protected readback.
    #[must_use]
    pub fn resolve_drain_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::Drain {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    /// Commits a snapshot-complete, contained, reassignment-ready drain edge.
    ///
    /// The carrier supplies only the node's raw progress. This fixed owner
    /// joins it to opaque snapshot and assignment-authority values that can be
    /// issued only by protected paths, then derives the complete evidence row.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless an evacuation or
    /// decommission directive has one exact snapshot-stop target and the joined
    /// observation proves containment and replacement readiness.
    pub fn commit_current_reassignment_ready_drain(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        snapshot_completion: SnapshotTransferCompletionV1,
        snapshot_authority: VerifiedAssignmentAuthorityV1,
        containment_authority: VerifiedAssignmentAuthorityV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let NodeResponseBodyV1::Drain(reported) = response.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        self.commit_reassignment_ready_drain_observation(
            response,
            reported,
            snapshot_completion,
            snapshot_authority,
            containment_authority,
            verified_at_unix_seconds,
        )
    }

    /// Commits a reassignment-ready drain observation carried by a watch event.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the indexed event is
    /// an authenticated drain report and the same opaque snapshot and authority
    /// joins required by [`Self::commit_current_reassignment_ready_drain`] hold.
    pub fn commit_current_watch_reassignment_ready_drain(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        event_index: usize,
        snapshot_completion: SnapshotTransferCompletionV1,
        snapshot_authority: VerifiedAssignmentAuthorityV1,
        containment_authority: VerifiedAssignmentAuthorityV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let NodeResponseBodyV1::WatchBatch {
            events,
            cursor_gap: None,
        } = response.body()
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        let Some(NodeWatchEventBodyV1::Drain(reported)) =
            events.get(event_index).map(NodeWatchEventV1::body)
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        self.commit_reassignment_ready_drain_observation(
            response,
            reported,
            snapshot_completion,
            snapshot_authority,
            containment_authority,
            verified_at_unix_seconds,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::local_inventory::store_authority) fn commit_reassignment_ready_drain_observation(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        reported: &DrainObservationV1,
        snapshot_completion: SnapshotTransferCompletionV1,
        snapshot_authority: VerifiedAssignmentAuthorityV1,
        containment_authority: VerifiedAssignmentAuthorityV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
            Some(MultiNodeReducerStateV1::Drain(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current.directive().mode() == NodeDrainModeV1::CordonOnly
            || current.directive().assignments().len() != 1
            || current.directive().assignments()[0].strategy()
                != DrainAssignmentStrategyV1::SnapshotStopAndReplace
        {
            return Err(InvalidDrainModel::IncompatibleStrategy.into());
        }
        let transfer_identity = snapshot_completion.identity();
        let context = self.store.backend.authenticated_context;
        if transfer_identity.source_node() != context.node()
            || transfer_identity.destination_node() == context.node()
            || transfer_identity.storage_domain_digest() != self.store.backend.storage_domain_digest
            || transfer_identity.audience_digest() != context.audience_digest()
            || transfer_identity.disclosure_domain_digest() != context.disclosure_domain_digest()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let observation = DrainObservationV1::from_protected_owner(
            current.directive(),
            reported,
            Some(snapshot_completion),
            snapshot_authority,
            containment_authority,
            verified_at_unix_seconds,
        )?;
        if observation.reassignment_ready().len() != 1
            || !matches!(
                observation.phase(),
                crate::local_inventory::draining::DrainPhaseV1::ReadyForReassignment
                    | crate::local_inventory::draining::DrainPhaseV1::Complete
            )
        {
            return Err(InvalidDrainModel::ProgressMismatch.into());
        }
        let durable = durable_drain_observation(&observation)?;
        let state = DrainJournalStateV1::new(current.directive().clone(), Some(durable))?;
        self.commit_domain_projection(
            MultiNodeReducerStateV1::Drain(state),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }
}

pub(in crate::local_inventory::store_authority) fn durable_drain_observation(
    observation: &DrainObservationV1,
) -> Result<DurableDrainObservationV1, InvalidMultiNodeJournal> {
    let context = observation.context();
    let evidence = DurableEvidenceBindingV1::new(
        context.node(),
        context.lineage(),
        context.audience_digest(),
        context.disclosure_domain_digest(),
        context.carrier_binding_digest(),
        context.canonical_frame_digest(),
        context.canonical_frame_bytes(),
        context.coordinator_epoch(),
        context.verified_at_unix_seconds(),
        context.valid_until_unix_seconds(),
        context.replay_fence(),
    )?;
    let assignments = observation
        .assignments()
        .iter()
        .map(|assignment| {
            crate::local_inventory::reducer_state::DurableDrainAssignmentV1::new(
                assignment.sandbox(),
                assignment.incarnation(),
                assignment.epoch(),
                assignment.desired_generation(),
                assignment.assignment_digest(),
                assignment.progress(),
                assignment
                    .snapshot_evidence()
                    .map(|snapshot| snapshot.transfer_manifest_digest()),
                assignment
                    .containment_evidence()
                    .map(|containment| containment.evidence_digest()),
                assignment
                    .release_evidence()
                    .map(|release| release.released_inventory_digest()),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    DurableDrainObservationV1::new(
        observation.sequence(),
        observation.phase(),
        assignments,
        observation.observed_at_unix_seconds(),
        evidence,
    )
}

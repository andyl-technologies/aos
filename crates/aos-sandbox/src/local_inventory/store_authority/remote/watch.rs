//! Protected remote watch bootstrap, cursor, resync, and batch writes.
//!
//! This selected child retains the original protected-store enclosure. It
//! does not expose a backend, signer, or independent authority constructor.

use super::*;

impl ProtectedMultiNodeAuthorityOwnerV1 {
    /// Builds the complete-inventory request that establishes a watch cursor.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the authenticated session
    /// belongs to this owner and admits its fixed rolling-version window.
    pub fn prepare_watch_bootstrap_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        let binding = self.protected_watch_binding(session)?;
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::RelistAssignments { binding },
            b"watch-bootstrap",
        )
    }

    /// Durably installs an authenticated complete-inventory watch bootstrap.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the inventory is
    /// current, exactly bound to this owner, and is either the initial binding
    /// or a monotonic cursor-gap resynchronization of the retained watch.
    pub fn commit_watch_bootstrap(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedWatchBootstrapCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let inventory = response.validated_inventory()?;
        let bootstrap =
            NodeWatchBootstrapV1::from_validated_inventory(&inventory, verified_at_unix_seconds)?;
        let binding = bootstrap.cursor().binding();
        if let Some(MultiNodeReducerStateV1::Watch(current)) =
            self.current_domain_projection(MultiNodeJournalDomainV1::Watch)?
        {
            let current_binding = current.binding();
            if binding.query_digest() != current_binding.query_digest()
                || binding.authorization_digest() != current_binding.authorization_digest()
                || binding.audience_digest() != current_binding.audience_digest()
                || binding.disclosure_domain_digest() != current_binding.disclosure_domain_digest()
                || binding.schema() != current_binding.schema()
                || binding.coordinator_epoch() < current_binding.coordinator_epoch()
                || binding.history_floor_sequence() < current_binding.history_floor_sequence()
                || binding.bootstrap_watermark() < current.cursor().event_sequence()
            {
                return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
            }
        } else if binding.coordinator_epoch()
            != self.store.backend.authenticated_context.coordinator_epoch()
            || binding.history_floor_sequence() != 0
            || binding.history_floor_event_uid()
                != protected_watch_binding_digest(self.clock.config_digest, b"history-floor")
            || binding.bootstrap_watermark() != 0
            || binding.query_digest()
                != protected_watch_binding_digest(self.clock.config_digest, b"query")
            || binding.authorization_digest()
                != protected_watch_binding_digest(self.clock.config_digest, b"authorization")
            || binding.audience_digest()
                != self.store.backend.authenticated_context.audience_digest()
            || binding.disclosure_domain_digest()
                != self
                    .store
                    .backend
                    .authenticated_context
                    .disclosure_domain_digest()
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
        }
        let codec = CanonicalNodeSemanticCodecV1::new();
        let canonical_inventory = codec.encode_watch_inventory(inventory.inventory())?;
        let inventory_receipt = match self.artifacts.store_exact(
            ProtectedArtifactKindV1::WatchInventory,
            bootstrap.inventory_digest(),
            binding.bootstrap_watermark(),
            &canonical_inventory,
        )? {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => receipt,
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => {
                return Ok(
                    ProtectedWatchBootstrapCommitOutcomeV1::ArtifactRecoveryRequired(
                        ProtectedWatchArtifactRecoveryV1 { recovery },
                    ),
                );
            }
        };
        if let Some(recovery) = self.install_watch_bootstrap_capability(
            response,
            inventory.inventory(),
            verified_at_unix_seconds,
        )? {
            return Ok(ProtectedWatchBootstrapCommitOutcomeV1::ReducerRecoveryRequired(recovery));
        }
        let state = WatchJournalStateV1::new(
            binding,
            bootstrap.cursor(),
            bootstrap.inventory_digest(),
            inventory_receipt,
            Vec::new(),
        )?;
        self.validate_watch_artifacts_and_semantics(&state, self.store.backend.history.len())?;
        self.commit_domain_projection(
            MultiNodeReducerStateV1::Watch(state),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )
        .map(ProtectedWatchBootstrapCommitOutcomeV1::Store)
        .map_err(Into::into)
    }

    pub(in crate::local_inventory::store_authority) fn install_watch_bootstrap_capability(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        inventory: &ResyncInventoryV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Option<ProtectedStoreRecoveryRequiredV1>, ProtectedMultiNodeUpdateErrorV1> {
        let context = response.authenticated_context();
        let evidence = DurableEvidenceBindingV1::new(
            inventory.capabilities().node(),
            inventory.capabilities().lineage(),
            context.audience_digest(),
            context.disclosure_domain_digest(),
            context.carrier_binding_digest(),
            response.canonical_frame_digest(),
            context.canonical_frame_bytes(),
            context.coordinator_epoch(),
            context.verified_at_unix_seconds(),
            context.valid_until_unix_seconds(),
            context.replay_fence(),
        )?;
        let next = CapabilityJournalStateV1::new(inventory.capabilities().clone(), evidence)?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Capability)? {
            Some(MultiNodeReducerStateV1::Capability(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current.snapshot() == next.snapshot() {
            return Ok(None);
        }
        if !current.admits_successor(&next) {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        match self.commit_domain_projection(
            MultiNodeReducerStateV1::Capability(next),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )? {
            ProtectedRecordCommitOutcomeV1::Committed(_) => Ok(None),
            ProtectedRecordCommitOutcomeV1::RecoveryRequired(recovery) => Ok(Some(recovery)),
        }
    }

    /// Resolves the exact capability reducer edge preceding a watch bootstrap.
    #[must_use]
    pub fn resolve_watch_bootstrap_reducer(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::Capability {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    /// Builds a watch request from the exact cold-replayed protected cursor.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when no durable bootstrap
    /// exists or the session, coordinator epoch, schema, or cursor is stale.
    pub fn prepare_watch_resume_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let state = match self.current_domain_projection(MultiNodeJournalDomainV1::Watch)? {
            Some(MultiNodeReducerStateV1::Watch(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if state.binding().coordinator_epoch() != session.coordinator_epoch()
            || state.binding().audience_digest() != session.audience_digest()
            || state.binding().disclosure_domain_digest() != session.disclosure_domain_digest()
            || !state.binding().schema().admits(session.version())
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
        }
        let maximum_events = u16::try_from(MAX_WATCH_EVENTS)
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::Watch {
                after: state.cursor(),
                maximum_events,
            },
            b"watch-resume",
        )
        .map_err(Into::into)
    }

    /// Builds a bounded relist that advances the retained watch history floor.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless current replay and
    /// session fencing prove one exact same-policy compaction bootstrap.
    pub fn prepare_watch_compaction_resync_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Watch)? {
            Some(MultiNodeReducerStateV1::Watch(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let binding = current.binding();
        if binding.coordinator_epoch() != session.coordinator_epoch()
            || binding.audience_digest() != session.audience_digest()
            || binding.disclosure_domain_digest() != session.disclosure_domain_digest()
            || !binding.schema().admits(session.version())
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
        }
        let next = NodeWatchBindingV1::new(
            binding.coordinator_epoch(),
            current.cursor().event_sequence(),
            current.cursor().last_event_uid(),
            current.cursor().event_sequence(),
            binding.query_digest(),
            binding.authorization_digest(),
            binding.audience_digest(),
            binding.disclosure_domain_digest(),
            binding.schema(),
        )?;
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::RelistAssignments { binding: next },
            b"watch-compaction-resync",
        )
        .map_err(Into::into)
    }

    /// Commits one exact ordered watch batch or returns a sealed resync edge.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] for stale carrier evidence,
    /// a cursor/version/epoch mismatch, an orphan event, or an oversized
    /// retained stream.
    pub fn commit_watch_batch(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedWatchCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Watch)? {
            Some(MultiNodeReducerStateV1::Watch(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let NodeResponseBodyV1::WatchBatch { events, cursor_gap } = response.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        if let Some(binding) = cursor_gap {
            if !events.is_empty()
                || !watch_binding_advances(current.binding(), *binding, current.cursor())
            {
                return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
            }
            return Ok(ProtectedWatchCommitOutcomeV1::ResyncRequired(
                ProtectedWatchResyncRequiredV1 { binding: *binding },
            ));
        }
        if events.is_empty() {
            return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical.into());
        }
        let first = events
            .first()
            .ok_or(InvalidMultiNodeProtocol::WatchBatchNotCanonical)?;
        if first.cursor().binding() != current.binding()
            || first.cursor().lineage() != current.cursor().lineage()
            || first.cursor().event_sequence()
                != current.cursor().event_sequence().saturating_add(1)
            || first.predecessor_event_uid() != current.cursor().last_event_uid()
            || events.len().saturating_add(current.events().len()) > MAX_WATCH_EVENTS
        {
            return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical.into());
        }
        let mut durable_events = current.events().to_vec();
        let codec = CanonicalNodeSemanticCodecV1::new();
        for event in events {
            let canonical_event = codec.encode_watch_event_body(event.body())?;
            let protected_event_receipt = match self.artifacts.store_exact(
                ProtectedArtifactKindV1::WatchEvent,
                event.cursor().last_event_uid(),
                event.cursor().event_sequence(),
                &canonical_event,
            )? {
                ProtectedArtifactStoreOutcomeV1::Stored(receipt) => receipt,
                ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => {
                    return Ok(ProtectedWatchCommitOutcomeV1::ArtifactRecoveryRequired(
                        ProtectedWatchArtifactRecoveryV1 { recovery },
                    ));
                }
            };
            durable_events.push(DurableWatchEventV1 {
                canonical_event_bytes: event.canonical_event_bytes(),
                canonical_event_digest: event.canonical_event_digest(),
                event_uid: event.cursor().last_event_uid(),
                predecessor_event_uid: event.predecessor_event_uid(),
                sequence: event.cursor().event_sequence(),
                protected_event_receipt,
                carrier_frame_digest: response.canonical_frame_digest(),
            });
        }
        if let Some(recovery) =
            self.apply_watch_domain_events(response, events, verified_at_unix_seconds)?
        {
            return Ok(ProtectedWatchCommitOutcomeV1::ReducerRecoveryRequired(
                recovery,
            ));
        }
        let cursor = events
            .last()
            .map(NodeWatchEventV1::cursor)
            .ok_or(InvalidMultiNodeProtocol::WatchBatchNotCanonical)?;
        let state = WatchJournalStateV1::new(
            current.binding(),
            cursor,
            current.bootstrap_inventory_digest(),
            current.bootstrap_inventory_receipt(),
            durable_events,
        )?;
        self.validate_watch_artifacts_and_semantics(&state, self.store.backend.history.len())?;
        let outcome = self.commit_domain_projection(
            MultiNodeReducerStateV1::Watch(state),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )?;
        Ok(ProtectedWatchCommitOutcomeV1::Store(outcome))
    }

    pub(in crate::local_inventory::store_authority) fn apply_watch_domain_events(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        events: &[NodeWatchEventV1],
        verified_at_unix_seconds: u64,
    ) -> Result<Option<ProtectedStoreRecoveryRequiredV1>, ProtectedMultiNodeUpdateErrorV1> {
        for (event_index, event) in events.iter().enumerate() {
            let next = match event.body() {
                NodeWatchEventBodyV1::Capability(_) => {
                    let observation = response.validated_watch_capability(event_index)?;
                    let next =
                        CapabilityJournalStateV1::from_authenticated_observation(&observation)?;
                    let current = match self
                        .current_domain_projection(MultiNodeJournalDomainV1::Capability)?
                    {
                        Some(MultiNodeReducerStateV1::Capability(state)) => state,
                        _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
                    };
                    if current == next
                        || (current.evidence().canonical_frame_digest()
                            == response.canonical_frame_digest()
                            && current.snapshot().lineage() == next.snapshot().lineage()
                            && current.snapshot().sequence() >= next.snapshot().sequence())
                    {
                        continue;
                    }
                    if !current.admits_successor(&next) {
                        return Err(InvalidMultiNodeJournal::Equivocation.into());
                    }
                    MultiNodeReducerStateV1::Capability(next)
                }
                NodeWatchEventBodyV1::Assignment(observation) => {
                    let current = match self
                        .current_domain_projection(MultiNodeJournalDomainV1::Assignment)?
                    {
                        Some(MultiNodeReducerStateV1::Assignment(state)) => state,
                        _ => continue,
                    };
                    if !observation.matches(current.intent()) {
                        continue;
                    }
                    let durable = DurableAssignmentObservationV1::new(
                        observation.sandbox(),
                        observation.incarnation(),
                        observation.epoch(),
                        observation.desired_generation(),
                        observation.assignment_digest(),
                        observation.sequence(),
                        observation.phase(),
                        observation.realized_lifecycle(),
                        observation.reason(),
                        observation.observed_at_unix_seconds(),
                        observation
                            .authority()
                            .map(|authority| authority.guardian_digest()),
                    )?;
                    if current.observation() == Some(&durable) {
                        continue;
                    }
                    if self.current_domain_effect_digest(MultiNodeJournalDomainV1::Assignment)?
                        == Some(response.canonical_frame_digest())
                        && current
                            .observation()
                            .is_some_and(|prior| prior.sequence >= observation.sequence())
                    {
                        continue;
                    }
                    if current.observation().is_some_and(|prior| {
                        observation.sequence() <= prior.sequence
                            || !prior.phase.can_transition_to(observation.phase())
                    }) {
                        return Err(InvalidMultiNodeJournal::Equivocation.into());
                    }
                    MultiNodeReducerStateV1::Assignment(
                        crate::local_inventory::reducer_state::AssignmentJournalStateV1::new(
                            current.intent().clone(),
                            Some(durable),
                            current.capability_evidence_digest(),
                            current.affinities().to_vec(),
                        )?,
                    )
                }
                NodeWatchEventBodyV1::Drain(observation) => {
                    let current =
                        match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
                            Some(MultiNodeReducerStateV1::Drain(state)) => state,
                            _ => continue,
                        };
                    if !observation.matches(current.directive()) {
                        continue;
                    }
                    let requires_protected_evidence =
                        observation.assignments().iter().any(|assignment| {
                            matches!(
                                assignment.progress(),
                                crate::local_inventory::draining::DrainAssignmentProgressV1::Contained
                                    | crate::local_inventory::draining::DrainAssignmentProgressV1::Released
                            )
                        });
                    if requires_protected_evidence {
                        if self.current_domain_effect_digest(MultiNodeJournalDomainV1::Drain)?
                            != Some(response.canonical_frame_digest())
                            || current.observation().is_none_or(|durable| {
                                !durable_drain_matches_report(durable, observation)
                            })
                        {
                            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
                        }
                        continue;
                    }
                    let durable = durable_drain_observation(observation)?;
                    if current.observation() == Some(&durable) {
                        continue;
                    }
                    if self.current_domain_effect_digest(MultiNodeJournalDomainV1::Drain)?
                        == Some(response.canonical_frame_digest())
                        && current
                            .observation()
                            .is_some_and(|prior| prior.sequence() >= durable.sequence())
                    {
                        continue;
                    }
                    if current.observation().is_some_and(|prior| {
                        durable.sequence() <= prior.sequence()
                            || !prior.phase().can_transition_to(durable.phase())
                    }) {
                        return Err(InvalidMultiNodeJournal::Equivocation.into());
                    }
                    MultiNodeReducerStateV1::Drain(DrainJournalStateV1::new(
                        current.directive().clone(),
                        Some(durable),
                    )?)
                }
            };
            match self.commit_domain_projection(
                next,
                response.request(),
                response.canonical_frame_digest(),
                verified_at_unix_seconds,
            )? {
                ProtectedRecordCommitOutcomeV1::Committed(_) => {}
                ProtectedRecordCommitOutcomeV1::RecoveryRequired(recovery) => {
                    return Ok(Some(recovery));
                }
            }
        }
        Ok(None)
    }

    /// Issues placement evidence from a durably applied capability watch event.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the selected event is
    /// carrier-authenticated, current, and exactly equals the protected current
    /// capability projection installed before the watch cursor.
    #[cfg(feature = "multi-node")]
    pub fn issue_current_watch_placement_candidate(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        event_index: usize,
    ) -> Result<PlacementCandidateV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let observation = response.validated_watch_capability(event_index)?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Capability)? {
            Some(MultiNodeReducerStateV1::Capability(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let expected = CapabilityJournalStateV1::from_authenticated_observation(&observation)?;
        if current != expected || !observation.is_current_at(verified_at_unix_seconds) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        Ok(PlacementCandidateV1::from_authenticated_observation(
            observation,
        ))
    }

    /// Builds the exact relist request required by a carrier-authenticated gap.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the consumed binding remains
    /// current for this fixed owner's authenticated session.
    pub fn prepare_watch_resync_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
        resync: ProtectedWatchResyncRequiredV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        if resync.binding.coordinator_epoch() != session.coordinator_epoch()
            || resync.binding.audience_digest() != session.audience_digest()
            || resync.binding.disclosure_domain_digest() != session.disclosure_domain_digest()
            || !resync.binding.schema().admits(session.version())
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::RelistAssignments {
                binding: resync.binding,
            },
            b"watch-resync",
        )
    }

    /// Resolves only an exact ambiguous watch commit by protected readback.
    #[must_use]
    pub fn resolve_watch_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::Watch {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    /// Resolves one exact watch semantic artifact through protected readback.
    #[must_use]
    pub fn resolve_watch_artifact(
        &mut self,
        pending: ProtectedWatchArtifactRecoveryV1,
    ) -> ProtectedWatchArtifactRecoveryOutcomeV1 {
        if self.observe_current_time().is_err() {
            return ProtectedWatchArtifactRecoveryOutcomeV1::RecoveryRequired(pending);
        }
        match self.artifacts.resolve(pending.recovery.clone()) {
            Ok(ProtectedArtifactStoreOutcomeV1::Stored(_)) => {
                ProtectedWatchArtifactRecoveryOutcomeV1::Stored
            }
            Ok(ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery)) => {
                ProtectedWatchArtifactRecoveryOutcomeV1::RecoveryRequired(
                    ProtectedWatchArtifactRecoveryV1 { recovery },
                )
            }
            Err(_) => ProtectedWatchArtifactRecoveryOutcomeV1::RecoveryRequired(pending),
        }
    }

    pub(in crate::local_inventory::store_authority) fn current_domain_effect_digest(
        &self,
        domain: MultiNodeJournalDomainV1,
    ) -> Result<Option<ObjectDigest>, InvalidMultiNodeJournal> {
        self.store
            .backend
            .history
            .iter()
            .rev()
            .find(|entry| {
                entry.domain == domain && entry.kind == ProtectedStoreObjectKindV1::Record
            })
            .map(|entry| {
                MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)
                    .map(|record| record.effect_digest())
            })
            .transpose()
    }

    pub(in crate::local_inventory::store_authority) fn protected_watch_binding(
        &self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<NodeWatchBindingV1, InvalidMultiNodeProtocol> {
        let context = self.store.backend.authenticated_context;
        if session.node() != context.node()
            || session.lineage() != context.lineage()
            || session.coordinator_epoch() != context.coordinator_epoch()
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let schema = RollingVersionWindowV1::new(session.version(), session.version())?;
        NodeWatchBindingV1::new(
            context.coordinator_epoch(),
            0,
            protected_watch_binding_digest(self.clock.config_digest, b"history-floor"),
            0,
            protected_watch_binding_digest(self.clock.config_digest, b"query"),
            protected_watch_binding_digest(self.clock.config_digest, b"authorization"),
            context.audience_digest(),
            context.disclosure_domain_digest(),
            schema,
        )
    }
}

pub(in crate::local_inventory::store_authority) fn protected_watch_binding_digest(
    config_digest: ObjectDigest,
    purpose: &[u8],
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-watch-binding.v1\0")
            .chain_update(config_digest.as_bytes())
            .chain_update((purpose.len() as u64).to_be_bytes())
            .chain_update(purpose)
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn watch_binding_advances(
    current: NodeWatchBindingV1,
    next: NodeWatchBindingV1,
    cursor: NodeWatchCursorV1,
) -> bool {
    next != current
        && next.query_digest() == current.query_digest()
        && next.authorization_digest() == current.authorization_digest()
        && next.audience_digest() == current.audience_digest()
        && next.disclosure_domain_digest() == current.disclosure_domain_digest()
        && next.schema() == current.schema()
        && next.coordinator_epoch() >= current.coordinator_epoch()
        && next.history_floor_sequence() >= current.history_floor_sequence()
        && (next.history_floor_sequence() != current.history_floor_sequence()
            || next.history_floor_event_uid() == current.history_floor_event_uid())
        && next.bootstrap_watermark() >= cursor.event_sequence()
}

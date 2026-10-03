//! Same-Session Query planning and signature retention before postchecks.

use super::*;

impl CurrentRootMountSourceProviderSessionV1 {
    /// Parks one ordinary Query preparation before its first fallible check.
    ///
    /// # Errors
    /// Revokes both original and Session effects; all produced owners remain parked.
    #[doc(hidden)]
    pub fn begin_original_inventory_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        slot: &mut Option<OriginalInventoryPreparationV6>,
    ) -> Result<(), SourceProviderSecurityError> {
        let mut boundary = QueryBoundaryV6::new(self, original, slot);
        boundary.run(|session, progress| {
            let slot = &mut **progress;

            if let Some(existing) = slot.as_ref() {
                existing.failed.set(true);
                session.fail_query_v6(original);
                return Err(invalid());
            }

            *slot = Some(OriginalInventoryPreparationV6 {
                root: original.2.attempt(),
                plan: None,
                request: None,
                draft: None,
                correlations: None,
                historical: Vec::new(),
                attempted_sign: false,
                signed: None,
                prepared: None,
                confirmed: false,
                failed: Cell::new(false),
            });
            let preparation = slot.as_mut().ok_or_else(invalid)?;

            session.revalidate_original_inventory_continuation_v6(writer, original)?;
            let graph = writer.current_graph().map_err(|_| invalid())?;
            let root = graph
                .legacy()
                .provider_attempts
                .get(&preparation.root)
                .ok_or_else(invalid)?;
            let identity = (root.scope.holder_authority_id, root.scope.provider_authority_id);
            let head = graph.legacy().provider_heads.get(&identity).ok_or_else(invalid)?;
            if head.recovery_barrier.is_some()
                || head.pending_attempt.is_some()
                || head.next_request_sequence != head.next_response_sequence
            {
                return Err(invalid());
            }

            let key = msa::provider_head_key(identity.0, identity.1);
            let bytes = graph.canonical_records().get(&key).ok_or_else(invalid)?.clone();
            let stored = graph
                .legacy()
                .provider_sessions
                .get(&head.current_session_id)
                .ok_or_else(invalid)?;
            preparation.plan = Some(session.current_mount_provider_session_plan_with_view_v2(
                writer,
                writer.snapshot().map_err(|_| invalid())?,
                key,
                bytes,
                head.next_request_sequence,
                head.next_response_sequence,
                Some(stored.authenticated_at_seconds),
            )?);
            let plan = preparation.plan.as_ref().ok_or_else(invalid)?;
            if !stored_mount_session_matches_projection(stored, &plan.session) {
                return Err(invalid());
            }

            let (draft, correlations) = unsigned_draft(graph.legacy(), head, stored)?;
            let request = InventorySourceRequestV1::new(
                plan.session.session_binding,
                head.next_request_sequence,
                draft.request_id,
                identity.0,
                stored.root_mount_authority_generation,
                ObjectDigest::from_bytes(stored.root_mount_authority_digest),
                head.inventory_floor
                    .as_ref()
                    .map(|floor| ObjectDigest::from_bytes(floor.inventory_digest)),
                original.0.deadline_seconds.min(plan.session.current_valid_until_seconds),
            )
            .map_err(|_| invalid())?;
            preparation.request = Some(request);
            preparation.draft = Some(draft);
            preparation.correlations = Some(correlations);

            // Historical authorizations remain actual move-only values, not markers.
            let historical_rows = graph.legacy().acquisitions.values().filter(|row| {
                row.scope == head.scope
                    && row.evidence.is_some()
                    && (row.provider_acquisition.holder_authority_generation != stored.root_mount_authority_generation
                        || row.provider_acquisition.holder_authority_digest != stored.root_mount_authority_digest)
            });
            for row in historical_rows {
                preparation.historical.try_reserve(1).map_err(|_| invalid())?;
                let evidence = row.evidence.as_ref().ok_or_else(invalid)?;
                let previous = graph
                    .legacy()
                    .provider_sessions
                    .get(&evidence.session_id)
                    .ok_or_else(invalid)?;
                let holder = SourceProviderAuthorityV1::new(
                    previous.scope.holder_authority_id,
                    previous.root_mount_authority_generation,
                    ObjectDigest::from_bytes(previous.root_mount_authority_digest),
                )
                .map_err(|_| invalid())?;
                let acquisition_key = msa::acquisition_key(row.acquisition_id);
                let session_key = msa::provider_session_key(previous.session_id);
                let acquisition_bytes = graph.canonical_records()
                    .get(&acquisition_key).ok_or_else(invalid)?.clone();
                let session_bytes = graph.canonical_records()
                    .get(&session_key).ok_or_else(invalid)?.clone();
                let lineage = session.authorize_historical_mount_acquisition_v2(
                    writer,
                    writer.snapshot().map_err(|_| invalid())?,
                    acquisition_key,
                    acquisition_bytes,
                    session_key,
                    session_bytes,
                    holder,
                    ObjectDigest::from_bytes(row.provider_acquisition.acquisition_id),
                    row.provider_acquisition.acquisition_sequence,
                    evidence.lease_id,
                    ObjectDigest::from_bytes(evidence.signed_lease_digest),
                    previous.authenticated_at_seconds,
                    previous.trust_generation,
                    ObjectDigest::from_bytes(previous.trust_digest),
                    previous.revocation_generation,
                    ObjectDigest::from_bytes(previous.revocation_digest),
                    previous.signed_root_mount_hello.clone(),
                )?;
                preparation.historical.push(HistoricalMountInventoryAuthorizationV2 { lineage });
            }

            session.revalidate_original_inventory_continuation_v6(writer, original)
        })
    }

    /// Signs the retained Query once and parks the signature before postchecks.
    ///
    /// # Errors
    /// Rejects another attempt, stale originals or changed plan/correlations; retains output.
    #[doc(hidden)]
    pub fn advance_original_inventory_preparation_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        preparation: &mut OriginalInventoryPreparationV6,
    ) -> Result<bool, SourceProviderSecurityError> {
        let mut boundary = QueryBoundaryV6::new(self, original, preparation);
        boundary.run(|session, progress| {
            let preparation = &mut **progress;

            session.revalidate_original_inventory_continuation_v6(writer, original)?;
            if preparation.failed.get()
                || preparation.attempted_sign
                || preparation.root != original.2.attempt()
            {
                return Err(invalid());
            }
            let plan = preparation.plan.as_ref().ok_or_else(invalid)?;
            session.validate_current_mount_plan(writer, plan)?;
            let snapshot = writer.snapshot().map_err(|_| invalid())?;
            let expected = session.historical_inventory_correlations_with_view_v6(
                writer,
                &preparation.historical,
            )?;
            let correlations = preparation.correlations.as_ref().ok_or_else(invalid)?;
            if &expected != correlations {
                return Err(invalid());
            }

            let request = preparation.request.as_ref().ok_or_else(invalid)?;
            // Authentication-time DATA stays frozen; real currentness is checked
            // independently by Session and the unchanged original clock guard.
            session.revalidate()?;
            let authentication_time = query_authentication_time_v6(
                plan.session.authenticated_at_seconds,
                super::super::current_unix_seconds()?,
            )?;
            let projection = capture_session_projection(session, authentication_time)?;
            let graph = writer.current_graph().map_err(|_| invalid())?;
            let draft = preparation.draft.as_ref().ok_or_else(invalid)?;
            let stored = graph
                .legacy()
                .provider_sessions
                .get(&draft.session_id)
                .ok_or_else(invalid)?;
            if !stored_mount_session_matches_projection(stored, &projection)
                || request.sequence() != plan.current_request_sequence
            {
                return Err(invalid());
            }

            preparation.attempted_sign = true;
            session.authorize_non_acquire_retaining_v6(
                SourceProviderMethod::Inventory,
                encode_inventory_request(request),
                request.session_binding(),
                request.sequence(),
                request.request_id(),
                request.holder_authority_id(),
                request.holder_generation(),
                request.holder_authority_digest(),
                request.deadline_seconds(),
                plan.current_response_sequence,
                None,
                None,
                digest_inventory_request(request),
                projection,
                &mut preparation.signed,
                &mut preparation.prepared,
            )?;

            // The original prepared owner is parked before correlation clones
            // or any writer/Session postcheck can fail or unwind.
            let prepared = preparation.prepared.as_mut().ok_or_else(invalid)?;
            prepared.projection.inventory_correlations = Some(correlations.clone());
            prepared.outcome.inventory_correlations = Some(correlations.clone());
            writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;
            session.revalidate_original_inventory_continuation_v6(writer, original)?;
            Ok(true)
        })
    }
}

// This DATA builder is checked independently by the accepted exact Query edge
// predicate before append. Canonical identity and owner arithmetic stay shared.
fn unsigned_draft(
    state: &msa::MountSourceAcquisitionStateV2,
    head: &msa::SourceProviderHeadV2,
    session: &msa::SourceProviderSessionV2,
) -> Result<
    (msa::SourceProviderQueryAttemptV2, msa::InventoryCorrelationSetV2),
    SourceProviderSecurityError,
> {
    let mut entries = state
        .acquisitions
        .values()
        .filter(|row| row.scope == head.scope)
        .filter_map(msa::inventory_correlation_for_row_v2)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.provider_acquisition.acquisition_id);
    let correlations = msa::inventory_correlation_set_v2(entries).map_err(|_| invalid())?;
    let intent = msa::ProviderIntentV2::Inventory {
        value: msa::InventoryIntentV2 {
            scope: head.scope,
            known_inventory_generation: head.inventory_floor
                .as_ref().map(|floor| floor.inventory_generation),
            known_inventory_digest: head.inventory_floor
                .as_ref().map(|floor| floor.inventory_digest),
            known_catalog_generation: head.inventory_floor
                .as_ref().map(|floor| floor.catalog_generation),
            known_catalog_digest: head.inventory_floor
                .as_ref().map(|floor| floor.catalog_digest),
            known_observation_ordinal: head.inventory_observation_ordinal,
            recovery_root_attempt_id: None,
            correlation_digest: correlations.digest,
        },
    };

    let predecessor = head.last_inventory_attempt
        .map(|reference| {
            state.provider_attempts.get(&reference.id)
                .filter(|attempt| {
                    attempt.revision == reference.revision
                        && attempt.record_digest == reference.record_digest
                        && attempt.method == msa::ProviderMethodV2::Inventory
                })
                .ok_or_else(invalid)
        })
        .transpose()?;
    let (lineage, previous, number) = match predecessor {
        Some(attempt)
            if attempt.attempt_number != msa::format::MAXIMUM_LINEAGE_ATTEMPTS as u64 =>
        {
            (
                attempt.lineage_root_attempt_id,
                Some(attempt.attempt_id),
                attempt.attempt_number.checked_add(1).ok_or_else(invalid)?,
            )
        }
        _ => ([0; 32], None, 1),
    };

    let mut head_id = [0; 32];
    head_id[..16].copy_from_slice(&head.scope.holder_authority_id);
    head_id[16..].copy_from_slice(&head.scope.provider_authority_id);
    let predecessor = msa::OwnerPredecessorWitnessV2::ProviderHead {
        value: msa::ProviderHeadPredecessorWitnessV2 {
            record: msa::RecordRefV2 {
                id: head_id,
                revision: head.revision,
                record_digest: head.record_digest,
            },
            scope: head.scope,
            holder_authority_generation: head.holder_authority_generation,
            holder_authority_digest: head.holder_authority_digest,
            provider_authority_generation: head.provider_authority_generation,
            provider_authority_digest: head.provider_authority_digest,
            current_session_id: head.current_session_id,
            current_session_record_digest: head.current_session_record_digest,
            next_request_sequence: head.next_request_sequence,
            next_response_sequence: head.next_response_sequence,
            pending_attempt: head.pending_attempt,
            inventory_observation_ordinal: head.inventory_observation_ordinal,
            inventory_floor: head.inventory_floor.clone(),
            last_inventory_attempt: head.last_inventory_attempt,
            current_projection_epoch: head.current_projection_epoch,
            current_projection_digest: head.current_projection_digest,
            last_reconciliation: head.last_reconciliation.clone(),
            recovery_barrier: head.recovery_barrier.clone(),
        },
    };

    let mut draft = msa::SourceProviderQueryAttemptV2 {
        attempt_id: [0; 32],
        revision: 1,
        scope: head.scope,
        method: msa::ProviderMethodV2::Inventory,
        owner: msa::ProviderQueryOwnerV2::Inventory,
        immutable_intent_digest: msa::intent_digest(&intent).map_err(|_| invalid())?,
        intent,
        provider_acquisition: None,
        lineage_root_attempt_id: lineage,
        previous_attempt_id: previous,
        attempt_number: number,
        session_id: session.session_id,
        session_record_digest: session.record_digest,
        signer_set_commitment: session.signer_set_commitment,
        trust_digest: session.trust_digest,
        revocation_digest: session.revocation_digest,
        route_digest: session.route_digest,
        process_execution_digest: session.provider_execution.process_execution_digest,
        normalized_acquire_intent: None,
        acquire_verification_floor: None,
        inventory_correlations: None,
        request_id: [0; 16],
        request_sequence: head.next_request_sequence,
        signed_request: Vec::new(),
        signed_request_digest: [0; 32],
        owner_predecessor_revision: head.revision,
        owner_predecessor_digest: head.record_digest,
        owner_predecessor: Some(predecessor),
        state: msa::ProviderAttemptStateV2::Reserved,
        record_digest: [0; 32],
    };
    draft.attempt_id = msa::attempt_id(&draft);
    if draft.lineage_root_attempt_id == [0; 32] {
        draft.lineage_root_attempt_id = draft.attempt_id;
    }
    draft.request_id = msa::request_id(draft.attempt_id);
    Ok((draft, correlations))
}

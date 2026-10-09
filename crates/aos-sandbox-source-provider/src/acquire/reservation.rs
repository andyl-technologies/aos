//! Fresh Acquire and superseding-session reservation reducers.

use super::*;

pub(crate) fn reserve_acquire(
    ledger: &mut ProviderLedgerV1<'_>,
    security_session: &mut CurrentProviderIngressSessionV1,
    current_request: aos_sandbox_source_provider_security::CurrentProviderRequestV1,
    current_catalog: Option<(&[u8], &[u8])>,
    original_packet: Option<&crate::FixedProviderAuthenticatedSourceRequestV1>,
    native_reauthentication: Option<crate::native_completion::NativeReplyReauthentication>,
) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
    let provider_execution_identity = current_request.provider_execution_identity();
    let verified = match current_request.verified() {
        aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(value) => value,
        _ => return Err(ProviderLedgerError::Equivocation),
    };
    let projection = verified.ingress_projection();
    let existing_session = validate_projection(ledger, projection)?;
    validate_session_capacity(ledger, &existing_session, projection)?;
    let request = verified.request();
    // Raw/public callers remain closed. Only the original carrier packet can
    // enter the seven-claim preclassification cut below.
    let native_v3 =
        super::native_admission::require_original_packet_profile(request, original_packet)?;
    let mut native_admission = if native_v3 {
        let (publication, rows) = current_catalog.ok_or(ProviderLedgerError::Unavailable)?;
        let normalized = normalized_intent(verified)?;
        let selection = super::native_admission::select_current_resource(
            ledger,
            security_session,
            &normalized,
            projection.resource_namespace_digest(),
            publication,
            rows,
        )?;
        let native = super::native_admission::OriginalNativeAdmission::prepare(
            ledger,
            original_packet.ok_or(ProviderLedgerError::Equivocation)?,
            verified,
            selection,
        )?;
        native.before_commit(ledger, security_session, rows)?;
        Some(native)
    } else {
        None
    };
    let attempt_evidence = verified.attempt();
    // This slot is only for the already-qualified legacy dispatch seam. The
    // original V3 no-dispatch/recovery cut and ordinary V2 requests never
    // reserve it, even when another operation retains a native completion.
    let native_reply_candidate = super::native_admission::permits_native_reply_reservation(
        current_catalog.is_some(),
        request.acquisition_version(),
        request.kernel_coupled(),
        ledger.qualified_native_bridge.as_ref(),
    );
    let native_reply_identity = crate::native_completion::NativeReplyIdentity {
        acquisition: request.acquisition_id(),
        attempt: attempt_evidence.attempt_digest(),
        session: projection.session_binding(),
        signed_request: attempt_evidence.signed_request_digest(),
    };
    if let Some(cut) = native_reauthentication {
        let identity = cut.identity;
        if !native_reply_candidate || identity != native_reply_identity {
            return Err(ProviderLedgerError::Equivocation);
        }
        ledger.native_reply_custody.require_reserved(identity)?;
        let retained = ledger
            .recovered
            .native_completions
            .get(&identity.acquisition)
            .ok_or(ProviderLedgerError::Unavailable)?;
        cut.require_record(retained, attempt_evidence.canonical_signed_request())?;
        if ledger
            .journal
            .get(&crate::ledger::native_completion::native_completion_key_v2(
                identity.acquisition,
            ))?
            != Some(crate::format::encode_native_completion_v2(retained).as_slice())
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        ledger
            .native_acquire_custody
            .get(&identity.acquisition)
            .ok_or(ProviderLedgerError::Unavailable)?
            .clock
            .require_record(retained)?;
    } else {
        ledger
            .native_reply_custody
            .require_candidate_available(native_reply_candidate)?;
    }
    let native_reply_selection = if native_reply_candidate {
        let (publication, rows) = current_catalog.ok_or(ProviderLedgerError::Unavailable)?;
        Some(super::native_admission::select_current_resource(
            ledger,
            security_session,
            &normalized_intent(verified)?,
            projection.resource_namespace_digest(),
            publication,
            rows,
        )?)
    } else {
        None
    };
    if native_reply_candidate
        && native_reauthentication.is_none()
        && ledger.recovered.acquisitions.values().any(|row| {
            row.acquisition_id == request.acquisition_id()
                && row.state == ProviderAcquisitionStateV1::Applying
                && crate::native_completion::is_native_dispatch_acquisition(row)
        })
    {
        ledger.native_reply_custody.reserve(native_reply_identity)?;
    }
    let root_record_signer = projection.ordered_signers()[1].clone();
    let key = AttemptKeyV1 {
        provider_id: projection.provider_authority().authority_id(),
        holder_id: projection.root_mount_authority().authority_id(),
        root_record_key_id: root_record_signer.key_id(),
        method: SourceProviderMethod::Acquire as u8,
        request_id: attempt_evidence.request_id(),
    };
    if let Some(disposition) = classify_attempt(
        ledger,
        &key,
        attempt_evidence.attempt_digest(),
        attempt_evidence.signed_request_digest(),
        digest_acquire_request(request),
        attempt_evidence.canonical_signed_request(),
    )? {
        if matches!(
            &disposition,
            ProviderAdmissionDispositionV1::Recover(_)
                | ProviderAdmissionDispositionV1::CachedRecovery { .. }
        ) {
            if let Some(native) = &native_admission {
                native.before_commit(
                    ledger,
                    security_session,
                    current_catalog.ok_or(ProviderLedgerError::Unavailable)?.1,
                )?;
            }
            let retained =
                ledger
                    .recovered
                    .attempts
                    .get(&key)
                    .ok_or(ProviderLedgerError::Corrupt(
                        "missing retained Acquire attempt",
                    ))?;
            let response_sequence = ledger
                .recovered
                .sessions
                .get(&(
                    retained.provider.authority_id(),
                    retained.holder.authority_id(),
                ))
                .ok_or(ProviderLedgerError::Corrupt(
                    "missing retained Acquire session",
                ))?
                .next_response_sequence;
            let retained = retained.clone();
            let retained_digest = retained.attempt_digest;
            let signing_authorization = authorize_current_reservation(
                security_session,
                current_request,
                ledger,
                &key,
                &retained,
                response_sequence,
            )?;
            ledger
                .recovery_authorizations
                .insert(retained_digest, signing_authorization);
        }
        if let Some(native) = &native_admission {
            if let Err(error) = native.require_live(security_session) {
                ledger.poison_runtime();
                return Err(error);
            }
        }
        return Ok(disposition);
    }
    if native_reauthentication.is_some() {
        // Either named internal cut can only borrow the original Applying
        // reservation; it cannot admit a fresh operation or a new slot.
        return Err(ProviderLedgerError::Equivocation);
    }
    let next_request_sequence = match verified.sequence() {
        VerifiedProviderRequestSequenceV1::Fresh(advance) => {
            if advance.accepted_sequence() != request.sequence()
                || advance.attempt_digest() != attempt_evidence.attempt_digest()
            {
                return Err(ProviderLedgerError::Equivocation);
            }
            advance.next_sequence()
        }
        VerifiedProviderRequestSequenceV1::ExactReplay(_) => {
            return Err(ProviderLedgerError::Equivocation);
        }
    };
    let normalized_intent = normalized_intent(&verified)?;
    let selected_resource = if let Some(native) = &native_admission {
        Some(native.resource().clone())
    } else if let Some(selection) = &native_reply_selection {
        Some(selection.resource().clone())
    } else if let Some((canonical_publication, canonical_rows)) = current_catalog {
        Some(
            super::native_admission::select_current_resource(
                ledger,
                security_session,
                &normalized_intent,
                projection.resource_namespace_digest(),
                canonical_publication,
                canonical_rows,
            )?
            .resource()
            .clone(),
        )
    } else if normalized_intent.kernel_coupled() {
        return Err(ProviderLedgerError::Unavailable);
    } else {
        None
    };
    let acquisition_key_value = AcquisitionKeyV1 {
        provider_id: projection.provider_authority().authority_id(),
        holder_id: projection.root_mount_authority().authority_id(),
        acquisition_id: request.acquisition_id(),
    };
    if let Some((existing_key, existing)) = ledger
        .recovered
        .acquisitions
        .iter()
        .find(|(key, _)| key.acquisition_id == request.acquisition_id())
    {
        crate::ledger::native_completion::validate_native_export_open_v1(
            existing,
            ledger
                .recovered
                .native_completions
                .get(&existing.acquisition_id),
        )
        .map_err(crate::transaction::map_pure_ledger_error)?;
        if existing_key != &acquisition_key_value || existing.normalized_intent != normalized_intent
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        if matches!(
            existing.state,
            ProviderAcquisitionStateV1::Applying
                | ProviderAcquisitionStateV1::Active
                | ProviderAcquisitionStateV1::Pending
        ) && existing_session
            .as_ref()
            .is_some_and(|session| session.session_binding != projection.session_binding())
        {
            let descriptor_predecessor_is_fenced =
                existing_session.as_ref().is_some_and(|session| {
                    ledger.recovered.authority.revocation_generation > session.revocation_generation
                        || ledger
                            .current_sessions
                            .get(&projection.root_mount_authority().authority_id())
                            .and_then(|installed| installed.recovered_execution_death.as_ref())
                            .is_some_and(|death| {
                                death.matches(
                                    session.boot_id,
                                    session.provider_process_id,
                                    session.provider_start_time_ticks,
                                    session.provider_process_instance,
                                )
                            })
                });
            if existing.state == ProviderAcquisitionStateV1::Active
                && !descriptor_predecessor_is_fenced
            {
                return Err(ProviderLedgerError::InvalidTransition(
                    "descriptor-bearing rebind requires exact predecessor death or revocation",
                ));
            }
            return reserve_acquire_rebind(
                ledger,
                security_session,
                current_request,
                key,
                existing.clone(),
                existing_session,
                normalized_intent,
                next_request_sequence,
            );
        }
        return Err(ProviderLedgerError::InvalidTransition(
            "acquisition continuation requires a superseding session and exact backend revalidation",
        ));
    }
    if ledger.recovered.authority.state != ProviderAuthorityStateV1::Active {
        return Err(ProviderLedgerError::InvalidTransition(
            "new Acquire is closed",
        ));
    }
    enforce_acquire_limits(ledger, projection.root_mount_authority().authority_id())?;

    let effect_id =
        derive_acquire_effect_id(request.acquisition_id(), attempt_evidence.attempt_digest())?;
    let selected_native = selected_resource.is_some() && !normalized_intent.kernel_coupled();
    let native_dispatch = super::native_admission::permits_native_dispatch(
        selected_native,
        native_v3,
        ledger.qualified_native_bridge.as_ref(),
    );
    let native_no_dispatch = selected_native && !native_dispatch;
    if native_dispatch {
        if !native_reply_candidate {
            return Err(ProviderLedgerError::Unavailable);
        }
        ledger.native_reply_custody.reserve(native_reply_identity)?;
    }
    let backend_id = if native_dispatch {
        aos_sandbox_source_provider_ledger::identity::acquire_native_dispatch_id_v2(
            normalized_intent.digest(),
            ledger.recovered.catalog.catalog_generation,
            ledger.recovered.catalog.catalog_digest,
            attempt_evidence.attempt_digest(),
        )
    } else if native_no_dispatch {
        derive_native_no_dispatch_id(
            normalized_intent.digest(),
            ledger.recovered.catalog.catalog_generation,
            ledger.recovered.catalog.catalog_digest,
        )
    } else {
        derive_backend_plan_id(
            normalized_intent.digest(),
            ledger.recovered.catalog.catalog_generation,
            ledger.recovered.catalog.catalog_digest,
        )
    };
    let attempt = crate::transaction::reserved_acquire_attempt(
        verified,
        root_record_signer,
        &normalized_intent,
        ledger.pending_recovery_bridge.as_ref(),
    );
    let (mut session, _persist_history) = prepare_session(
        ledger,
        projection,
        provider_execution_identity,
        existing_session,
        request.sequence(),
    )?;
    if request.acquisition_sequence() < session.next_acquisition_sequence {
        return Err(ProviderLedgerError::Equivocation);
    }
    session.next_acquisition_sequence = request.acquisition_sequence().checked_add(1).ok_or(
        ProviderLedgerError::InvalidTransition("acquisition sequence exhausted"),
    )?;
    let session = reserve_session(session, next_request_sequence, attempt.attempt_digest)?;
    let acquire_plan = crate::backend::AcquirePlanV1 {
        provider_id: projection.provider_authority().authority_id(),
        holder_id: projection.root_mount_authority().authority_id(),
        session_binding: projection.session_binding(),
        attempt_digest: attempt.attempt_digest,
        acquisition_id: request.acquisition_id(),
        effect_id,
        normalized_intent_digest: normalized_intent.digest(),
        kernel_coupled: normalized_intent.kernel_coupled(),
        backend_id,
    };
    let acquisition = crate::transaction::reserved_acquisition(
        projection,
        request,
        &attempt,
        &ledger.recovered.catalog,
        &acquire_plan,
        normalized_intent,
        selected_resource.as_ref(),
    );
    let mut records = vec![
        (attempt_key(&key), encode_attempt(&attempt)),
        (
            acquisition_key(&acquisition_key_value),
            encode_acquisition(&acquisition),
        ),
        (
            session_key(
                session.provider.authority_id(),
                session.holder.authority_id(),
            ),
            encode_session(&session),
        ),
    ];
    records.push((
        session_history_key(
            session.provider.authority_id(),
            session.holder.authority_id(),
            session.session_binding,
        ),
        encode_session_history(&session),
    ));
    let reservation_digest = if let Some(native) = &native_admission {
        crate::native_no_dispatch_capacity::commit_reservation_checked(
            ledger,
            ACQUIRE_RESERVE_PURPOSE,
            records,
            &acquisition,
            &attempt,
            &session,
            |ledger| {
                native.retain_before_append(
                    ledger,
                    security_session,
                    current_catalog.ok_or(ProviderLedgerError::Unavailable)?.1,
                )
            },
        )?
    } else if selected_native {
        crate::native_no_dispatch_capacity::commit_reservation(
            ledger,
            ACQUIRE_RESERVE_PURPOSE,
            records,
            &acquisition,
            &attempt,
            &session,
        )?
    } else {
        commit_records(ledger, ACQUIRE_RESERVE_PURPOSE, records)?
    };
    let journal_snapshot = match ledger.journal.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            ledger.poison_runtime();
            return Err(error.into());
        }
    };
    let authorization_attempt = attempt.clone();
    let authorization_key = key.clone();
    let response_sequence = session.next_response_sequence;
    ledger.recovered.attempts.insert(key, attempt);
    ledger
        .recovered
        .acquisitions
        .insert(acquisition_key_value, acquisition.clone());
    ledger.recovered.sessions.insert(
        (
            session.provider.authority_id(),
            session.holder.authority_id(),
        ),
        session.clone(),
    );
    ledger.recovered.session_history.insert(
        (
            session.provider.authority_id(),
            session.holder.authority_id(),
            session.session_binding,
        ),
        session,
    );
    ledger.refresh_recovery_work();
    if let Some(native) = &native_admission {
        let (publication, rows) = current_catalog.ok_or(ProviderLedgerError::Unavailable)?;
        if let Err(error) = native.after_commit(ledger, security_session, publication, rows) {
            // The exact occupied rows and hot clock survive this ambiguity.
            // Poisoning prevents any permit, rollback, or absence claim.
            ledger.poison_runtime();
            return Err(error);
        }
    }
    let signing_authorization = match authorize_current_reservation(
        security_session,
        current_request,
        ledger,
        &authorization_key,
        &authorization_attempt,
        response_sequence,
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            ledger.poison_runtime();
            return Err(error);
        }
    };
    let completion_capacity = if native_dispatch {
        crate::transaction::CompletionCapacityV1::NativeDispatch
    } else if native_no_dispatch {
        crate::transaction::CompletionCapacityV1::native_no_dispatch()
    } else {
        preflight_completion_capacity(
            &ledger.journal,
            ACQUIRE_COMPLETE_PURPOSE,
            reservation_digest,
            MAXIMUM_ACQUIRE_COMPLETION_BYTES,
        )?
    };
    if let Some(native) = native_admission.take() {
        if let Err(error) = native.require_live(security_session) {
            ledger.poison_runtime();
            return Err(error);
        }
    }
    Ok(ProviderAdmissionDispositionV1::Acquire(
        DurableAcquireEffectPermitV1 {
            plan: acquire_plan,
            completion_session_binding: authorization_attempt.session_binding,
            completion_attempt_digest: authorization_attempt.attempt_digest,
            reservation_digest,
            journal_snapshot,
            completion_capacity,
            signing_authorization,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn reserve_acquire_rebind(
    ledger: &mut ProviderLedgerV1<'_>,
    security_session: &mut CurrentProviderIngressSessionV1,
    current_request: aos_sandbox_source_provider_security::CurrentProviderRequestV1,
    attempt_key_value: AttemptKeyV1,
    acquisition: AcquisitionRecordV1,
    existing_session: Option<crate::model::HolderSessionHeadRecordV1>,
    normalized_intent: NormalizedAcquisitionIntentV1,
    next_request_sequence: u64,
) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
    let provider_execution_identity = current_request.provider_execution_identity();
    let verified = match current_request.verified() {
        aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(value) => value,
        _ => return Err(ProviderLedgerError::Equivocation),
    };
    let projection = verified.ingress_projection();
    let request = verified.request();
    let superseded_pending_attempt = existing_session.as_ref().and_then(|session| {
        (session.session_binding != projection.session_binding())
            .then_some(session.pending_attempt_digest)
            .flatten()
    });
    let attempt = crate::transaction::reserved_acquire_attempt(
        verified,
        projection.ordered_signers()[1].clone(),
        &normalized_intent,
        ledger.pending_recovery_bridge.as_ref(),
    );
    let (session, persist_history) = prepare_session(
        ledger,
        projection,
        provider_execution_identity,
        existing_session,
        request.sequence(),
    )?;
    if !persist_history {
        return Err(ProviderLedgerError::InvalidTransition(
            "active acquisition rebind requires a superseding session",
        ));
    }
    if request.acquisition_sequence() != acquisition.acquisition_sequence
        || request.acquisition_sequence() >= session.next_acquisition_sequence
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let session = reserve_session(session, next_request_sequence, attempt.attempt_digest)?;
    let mut acquisition = acquisition;
    let recovery_predecessor =
        if acquisition.state == ProviderAcquisitionStateV1::Applying
            || superseded_pending_attempt.is_some()
        {
            let predecessor_digest = match superseded_pending_attempt {
                Some(digest) => digest,
                None => acquisition.current_attempt_digest,
            };
            let predecessor_key = ledger
                .recovered
                .attempts
                .keys()
                .find(|key| {
                    ledger
                        .recovered
                        .attempts
                        .get(*key)
                        .is_some_and(|value| value.attempt_digest == predecessor_digest)
                })
                .cloned()
                .ok_or(ProviderLedgerError::Corrupt(
                    "Applying continuation predecessor",
                ))?;
            let mut predecessor = ledger
                .recovered
                .attempts
                .get(&predecessor_key)
                .cloned()
                .ok_or(ProviderLedgerError::Corrupt(
                    "Applying continuation predecessor",
                ))?;
            if predecessor.state != ProviderAttemptStateV1::Reserved
                || predecessor.operation_intent_digest != normalized_intent.digest()
            {
                return Err(ProviderLedgerError::Equivocation);
            }
            if acquisition.state == ProviderAcquisitionStateV1::Applying
                && predecessor.attempt_digest != acquisition.effect_attempt_digest
            {
                return Err(ProviderLedgerError::Equivocation);
            }
            predecessor.revision = predecessor.revision.checked_add(1).ok_or(
                ProviderLedgerError::InvalidTransition("attempt revision exhausted"),
            )?;
            predecessor.state = ProviderAttemptStateV1::Retired;
            if acquisition.state == ProviderAcquisitionStateV1::Applying {
                acquisition.revision = acquisition.revision.checked_add(1).ok_or(
                    ProviderLedgerError::InvalidTransition("acquisition revision exhausted"),
                )?;
                acquisition.current_attempt_digest = attempt.attempt_digest;
            }
            Some((predecessor_key, predecessor))
        } else {
            None
        };
    let mut records = vec![
        (attempt_key(&attempt_key_value), encode_attempt(&attempt)),
        (
            session_key(
                session.provider.authority_id(),
                session.holder.authority_id(),
            ),
            encode_session(&session),
        ),
        (
            session_history_key(
                session.provider.authority_id(),
                session.holder.authority_id(),
                session.session_binding,
            ),
            encode_session_history(&session),
        ),
    ];
    if let Some((predecessor_key, predecessor)) = &recovery_predecessor {
        records.push((attempt_key(predecessor_key), encode_attempt(predecessor)));
        records.push((
            acquisition_key(&AcquisitionKeyV1 {
                provider_id: acquisition.provider.authority_id(),
                holder_id: acquisition.holder.authority_id(),
                acquisition_id: acquisition.acquisition_id,
            }),
            encode_acquisition(&acquisition),
        ));
    }
    let reservation_digest = commit_records(ledger, b"reserve-acquire-rebind", records)?;
    let journal_snapshot = ledger.journal.snapshot()?;
    let response_sequence = session.next_response_sequence;
    let committed_session_binding = session.session_binding;
    let holder_id = projection.root_mount_authority().authority_id();
    ledger
        .recovered
        .attempts
        .insert(attempt_key_value.clone(), attempt.clone());
    if let Some((predecessor_key, predecessor)) = recovery_predecessor {
        ledger
            .recovered
            .attempts
            .insert(predecessor_key, predecessor);
        let acquisition_key_value = AcquisitionKeyV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            acquisition_id: acquisition.acquisition_id,
        };
        ledger
            .recovered
            .acquisitions
            .insert(acquisition_key_value, acquisition.clone());
    }
    ledger.recovered.sessions.insert(
        (
            session.provider.authority_id(),
            session.holder.authority_id(),
        ),
        session.clone(),
    );
    ledger.recovered.session_history.insert(
        (
            session.provider.authority_id(),
            session.holder.authority_id(),
            session.session_binding,
        ),
        session,
    );
    let signing_authorization = authorize_current_reservation(
        security_session,
        current_request,
        ledger,
        &attempt_key_value,
        &attempt,
        response_sequence,
    )?;
    ledger.refresh_recovery_work();
    let completion_capacity = preflight_completion_capacity(
        &ledger.journal,
        b"complete-acquire-rebind",
        reservation_digest,
        MAXIMUM_ACQUIRE_COMPLETION_BYTES,
    )?;
    Ok(ProviderAdmissionDispositionV1::AcquireRebind(
        DurableAcquireRebindPermitV1 {
            holder_id: acquisition.holder.authority_id(),
            session_binding: committed_session_binding,
            acquisition_id: acquisition.acquisition_id,
            attempt_digest: attempt.attempt_digest,
            pending_claim: matches!(
                acquisition.state,
                ProviderAcquisitionStateV1::Applying | ProviderAcquisitionStateV1::Pending
            ),
            reservation_digest,
            journal_snapshot,
            completion_capacity,
            signing_authorization,
        },
    ))
}

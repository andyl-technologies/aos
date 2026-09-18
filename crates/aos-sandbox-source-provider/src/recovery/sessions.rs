//! Immutable session, request, and exact sequence-reachability validation.

use super::*;

pub(super) fn validate_sessions(
    authority: &crate::model::AuthorityHeadRecordV1,
    sessions: &BTreeMap<([u8; 16], [u8; 16]), crate::model::HolderSessionHeadRecordV1>,
    history: &BTreeMap<([u8; 16], [u8; 16], ObjectDigest), crate::model::HolderSessionHeadRecordV1>,
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
) -> Result<(), ProviderLedgerError> {
    let mut global_bindings = BTreeSet::new();
    let mut holder_generations = BTreeSet::new();
    let mut holder_request_identities = BTreeSet::new();
    if history
        .keys()
        .any(|(_, _, binding)| !global_bindings.insert(*binding))
    {
        return Err(ProviderLedgerError::Corrupt(
            "globally duplicate session binding",
        ));
    }
    for attempt in attempts.values() {
        validate_retained_request(attempt)?;
        if !holder_request_identities.insert((
            attempt.provider.authority_id(),
            attempt.holder.authority_id(),
            attempt.method as u8,
            attempt.request_id,
        )) {
            // Request identity is holder-authority scoped. Signing-key or
            // session rotation must not create a second retained meaning.
            return Err(ProviderLedgerError::Corrupt(
                "duplicate holder request identity",
            ));
        }
        if let Some(predecessor_digest) = attempt.recovery_predecessor_attempt_digest {
            let predecessor_binding = attempt
                .recovery_predecessor_session_binding
                .ok_or(ProviderLedgerError::Corrupt("recovery bridge shape"))?;
            let predecessor = attempts
                .values()
                .find(|candidate| candidate.attempt_digest == predecessor_digest)
                .ok_or(ProviderLedgerError::Corrupt(
                    "recovery bridge predecessor attempt",
                ))?;
            let predecessor_session = history
                .get(&(
                    attempt.provider.authority_id(),
                    attempt.holder.authority_id(),
                    predecessor_binding,
                ))
                .ok_or(ProviderLedgerError::Corrupt(
                    "recovery bridge predecessor session",
                ))?;
            let fence_domain = match attempt.recovery_fence_class {
                1 => b"execution-death".as_slice(),
                2 => b"durable-revocation".as_slice(),
                3 => b"pending-descriptor-not-authorized".as_slice(),
                _ => return Err(ProviderLedgerError::Corrupt("recovery fence class")),
            };
            let expected_fence = crate::recovery_bridge::recovery_fence_digest(
                fence_domain,
                predecessor_session,
                attempt.session_binding,
                attempt.recovery_revocation_generation,
                attempt.recovery_revocation_digest,
            );
            if attempt.recovery_fence_digest != Some(expected_fence)
                || attempt.session_binding == predecessor_binding
                || predecessor.session_binding != predecessor_binding
                || predecessor.provider != attempt.provider
                || predecessor.holder != attempt.holder
                || predecessor.method != attempt.method
                || attempt.recovery_revocation_generation > authority.revocation_generation
                || (attempt.recovery_revocation_generation == authority.revocation_generation
                    && attempt.recovery_revocation_digest != authority.revocation_digest)
                || (attempt.recovery_fence_class == 2
                    && attempt.recovery_revocation_generation
                        <= predecessor_session.revocation_generation)
                || (attempt.recovery_fence_class == 3
                    && (predecessor.status
                        != Some(aos_sandbox_source_provider_protocol::SourceProviderStatus::Pending)
                        || predecessor.descriptor_commitment
                            != aos_sandbox_source_provider_protocol::empty_descriptor_set_commitment_v1()))
            {
                return Err(ProviderLedgerError::Corrupt(
                    "recovery continuation cross-link",
                ));
            }
        }
    }
    for session in sessions.values() {
        let mut request_sequences = BTreeSet::new();
        let mut response_sequences = BTreeSet::new();
        if session.provider.authority_id() != authority.provider.authority_id()
            || session.acquisition_sequence_floor == 0
            || session.next_acquisition_sequence < session.acquisition_sequence_floor
        {
            return Err(ProviderLedgerError::Corrupt(
                "session provider identity mismatch",
            ));
        }
        let immutable = history
            .get(&(
                session.provider.authority_id(),
                session.holder.authority_id(),
                session.session_binding,
            ))
            .ok_or(ProviderLedgerError::Corrupt(
                "current session has no immutable transcript",
            ))?;
        if session != immutable {
            return Err(ProviderLedgerError::Corrupt(
                "current session/history head mismatch",
            ));
        }
        let pending = attempts.values().filter(|attempt| {
            attempt.provider.authority_id() == session.provider.authority_id()
                && attempt.holder.authority_id() == session.holder.authority_id()
                && attempt.session_binding == session.session_binding
                && attempt.state == ProviderAttemptStateV1::Reserved
        });
        let pending_digests: Vec<ObjectDigest> =
            pending.map(|attempt| attempt.attempt_digest).collect();
        match (session.pending_attempt_digest, pending_digests.as_slice()) {
            (None, []) => {}
            (Some(expected), [actual]) if expected == *actual => {
                let attempt = attempts
                    .values()
                    .find(|candidate| candidate.attempt_digest == expected)
                    .ok_or(ProviderLedgerError::Corrupt("missing pending attempt"))?;
                if attempt.request_sequence.checked_add(1) != Some(session.next_request_sequence) {
                    return Err(ProviderLedgerError::Corrupt("pending sequence head"));
                }
            }
            _ => return Err(ProviderLedgerError::Corrupt("session pending graph")),
        }
        if let Some(last_completed) = session.last_completed_attempt_digest {
            let matching = attempts
                .values()
                .filter(|attempt| {
                    attempt.attempt_digest == last_completed
                        && attempt.state == ProviderAttemptStateV1::Completed
                        && attempt.provider == session.provider
                        && attempt.holder == session.holder
                })
                .count();
            if matching != 1 {
                return Err(ProviderLedgerError::Corrupt("session last-completed graph"));
            }
        }
        for attempt in attempts.values().filter(|attempt| {
            attempt.provider.authority_id() == session.provider.authority_id()
                && attempt.holder.authority_id() == session.holder.authority_id()
                && attempt.session_binding == session.session_binding
        }) {
            if (attempt.request_sequence < session.request_sequence_floor
                || attempt
                    .response_sequence
                    .is_some_and(|sequence| sequence < session.response_sequence_floor))
                && attempt.state != ProviderAttemptStateV1::Retired
            {
                return Err(ProviderLedgerError::Corrupt(
                    "live artifact below current session floor",
                ));
            }
            if attempt.root_record_signer != session.signers[1]
                || attempt.signer_set_commitment != session.signer_set_commitment
                || attempt.root_process_instance != session.root_process_instance
                || attempt.provider_process_instance != session.provider_process_instance
                || attempt.request_sequence >= session.next_request_sequence
            {
                return Err(ProviderLedgerError::Corrupt("attempt/session cross-link"));
            }
            if attempt.request_sequence >= session.request_sequence_floor
                && !request_sequences.insert(attempt.request_sequence)
            {
                return Err(ProviderLedgerError::Corrupt("duplicate request sequence"));
            }
            if attempt.state == ProviderAttemptStateV1::Completed {
                let signed_status = completed_status(attempt)?;
                let status = signed_status.subject();
                if signed_status.signer() != &session.signers[3]
                    || status.method() != attempt.method
                    || status.request_id() != attempt.request_id
                    || status.signed_request_digest() != attempt.signed_request_digest
                    || Some(status.status()) != attempt.status
                    || status.provider_process_instance() != attempt.provider_process_instance
                    || status.session_binding() != attempt.session_binding
                    || Some(status.result_digest()) != attempt.result_digest
                    || status.descriptor_commitment() != attempt.descriptor_commitment
                    || status.response_sequence() >= session.next_response_sequence
                    || (status.response_sequence() >= session.response_sequence_floor
                        && !response_sequences.insert(status.response_sequence()))
                {
                    return Err(ProviderLedgerError::Corrupt("response/session cross-link"));
                }
            }
        }
        if !exact_sequence_reachability(
            &request_sequences,
            session.request_sequence_floor,
            session.next_request_sequence,
        ) || !exact_sequence_reachability(
            &response_sequences,
            session.response_sequence_floor,
            session.next_response_sequence,
        ) {
            return Err(ProviderLedgerError::Corrupt(
                "session sequence reachability",
            ));
        }
    }
    if attempts.values().any(|attempt| {
        !history.contains_key(&(
            attempt.provider.authority_id(),
            attempt.holder.authority_id(),
            attempt.session_binding,
        ))
    }) {
        return Err(ProviderLedgerError::Corrupt(
            "attempt without immutable holder session",
        ));
    }
    for (identity, immutable) in history {
        if identity
            != &(
                immutable.provider.authority_id(),
                immutable.holder.authority_id(),
                immutable.session_binding,
            )
            || immutable.session_generation == 0
            || !holder_generations.insert((identity.0, identity.1, immutable.session_generation))
            || (immutable.session_generation == 1
                && (immutable.predecessor_session_binding.is_some()
                    || immutable.supersession_evidence_digest.is_some()))
            || (immutable.session_generation > 1
                && (immutable.predecessor_session_binding.is_none()
                    || immutable.supersession_evidence_digest.is_none()))
        {
            return Err(ProviderLedgerError::Corrupt(
                "immutable session lineage shape",
            ));
        }
        let session_attempts: Vec<_> = attempts
            .values()
            .filter(|attempt| {
                attempt.provider.authority_id() == identity.0
                    && attempt.holder.authority_id() == identity.1
                    && attempt.session_binding == identity.2
            })
            .collect();
        if session_attempts.is_empty()
            && (immutable.request_sequence_floor != immutable.next_request_sequence
                || immutable.response_sequence_floor != immutable.next_response_sequence
                || immutable.pending_attempt_digest.is_some()
                || immutable.last_completed_attempt_digest.is_some())
        {
            return Err(ProviderLedgerError::Corrupt(
                "immutable session without admitted attempt",
            ));
        }
        if session_attempts.iter().any(|attempt| {
            attempt.provider != immutable.provider
                || attempt.holder != immutable.holder
                || attempt.root_record_signer != immutable.signers[1]
                || attempt.signer_set_commitment != immutable.signer_set_commitment
                || attempt.root_process_instance != immutable.root_process_instance
                || attempt.provider_process_instance != immutable.provider_process_instance
        }) {
            return Err(ProviderLedgerError::Corrupt(
                "historical attempt/session cross-link",
            ));
        }
        if immutable.session_generation > 1 {
            let predecessor = immutable
                .predecessor_session_binding
                .ok_or(ProviderLedgerError::Corrupt("missing session predecessor"))?;
            let predecessor_record = history
                .get(&(identity.0, identity.1, predecessor))
                .ok_or(ProviderLedgerError::Corrupt("missing session predecessor"))?;
            if predecessor_record.session_generation.checked_add(1)
                != Some(immutable.session_generation)
                || attempts
                    .values()
                    .filter(|attempt| {
                        attempt.provider.authority_id() == identity.0
                            && attempt.holder.authority_id() == identity.1
                            && attempt.session_binding == predecessor
                    })
                    .any(|attempt| attempt.state == ProviderAttemptStateV1::Reserved)
            {
                return Err(ProviderLedgerError::Corrupt("superseded session lineage"));
            }
            let expected_supersession =
                session_supersession_digest(predecessor_record, immutable, attempts);
            if immutable.supersession_evidence_digest != Some(expected_supersession) {
                return Err(ProviderLedgerError::Corrupt(
                    "session supersession evidence commitment",
                ));
            }
        }
        if session_attempts.iter().any(|attempt| {
            (attempt.request_sequence < immutable.request_sequence_floor
                || attempt
                    .response_sequence
                    .is_some_and(|sequence| sequence < immutable.response_sequence_floor))
                && attempt.state != ProviderAttemptStateV1::Retired
        }) {
            return Err(ProviderLedgerError::Corrupt(
                "live historical artifact below session floor",
            ));
        }
        let request_sequences: BTreeSet<_> = session_attempts
            .iter()
            .filter(|attempt| attempt.request_sequence >= immutable.request_sequence_floor)
            .map(|attempt| attempt.request_sequence)
            .collect();
        let response_sequences: BTreeSet<_> = session_attempts
            .iter()
            .filter(|attempt| {
                attempt
                    .response_sequence
                    .is_some_and(|sequence| sequence >= immutable.response_sequence_floor)
            })
            .map(|attempt| {
                if attempt.state == ProviderAttemptStateV1::Completed {
                    let status = completed_status(attempt)?;
                    if status.signer() != &immutable.signers[3] {
                        return Err(ProviderLedgerError::Corrupt(
                            "historical response signer/session cross-link",
                        ));
                    }
                }
                attempt
                    .response_sequence
                    .ok_or(ProviderLedgerError::Corrupt(
                        "historical response sequence tombstone",
                    ))
            })
            .collect::<Result<_, _>>()?;
        if !contiguous_from_floor(
            &request_sequences,
            immutable.request_sequence_floor,
            immutable.next_request_sequence,
        ) || !contiguous_from_floor(
            &response_sequences,
            immutable.response_sequence_floor,
            immutable.next_response_sequence,
        ) {
            return Err(ProviderLedgerError::Corrupt(
                "historical session sequence reachability",
            ));
        }
    }
    for session in sessions.values() {
        let maximum_generation = history
            .values()
            .filter(|candidate| {
                candidate.provider.authority_id() == session.provider.authority_id()
                    && candidate.holder.authority_id() == session.holder.authority_id()
            })
            .map(|candidate| candidate.session_generation)
            .max()
            .ok_or(ProviderLedgerError::Corrupt("missing session generation"))?;
        if maximum_generation != session.session_generation {
            return Err(ProviderLedgerError::Corrupt(
                "holder head does not reach newest session",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_retained_request(
    attempt: &crate::model::AttemptRecordV1,
) -> Result<(), ProviderLedgerError> {
    if attempt.state == ProviderAttemptStateV1::Retired && attempt.signed_request.is_empty() {
        return Ok(());
    }
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| ProviderLedgerError::Corrupt("retained signed request"))?;
    if signed.signer() != &attempt.root_record_signer
        || signed.method() != attempt.method
        || source_provider_request_attempt_digest_v1(
            signed.signer(),
            signed.method(),
            attempt.request_id,
        ) != attempt.attempt_digest
        || attempt.verified_at_seconds < 0
        || attempt.deadline_seconds <= attempt.verified_at_seconds
        || attempt.current_valid_until_seconds <= attempt.verified_at_seconds
        || attempt.deadline_seconds > attempt.current_valid_until_seconds
        || attempt.proof_class_capabilities == 0
        || attempt.proof_class_capabilities & !0x0f != 0
    {
        return Err(ProviderLedgerError::Corrupt(
            "retained request authority fields",
        ));
    }
    let common_matches = |session_binding: ObjectDigest,
                          sequence: u64,
                          request_id: [u8; 16],
                          holder_id: [u8; 16],
                          holder_generation: u64,
                          holder_digest: ObjectDigest,
                          deadline_seconds: i64| {
        session_binding == attempt.session_binding
            && sequence == attempt.request_sequence
            && request_id == attempt.request_id
            && holder_id == attempt.holder.authority_id()
            && holder_generation == attempt.holder.authority_generation()
            && holder_digest == attempt.holder.authority_digest()
            && deadline_seconds == attempt.deadline_seconds
    };
    match attempt.method {
        SourceProviderMethod::Acquire => {
            let request = decode_acquire_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Corrupt("retained Acquire request"))?;
            if !common_matches(
                request.session_binding(),
                request.sequence(),
                request.request_id(),
                request.holder_authority_id(),
                request.holder_generation(),
                request.holder_authority_digest(),
                request.deadline_seconds(),
            ) || digest_acquire_request(&request) != attempt.typed_request_digest
                || (request.recursive() && !attempt.supports_recursive)
                || (request.kernel_coupled() && !attempt.supports_kernel_coupled)
            {
                return Err(ProviderLedgerError::Corrupt(
                    "retained Acquire request cross-link",
                ));
            }
        }
        SourceProviderMethod::Release => {
            let request = decode_release_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Corrupt("retained Release request"))?;
            if !common_matches(
                request.session_binding(),
                request.sequence(),
                request.request_id(),
                request.holder_authority_id(),
                request.holder_generation(),
                request.holder_authority_digest(),
                request.deadline_seconds(),
            ) || digest_release_request(&request) != attempt.typed_request_digest
                || source_provider_release_intent_digest_v1(&request)
                    != attempt.operation_intent_digest
            {
                return Err(ProviderLedgerError::Corrupt(
                    "retained Release request cross-link",
                ));
            }
        }
        SourceProviderMethod::Inventory => {
            let request = decode_inventory_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Corrupt("retained Inventory request"))?;
            if !common_matches(
                request.session_binding(),
                request.sequence(),
                request.request_id(),
                request.holder_authority_id(),
                request.holder_generation(),
                request.holder_authority_digest(),
                request.deadline_seconds(),
            ) || digest_inventory_request(&request) != attempt.typed_request_digest
                || source_provider_inventory_intent_digest_v1(&request)
                    != attempt.operation_intent_digest
            {
                return Err(ProviderLedgerError::Corrupt(
                    "retained Inventory request cross-link",
                ));
            }
        }
        SourceProviderMethod::Hello => {
            return Err(ProviderLedgerError::Corrupt("retained Hello attempt"));
        }
    }
    Ok(())
}

pub(super) fn session_supersession_digest(
    previous: &crate::model::HolderSessionHeadRecordV1,
    replacement: &crate::model::HolderSessionHeadRecordV1,
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    let recovery_retirement = previous.pending_attempt_digest.is_some_and(|pending| {
        attempts.values().any(|attempt| {
            attempt.attempt_digest == pending && attempt.state == ProviderAttemptStateV1::Retired
        })
    });
    hasher.update(b"aos.sandbox.source-provider.session-recovery-death.v1\0");
    hasher.update(previous.provider.authority_id());
    hasher.update(previous.holder.authority_id());
    hasher.update(previous.session_binding.as_bytes());
    hasher.update(replacement.session_binding.as_bytes());
    hasher.update(previous.boot_id);
    hasher.update(previous.provider_process_id.to_be_bytes());
    hasher.update(previous.provider_start_time_ticks.to_be_bytes());
    hasher.update(previous.provider_process_instance);
    hasher.update(previous.provider_execution_commitment.as_bytes());
    let death_digest = ObjectDigest::from_bytes(hasher.finalize_reset().into());
    if recovery_retirement || replacement.supersession_evidence_digest == Some(death_digest) {
        return death_digest;
    }
    if replacement.revocation_generation > previous.revocation_generation {
        hasher.update(b"aos.sandbox.source-provider.session-revocation-fence.v1\0");
        hasher.update(previous.provider.authority_id());
        hasher.update(previous.holder.authority_id());
        hasher.update(previous.session_binding.as_bytes());
        hasher.update(previous.revocation_generation.to_be_bytes());
        hasher.update(replacement.revocation_generation.to_be_bytes());
        hasher.update(replacement.revocation_digest.as_bytes());
    } else {
        hasher.update(b"aos.sandbox.source-provider.session-supersession.v1\0");
        hasher.update(previous.provider.authority_id());
        hasher.update(previous.holder.authority_id());
        hasher.update(previous.session_binding.as_bytes());
        hasher.update(replacement.session_binding.as_bytes());
        hasher.update(previous.root_process_instance);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn exact_sequence_reachability(
    sequences: &BTreeSet<u64>,
    floor: u64,
    next: u64,
) -> bool {
    if floor == 0
        || next == 0
        || next == u64::MAX
        || floor > next
        || sequences.len() as u64 != next - floor
    {
        return false;
    }
    sequences
        .iter()
        .copied()
        .enumerate()
        .all(|(index, sequence)| sequence == index as u64 + floor)
}

pub(super) fn contiguous_from_floor(sequences: &BTreeSet<u64>, floor: u64, next: u64) -> bool {
    floor > 0
        && floor <= next
        && sequences.len() as u64 == next - floor
        && sequences
            .iter()
            .copied()
            .enumerate()
            .all(|(index, sequence)| sequence == index as u64 + floor)
}

pub(super) fn completed_status(
    attempt: &crate::model::AttemptRecordV1,
) -> Result<SignedSourceProviderStatusV1, ProviderLedgerError> {
    match attempt.method {
        SourceProviderMethod::Acquire => decode_acquire_response(&attempt.completed_response)
            .map(|response| response.signed_status().clone())
            .map_err(|_| ProviderLedgerError::Corrupt("retained Acquire response")),
        SourceProviderMethod::Release => decode_release_response(&attempt.completed_response)
            .map(|response| response.signed_status().clone())
            .map_err(|_| ProviderLedgerError::Corrupt("retained Release response")),
        SourceProviderMethod::Inventory => decode_inventory_response(&attempt.completed_response)
            .map(|response| response.signed_status().clone())
            .map_err(|_| ProviderLedgerError::Corrupt("retained Inventory response")),
        SourceProviderMethod::Hello => Err(ProviderLedgerError::Corrupt("retained Hello response")),
    }
}

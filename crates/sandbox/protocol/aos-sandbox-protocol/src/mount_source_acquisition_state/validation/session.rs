//! Holder-sequence, immutable-session, and session-reachability validation.

use super::*;

pub(super) fn validate_holder_sequence(sequence: &HolderSequenceV2) -> Result<()> {
    if sequence.revision == 0
        || sequence.holder_authority_id == [0; 16]
        || sequence.last_allocated_acquisition_sequence == 0
        || sequence.next_acquisition_sequence
            != sequence
                .last_allocated_acquisition_sequence
                .checked_add(1)
                .ok_or_else(|| state_error("holder acquisition sequence exhausted"))?
        || sequence.record_digest == [0; 32]
    {
        return Err(state_error("AOSMSA02 holder sequence is invalid"));
    }
    let stored = StoredRecordV2::HolderSequence {
        value: sequence.clone(),
    };
    if record_digest(&stored)? != sequence.record_digest {
        return Err(state_error("AOSMSA02 holder sequence digest differs"));
    }
    Ok(())
}

pub(super) fn validate_holder_sequence_graph(table: &SourceAcquisitionTableV2) -> Result<()> {
    let mut allocated = BTreeMap::<[u8; 16], BTreeSet<u64>>::new();
    for row in table.acquisitions.values() {
        allocated
            .entry(row.provider_acquisition.holder_authority_id)
            .or_default()
            .insert(row.provider_acquisition.acquisition_sequence);
    }
    if allocated.len() != table.holder_sequences.len() {
        return Err(state_error("holder sequence ownership is incomplete"));
    }
    for (holder_id, sequences) in allocated {
        let holder = table
            .holder_sequences
            .get(&holder_id)
            .ok_or_else(|| state_error("acquisition lacks its holder sequence floor"))?;
        let expected_count = usize::try_from(holder.last_allocated_acquisition_sequence)
            .map_err(|_| state_error("holder sequence floor exceeds usize"))?;
        if sequences.len() != expected_count
            || sequences.first().copied() != Some(1)
            || sequences.last().copied() != Some(holder.last_allocated_acquisition_sequence)
        {
            return Err(state_error(
                "holder acquisition sequence has a gap or reuse",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_session_reachability(table: &SourceAcquisitionTableV2) -> Result<()> {
    let mut reachable = BTreeSet::new();
    for head in table.provider_heads.values() {
        let mut current = Some(head.current_session_id);
        let mut scope_chain = BTreeSet::new();
        while let Some(session_id) = current {
            if !scope_chain.insert(session_id) || !reachable.insert(session_id) {
                return Err(state_error(
                    "provider session belongs to a cyclic or aliased head chain",
                ));
            }
            let session = table
                .provider_sessions
                .get(&session_id)
                .ok_or_else(|| state_error("provider head session chain is missing"))?;
            if session.scope != head.scope {
                return Err(state_error("provider session chain changes stable scope"));
            }
            current = session.predecessor_session_id;
        }
    }
    for attempt in table.provider_attempts.values() {
        if !reachable.contains(&attempt.session_id) {
            return Err(state_error(
                "provider attempt references a session outside its head chain",
            ));
        }
    }
    for session in table.provider_sessions.values() {
        if !reachable.contains(&session.session_id) {
            return Err(state_error(
                "provider session is unreachable from durable state",
            ));
        }
        if let Some(witness) = &session.barrier_idle_replacement {
            let predecessor = table
                .provider_sessions
                .get(&witness.predecessor_head.current_session_id)
                .ok_or_else(|| state_error("barrier-idle predecessor session is missing"))?;
            let root = resolve_historical_attempt(table, witness.root_attempt)?;
            if session.predecessor_session_id != Some(predecessor.session_id)
                || predecessor.scope != session.scope
                || witness.root_attempt.revision != 2
                || !matches!(
                    root.state,
                    ProviderAttemptStateV2::AbandonedIndeterminate {
                        resolution: None,
                        ..
                    }
                )
                || root.scope != session.scope
                || witness.predecessor_head.scope != session.scope
                || witness.predecessor_head.current_session_id != predecessor.session_id
                || witness.predecessor_head.current_session_record_digest
                    != predecessor.record_digest
                || witness.predecessor_head.pending_attempt.is_some()
                || witness.predecessor_head.next_request_sequence
                    != witness.predecessor_head.next_response_sequence
                || witness
                    .predecessor_head
                    .recovery_barrier
                    .as_ref()
                    .is_none_or(|barrier| {
                        barrier.root_attempt != witness.root_attempt
                            || barrier.required_session_id != predecessor.session_id
                            || barrier.recovery_inventory_tail.is_some()
                            || barrier.replacement_count.checked_add(1)
                                != Some(witness.replacement_count)
                    })
                || record_digest(&StoredRecordV2::ProviderHead {
                    value: *witness.predecessor_head.clone(),
                })? != witness.predecessor_head.record_digest
                || !barrier_idle_observation_matches(
                    &witness.predecessor_observation,
                    predecessor,
                    session,
                )?
                || session_successor_distance(table, root.session_id, session.session_id)?
                    != witness.replacement_count
            {
                return Err(state_error("barrier-idle session witness is inconsistent"));
            }
        }
    }
    Ok(())
}

fn barrier_idle_observation_matches(
    observation: &BarrierIdlePredecessorObservationV2,
    predecessor: &SourceProviderSessionV2,
    successor: &SourceProviderSessionV2,
) -> Result<bool> {
    Ok(match observation {
        BarrierIdlePredecessorObservationV2::Dead { execution } => {
            execution.old_session_id == predecessor.session_id
                && execution.old_session_record_digest == predecessor.record_digest
                && execution.node_id == predecessor.node_id
                && execution.process_execution_digest
                    == predecessor.provider_execution.process_execution_digest
                && execution.old_kernel_boot_id == predecessor.kernel_boot_id
                && execution.provider_process_instance == predecessor.provider_process_instance
                && execution.observed_kernel_boot_id == successor.kernel_boot_id
                && match execution.proof_kind {
                    DeadProviderExecutionProofKindV2::PidfdExited => {
                        execution.observed_kernel_boot_id == predecessor.kernel_boot_id
                    }
                    DeadProviderExecutionProofKindV2::BootReplaced => {
                        execution.observed_kernel_boot_id != predecessor.kernel_boot_id
                    }
                }
                && execution.death_evidence_digest == death_digest(execution)?
        }
        BarrierIdlePredecessorObservationV2::Live => live_barrier_predecessor_matches(
            predecessor.node_id,
            predecessor.kernel_boot_id,
            predecessor.provider_process_instance,
            &predecessor.provider_execution,
            successor.node_id,
            successor.kernel_boot_id,
            successor.provider_process_instance,
            &successor.provider_execution,
        ),
    })
}

#[allow(clippy::too_many_arguments)]
fn live_barrier_predecessor_matches(
    predecessor_node: [u8; 16],
    predecessor_boot: [u8; 16],
    predecessor_instance: [u8; 16],
    predecessor_execution: &ProviderExecutionSnapshotV2,
    successor_node: [u8; 16],
    successor_boot: [u8; 16],
    successor_instance: [u8; 16],
    successor_execution: &ProviderExecutionSnapshotV2,
) -> bool {
    predecessor_node == successor_node
        && predecessor_boot == successor_boot
        && predecessor_instance == successor_instance
        && predecessor_execution == successor_execution
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_barrier_successor_rejects_execution_and_session_substitution() {
        let execution = ProviderExecutionSnapshotV2 {
            pid: 11,
            tgid: 11,
            ppid: 1,
            start_time_ticks: 22,
            cgroup_id: 33,
            real_uid: 44,
            effective_uid: 44,
            saved_uid: 44,
            filesystem_uid: 44,
            real_gid: 55,
            effective_gid: 55,
            saved_gid: 55,
            filesystem_gid: 55,
            process_execution_digest: [66; 32],
        };
        let matches = |node, boot, instance, candidate: &ProviderExecutionSnapshotV2| {
            live_barrier_predecessor_matches(
                [1; 16], [2; 16], [3; 16], &execution, node, boot, instance, candidate,
            )
        };

        assert!(matches([1; 16], [2; 16], [3; 16], &execution));
        assert!(!matches([9; 16], [2; 16], [3; 16], &execution));
        assert!(!matches([1; 16], [9; 16], [3; 16], &execution));
        assert!(!matches([1; 16], [2; 16], [9; 16], &execution));
        assert!(!matches(
            [1; 16],
            [2; 16],
            [3; 16],
            &ProviderExecutionSnapshotV2 {
                start_time_ticks: 23,
                ..execution
            },
        ));
    }
}

pub(super) fn validate_session(session: &SourceProviderSessionV2) -> Result<()> {
    if session.revision != 1
        || session.session_id == [0; 32]
        || session.session_id != session_id(session)
        || !valid_scope(session.scope)
        || session.node_id == [0; 16]
        || session.kernel_boot_id == [0; 16]
        || session.root_mount_authority_generation == 0
        || session.root_mount_authority_digest == [0; 32]
        || session.provider_authority_generation == 0
        || session.provider_authority_digest == [0; 32]
        || session.route_generation == 0
        || session.route_digest == [0; 32]
        || session.authenticated_at_seconds < 0
        || session.current_valid_until_seconds <= session.authenticated_at_seconds
        || session.trusted_clock_evidence_digest == [0; 32]
        || session.trust_generation == 0
        || session.trust_digest == [0; 32]
        || session.revocation_generation == 0
        || session.revocation_digest == [0; 32]
        || session.root_mount_process_instance == [0; 16]
        || session.provider_process_instance == [0; 16]
        || session.record_digest == [0; 32]
        || (session.barrier_idle_replacement.is_some() && session.predecessor_session_id.is_none())
    {
        return Err(state_error(
            "SourceProvider session has an invalid scalar field",
        ));
    }
    if !session.negotiated_capabilities.signed_lease_receipts
        || !session.negotiated_capabilities.separated_signing_roles
        || session.negotiated_capabilities.proof_class_capabilities == 0
        || session.negotiated_capabilities.proof_class_capabilities & !0b1111 != 0
    {
        return Err(state_error(
            "SourceProvider session lacks mandatory capabilities",
        ));
    }
    validate_authority_and_signer_snapshots(session)?;
    validate_execution(session)?;
    validate_session_checkpoint(session)
}

pub(super) fn validate_authority_and_signer_snapshots(
    session: &SourceProviderSessionV2,
) -> Result<()> {
    let root = &session.authority_trust[0];
    let provider = &session.authority_trust[1];
    if root.authority_id != session.scope.holder_authority_id
        || root.authority_generation != session.root_mount_authority_generation
        || root.authority_digest != session.root_mount_authority_digest
        || provider.authority_id != session.scope.provider_authority_id
        || provider.authority_generation != session.provider_authority_generation
        || provider.authority_digest != session.provider_authority_digest
        || root.state != AuthorityAdmissionStateV2::Trusted
        || provider.state != AuthorityAdmissionStateV2::Trusted
        || !interval_contains(
            root.valid_from_seconds,
            root.valid_until_seconds,
            session.authenticated_at_seconds,
        )
        || !interval_contains(
            provider.valid_from_seconds,
            provider.valid_until_seconds,
            session.authenticated_at_seconds,
        )
    {
        return Err(state_error(
            "SourceProvider authority-trust snapshot is inconsistent",
        ));
    }

    let mut key_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut current_valid_until = root.valid_until_seconds.min(provider.valid_until_seconds);
    for signer in &session.signers {
        if signer.authority_id == [0; 16]
            || signer.authority_generation == 0
            || signer.authority_digest == [0; 32]
            || signer.key_id == [0; 16]
            || signer.key_generation == 0
            || signer.public_key == [0; 32]
            || signer.public_key_fingerprint == [0; 32]
            || signer.authority_state != AuthorityAdmissionStateV2::Trusted
            || signer.key_state != KeyAdmissionStateV2::Eligible
            || signer.superseded_by_key_generation != 0
            || !interval_contains(
                signer.authority_valid_from_seconds,
                signer.authority_valid_until_seconds,
                session.authenticated_at_seconds,
            )
            || !interval_contains(
                signer.key_valid_from_seconds,
                signer.key_valid_until_seconds,
                session.authenticated_at_seconds,
            )
            || !key_ids.insert(signer.key_id)
            || !public_keys.insert(signer.public_key)
            || !fingerprints.insert(signer.public_key_fingerprint)
        {
            return Err(state_error(
                "SourceProvider signer snapshot is invalid or aliased",
            ));
        }
        let authority = match signer.role {
            SignerRoleV2::RootMountHello | SignerRoleV2::RootMountRecord => root,
            SignerRoleV2::ProviderHello | SignerRoleV2::ProviderOutcome => provider,
        };
        if signer.authority_id != authority.authority_id
            || signer.authority_generation != authority.authority_generation
            || signer.authority_digest != authority.authority_digest
            || signer.authority_valid_from_seconds != authority.valid_from_seconds
            || signer.authority_valid_until_seconds != authority.valid_until_seconds
        {
            return Err(state_error(
                "SourceProvider signer authority is inconsistent",
            ));
        }
        current_valid_until = current_valid_until
            .min(signer.authority_valid_until_seconds)
            .min(signer.key_valid_until_seconds);
    }
    if session.current_valid_until_seconds != current_valid_until {
        return Err(state_error(
            "SourceProvider session current-valid-until does not reproduce",
        ));
    }
    Ok(())
}

pub(super) fn validate_execution(session: &SourceProviderSessionV2) -> Result<()> {
    let execution = &session.provider_execution;
    let writer = &session.actual_writer_root_mount_process;
    if execution.pid == 0
        || execution.tgid == 0
        || execution.ppid == 0
        || execution.start_time_ticks == 0
        || execution.cgroup_id == 0
        || execution.process_execution_digest == [0; 32]
        || execution.process_execution_digest != execution_digest(session)?
        || writer.tgid == 0
        || writer.start_time_ticks == 0
        || writer.cgroup_digest == [0; 32]
    {
        return Err(state_error("SourceProvider execution snapshot is invalid"));
    }
    Ok(())
}

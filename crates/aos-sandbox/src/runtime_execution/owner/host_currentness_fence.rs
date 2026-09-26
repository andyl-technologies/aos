//! HostState/Effect fence join under the fixed owner lock order.
//!
//! The peer writer is claimed before the Effect writer. A cold owner claim
//! accepts either both exact fences or neither; a crash between their appends
//! is quarantined until its original signed request is reauthenticated. The pair can
//! detect rollback of either journal alone, not coordinated rollback of both.

use super::*;
use crate::journal::host_currentness_fence::cut_v1;

pub(super) fn load_host_currentness_fence_v1(
    authority: &ProtectedJournalAuthority<'_>,
    protected_sequence: u64,
) -> Result<Option<HostCurrentnessFenceV1>, DormantRuntimeExecutionOwnerErrorV1> {
    let snapshot = authority.snapshot()?;
    if snapshot.sequence() != protected_sequence {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let Some(bytes) = authority.get(HOST_CURRENTNESS_FENCE_KEY)? else {
        return Ok(None);
    };
    let fence = HostCurrentnessFenceV1::decode(bytes)?;
    let actual_cut = cut_v1(
        authority.records()?,
        fence.store_binding,
        fence.pre_hold_epoch,
        true,
    )?;
    authority.validate_snapshot_for_effect(&snapshot)?;
    if fence.commit_sequence.checked_add(1) != Some(protected_sequence)
        || actual_cut != fence.pre_hold_cut
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    Ok(Some(fence))
}

pub(crate) fn validate_host_currentness_pair_v1(
    hoststate: Option<HostCurrentnessFenceV1>,
    effect: Option<HostExecutionFenceV1>,
    store_binding: ObjectDigest,
) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
    match (hoststate, effect) {
        (None, None) => Ok(()),
        (Some(hoststate), Some(effect))
            if hoststate.store_binding == store_binding
                && effect.store_binding == store_binding
                && hoststate.effect_fence_digest
                    == ObjectDigest::from_bytes(Sha256::digest(effect.encode()?).into()) =>
        {
            Ok(())
        }
        _ => Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness),
    }
}

/// Holds only HostState and Effect for recovery of an Effect-first crash.
///
/// This claim has no execution, agent, lifecycle, or Apply authority. It can
/// complete the HostState half only after the caller independently rejoins
/// the original signed request and current HostState completed handoff.
pub struct HostEffectFenceRecoveryClaimV1<'owner> {
    peer_authority: ProtectedJournalAuthority<'owner>,
    execution: JournalRuntimeExecutionStoreV1<'owner>,
    protected_sequence: u64,
    store_binding: ObjectDigest,
    hoststate_cut: ObjectDigest,
    effect_fence: HostExecutionFenceV1,
    currentness: AdmissionCurrentnessV1,
    host_verifier: ProtectedRuntimeHostVerifierV1,
}

impl DormantRuntimeExecutionOwnerV1 {
    /// Claims the exact one-sided Effect fence for recovery only.
    ///
    /// # Errors
    ///
    /// Rejects absent or changed Host currentness, a paired or missing fence,
    /// a rolled-back Effect store, or malformed protected replay.
    pub fn claim_effect_fence_recovery_v1(
        &mut self,
    ) -> Result<HostEffectFenceRecoveryClaimV1<'_>, DormantRuntimeExecutionOwnerErrorV1> {
        let peer_authority = self
            .peer_journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        let protected_sequence = peer_authority.snapshot()?.sequence();
        if load_host_currentness_fence_v1(&peer_authority, protected_sequence)?.is_some() {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        let peer = peer_authority
            .get(PEER_CURRENT_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?;
        let currentness = peer_authority
            .get(CURRENTNESS_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?;
        let capabilities = peer_authority
            .get(CAPABILITIES_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?;
        let host_evidence = peer_authority
            .get(HOST_EVIDENCE_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?;
        let plan_catalog = peer_authority
            .get(PLAN_CATALOG_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?;
        if peer_authority
            .records()?
            .any(|(key, _)| !crate::journal::host_currentness_fence::OWNER_KEYS.contains(&key))
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let resolved = resolve_currentness(
            protected_sequence,
            peer,
            currentness,
            capabilities,
            host_evidence,
            plan_catalog,
        )?;
        let execution = JournalRuntimeExecutionStoreV1::claim(
            &mut self.execution_journal,
            resolved.execution_store_binding,
            ProtectedAgentRoutePeerV1::new(
                resolved.agent_peer.public_key,
                resolved.agent_peer.channel_binding,
                resolved.agent_peer.authority_binding,
            )?,
        )?;
        if execution.load_admission_state()?
            != ProtectedExecutionAdmissionStateV1::new(&resolved.currentness)
        {
            return Err(JournalRuntimeExecutionError::InvalidBinding.into());
        }
        let effect_fence = execution
            .load_host_execution_fence_v1()?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        if effect_fence.store_binding != resolved.execution_store_binding {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let hoststate_cut = cut_v1(
            peer_authority.records()?,
            resolved.execution_store_binding,
            protected_sequence,
            false,
        )?;
        Ok(HostEffectFenceRecoveryClaimV1 {
            peer_authority,
            execution,
            protected_sequence,
            store_binding: resolved.execution_store_binding,
            hoststate_cut,
            effect_fence,
            currentness: resolved.currentness,
            host_verifier: resolved.host_verifier,
        })
    }
}

impl HostEffectFenceRecoveryClaimV1<'_> {
    /// Borrows the exact protected runtime currentness.
    #[must_use]
    pub const fn currentness(&self) -> &AdmissionCurrentnessV1 {
        &self.currentness
    }

    /// Borrows the exact protected Host verifier and boot identity.
    #[must_use]
    pub const fn host_verifier(&self) -> &ProtectedRuntimeHostVerifierV1 {
        &self.host_verifier
    }

    /// Rechecks both retained owner snapshots without permitting a mutation.
    ///
    /// # Errors
    ///
    /// Rejects a changed HostState epoch, missing Effect fence, or stale owner.
    pub fn revalidate(&self) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        if self.peer_authority.snapshot()?.sequence() != self.protected_sequence
            || cut_v1(
                self.peer_authority.records()?,
                self.store_binding,
                self.protected_sequence,
                false,
            )? != self.hoststate_cut
            || self.execution.load_host_execution_fence_v1()? != Some(self.effect_fence)
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        Ok(())
    }

    /// Rejoins the original method-37 source to its protected no-Apply marker.
    ///
    /// # Errors
    ///
    /// Rejects changed output custody, marker, boot, session, or request identity.
    pub fn query_host_no_apply_v1(
        &self,
        source: &ControllerExecutionArgumentAttemptV1,
        original_session_binding: [u8; 32],
        original_signed_request_digest: [u8; 32],
    ) -> Result<Option<HostExecutionNoApplyRecordV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.revalidate()?;
        self.execution.host_output_for_argument_v1(source)?;
        let Some(marker) = self.execution.load_host_no_apply_v1(source.execution())? else {
            return Ok(None);
        };
        let fields = marker.fields();
        if fields.create_operation_id != *source.create_operation().as_bytes()
            || fields.original_request_id != source.request_id()
            || fields.host_boot_id != source.host_boot_id()
            || fields.assignment_digest != *source.assignment_digest().as_bytes()
            || fields.source_record_digest != *source.record_digest().as_bytes()
            || fields.original_session_binding != original_session_binding
            || fields.original_signed_request_digest != original_signed_request_digest
            || fields.runtime_handle != *self.currentness.runtime().handle().as_bytes()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        self.revalidate()?;
        Ok(Some(marker))
    }

    /// Completes only the HostState half of the original Effect-first fence.
    ///
    /// The caller must first reauthenticate the signed preliminary request and
    /// recompute the completed HostState handoff while this claim is held.
    /// A failed append is outcome-unknown; cold replay must decide whether
    /// the pair is complete. No caller may retry with a new challenge.
    ///
    /// # Errors
    ///
    /// Rejects foreign original custody, a different preliminary request,
    /// changed HostState or Effect state, or uncertain durability.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_hoststate_hold_v1(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
        original_session_binding: [u8; 32],
        original_signed_request_digest: [u8; 32],
        handoff_digest: ObjectDigest,
        original_h_head: ObjectDigest,
        signed_terminal_outcome: ObjectDigest,
        settlement_session_binding: [u8; 32],
        challenge: [u8; 16],
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        let marker = self
            .query_host_no_apply_v1(
                source,
                original_session_binding,
                original_signed_request_digest,
            )?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        let stages = self
            .execution
            .load_host_settlement_history_v1(source.execution())?;
        let [Some(preliminary), None, None] = stages else {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        };
        require_original_recovery_preliminary_v1(
            marker,
            preliminary,
            self.effect_fence,
            handoff_digest,
            original_h_head,
            signed_terminal_outcome,
            settlement_session_binding,
            challenge,
        )?;
        self.revalidate()?;
        let fence = append_host_currentness_hold_v1(
            &mut self.peer_authority,
            self.protected_sequence,
            self.store_binding,
            self.effect_fence,
        )?;
        self.protected_sequence = fence
            .commit_sequence
            .checked_add(1)
            .ok_or(JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        if load_host_currentness_fence_v1(&self.peer_authority, self.protected_sequence)
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?
            != Some(fence)
        {
            return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown.into());
        }
        validate_host_currentness_pair_v1(
            Some(fence),
            self.execution.load_host_execution_fence_v1()?,
            self.store_binding,
        )
        .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn require_original_recovery_preliminary_v1(
    marker: HostExecutionNoApplyRecordV1,
    preliminary: HostSettlementRecordV1,
    effect_fence: HostExecutionFenceV1,
    handoff_digest: ObjectDigest,
    original_h_head: ObjectDigest,
    signed_terminal_outcome: ObjectDigest,
    settlement_session_binding: [u8; 32],
    challenge: [u8; 16],
) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
    if marker.fields().execution_store_binding != *effect_fence.store_binding.as_bytes()
        || preliminary.execution != effect_fence.execution
        || preliminary.digest() != effect_fence.preliminary_digest
        || !preliminary.matches_preliminary_source(
            marker,
            handoff_digest,
            original_h_head,
            signed_terminal_outcome,
            settlement_session_binding,
            challenge,
        )
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
    }
    Ok(())
}

fn append_host_currentness_hold_v1(
    peer_authority: &mut ProtectedJournalAuthority<'_>,
    protected_sequence: u64,
    store_binding: ObjectDigest,
    effect_fence: HostExecutionFenceV1,
) -> Result<HostCurrentnessFenceV1, DormantRuntimeExecutionOwnerErrorV1> {
    let snapshot = peer_authority.snapshot()?;
    if snapshot.sequence() != protected_sequence
        || peer_authority.get(HOST_CURRENTNESS_FENCE_KEY)?.is_some()
    {
        return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown.into());
    }
    let pre_hold_cut = cut_v1(
        peer_authority.records()?,
        store_binding,
        snapshot.sequence(),
        false,
    )?;
    peer_authority.validate_snapshot_for_effect(&snapshot)?;

    let effect_bytes = effect_fence.encode()?;
    let fence = HostCurrentnessFenceV1 {
        store_binding,
        effect_fence_digest: ObjectDigest::from_bytes(Sha256::digest(effect_bytes).into()),
        pre_hold_epoch: snapshot.sequence(),
        pre_hold_cut,
        commit_sequence: snapshot
            .sequence()
            .checked_add(2)
            .ok_or(JournalRuntimeExecutionError::SettlementOutcomeUnknown)?,
    };
    let bytes = fence.encode()?;
    let transaction_digest = Sha256::new()
        .chain_update(b"aos.sandbox.host-currentness-fence-transaction.v1\0")
        .chain_update(bytes)
        .finalize();
    let transaction_id = transaction_digest[..16]
        .try_into()
        .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::HostExecution,
            HOST_CURRENTNESS_FENCE_KEY.to_vec(),
            bytes.to_vec(),
        )],
    )?;

    let committed = peer_authority
        .acquire_host_currentness_fence_v1(fence, &transaction)
        .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
    if committed.commit_sequence != fence.commit_sequence
        || peer_authority
            .get(HOST_CURRENTNESS_FENCE_KEY)
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?
            != Some(bytes.as_slice())
    {
        return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown.into());
    }
    Ok(fence)
}

impl DormantRuntimeExecutionClaimV1<'_> {
    /// Persists the HostState half only after exact Effect-fence readback.
    ///
    /// A failure after Effect commit is never permission to remove or retry
    /// either fence. The cold claim rejects a one-sided pair until a separate
    /// recovery path is qualified.
    pub(super) fn commit_host_currentness_fence_after_effect_v1(
        &mut self,
        effect_fence: HostExecutionFenceV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        if self.peer_fence.is_some()
            || self.execution.load_host_execution_fence_v1()? != Some(effect_fence)
        {
            return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown.into());
        }
        let fence = append_host_currentness_hold_v1(
            &mut self.peer_authority,
            self.protected_sequence,
            self.execution_store_binding,
            effect_fence,
        )?;

        self.protected_sequence = fence
            .commit_sequence
            .checked_add(1)
            .ok_or(JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        self.peer_fence = Some(fence);
        self.validate_current()
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordFieldsV1;
    use tempfile::TempDir;

    use crate::journal::{JournalLimits, JournalRecord};

    #[test]
    fn pair_rejects_either_one_sided_rollback_and_substitution() {
        let binding = ObjectDigest::from_bytes([1; 32]);
        let effect = HostExecutionFenceV1 {
            store_binding: binding,
            execution: ExecutionId::from_bytes([2; 16]),
            preliminary_digest: ObjectDigest::from_bytes([3; 32]),
            pre_fence_epoch: 7,
            pre_fence_cut: ObjectDigest::from_bytes([4; 32]),
            commit_sequence: 9,
        };
        let hoststate = HostCurrentnessFenceV1 {
            store_binding: binding,
            effect_fence_digest: ObjectDigest::from_bytes(
                Sha256::digest(effect.encode().expect("effect fence")).into(),
            ),
            pre_hold_epoch: 11,
            pre_hold_cut: ObjectDigest::from_bytes([5; 32]),
            commit_sequence: 13,
        };

        assert!(validate_host_currentness_pair_v1(None, None, binding).is_ok());
        assert!(validate_host_currentness_pair_v1(Some(hoststate), Some(effect), binding).is_ok());
        for (peer, effect) in [
            (Some(hoststate), None),
            (None, Some(effect)),
            (
                Some(hoststate),
                Some(HostExecutionFenceV1 {
                    preliminary_digest: ObjectDigest::from_bytes([6; 32]),
                    ..effect
                }),
            ),
        ] {
            assert!(validate_host_currentness_pair_v1(peer, effect, binding).is_err());
        }
        assert!(
            validate_host_currentness_pair_v1(
                Some(hoststate),
                Some(effect),
                ObjectDigest::from_bytes([9; 32]),
            )
            .is_err()
        );
    }

    #[test]
    fn recovery_rejects_foreign_handoff_request_and_effect_fence() {
        let marker = HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
            execution_id: [1; 16],
            create_operation_id: [2; 16],
            original_request_id: [3; 16],
            terminal_request_id: [4; 16],
            host_boot_id: [5; 16],
            assignment_digest: [6; 32],
            source_record_digest: [7; 32],
            original_session_binding: [8; 32],
            original_signed_request_digest: [9; 32],
            terminal_session_binding: [10; 32],
            terminal_signed_request_digest: [11; 32],
            runtime_handle: [12; 32],
            execution_store_binding: [13; 32],
            commit_sequence: 10,
        })
        .expect("canonical marker");
        let handoff = ObjectDigest::from_bytes([14; 32]);
        let h_head = ObjectDigest::from_bytes([15; 32]);
        let terminal = ObjectDigest::from_bytes([16; 32]);
        let session = [18; 32];
        let challenge = [19; 16];
        let preliminary = HostSettlementRecordV1::preliminary(
            HostObservedSettlementIdentityV1::from_marker_and_handoff(marker, handoff)
                .expect("Host identity"),
            ControllerAssertedSettlementArchivesV1::new(h_head, terminal)
                .expect("asserted archives"),
            11,
            ObjectDigest::from_bytes([17; 32]),
            session,
            challenge,
            13,
        )
        .expect("original preliminary");
        let effect = HostExecutionFenceV1 {
            store_binding: ObjectDigest::from_bytes([13; 32]),
            execution: ExecutionId::from_bytes([1; 16]),
            preliminary_digest: preliminary.digest(),
            pre_fence_epoch: 14,
            pre_fence_cut: ObjectDigest::from_bytes([20; 32]),
            commit_sequence: 16,
        };
        let exact = |marker, effect, handoff, h_head, terminal, session, challenge| {
            require_original_recovery_preliminary_v1(
                marker,
                preliminary,
                effect,
                handoff,
                h_head,
                terminal,
                session,
                challenge,
            )
        };
        assert!(
            exact(
                marker, effect, handoff, h_head, terminal, session, challenge
            )
            .is_ok()
        );
        let mut foreign_fields = marker.fields();
        foreign_fields.original_request_id = [21; 16];
        let foreign_marker =
            HostExecutionNoApplyRecordV1::new(foreign_fields).expect("foreign marker");
        assert!(
            exact(
                foreign_marker,
                effect,
                handoff,
                h_head,
                terminal,
                session,
                challenge
            )
            .is_err()
        );
        assert!(
            exact(
                marker,
                effect,
                ObjectDigest::from_bytes([22; 32]),
                h_head,
                terminal,
                session,
                challenge
            )
            .is_err()
        );
        assert!(
            exact(
                marker,
                effect,
                handoff,
                ObjectDigest::from_bytes([23; 32]),
                terminal,
                session,
                challenge
            )
            .is_err()
        );
        assert!(
            exact(
                marker,
                effect,
                handoff,
                h_head,
                ObjectDigest::from_bytes([24; 32]),
                session,
                challenge
            )
            .is_err()
        );
        assert!(
            exact(
                marker, effect, handoff, h_head, terminal, [25; 32], challenge
            )
            .is_err()
        );
        assert!(exact(marker, effect, handoff, h_head, terminal, session, [26; 16]).is_err());
        assert!(
            exact(
                marker,
                HostExecutionFenceV1 {
                    preliminary_digest: ObjectDigest::from_bytes([27; 32]),
                    ..effect
                },
                handoff,
                h_head,
                terminal,
                session,
                challenge
            )
            .is_err()
        );
        assert!(
            exact(
                marker,
                HostExecutionFenceV1 {
                    execution: ExecutionId::from_bytes([28; 16]),
                    ..effect
                },
                handoff,
                h_head,
                terminal,
                session,
                challenge
            )
            .is_err()
        );
        assert!(
            exact(
                marker,
                HostExecutionFenceV1 {
                    store_binding: ObjectDigest::from_bytes([29; 32]),
                    ..effect
                },
                handoff,
                h_head,
                terminal,
                session,
                challenge
            )
            .is_err()
        );
    }

    #[test]
    fn hoststate_hold_blocks_currentness_writes_and_replays_exactly() {
        let directory = TempDir::new_in(std::env::current_dir().expect("current directory"))
            .expect("test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = directory.path().metadata().expect("metadata").uid();
        let binding = ObjectDigest::from_bytes([1; 32]);
        let effect = HostExecutionFenceV1 {
            store_binding: binding,
            execution: ExecutionId::from_bytes([2; 16]),
            preliminary_digest: ObjectDigest::from_bytes([3; 32]),
            pre_fence_epoch: 7,
            pre_fence_cut: ObjectDigest::from_bytes([4; 32]),
            commit_sequence: 9,
        };
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "hoststate.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("protected HostState journal");
        let mut authority = journal
            .claim_protected_authority(RecordNamespace::HostExecution)
            .expect("HostState authority");
        let rows = crate::journal::host_currentness_fence::OWNER_KEYS
            .iter()
            .enumerate()
            .map(|(index, key)| {
                JournalRecord::put(
                    RecordNamespace::HostExecution,
                    key.to_vec(),
                    vec![index as u8 + 1],
                )
            })
            .collect();
        authority
            .commit(&JournalTransaction::new([1; 16], rows).expect("five owner rows"))
            .expect("durable owner rows");
        drop(authority);
        drop(journal);

        for name in ["prehold.journal", "forged.journal", "recovery.journal"] {
            std::fs::copy(
                directory.path().join("hoststate.journal"),
                directory.path().join(name),
            )
            .expect("copy prehold state");
            std::fs::set_permissions(
                directory.path().join(name),
                std::fs::Permissions::from_mode(0o600),
            )
            .expect("private copied state");
        }
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "hoststate.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("reopen HostState");
        let mut authority = journal
            .claim_protected_authority(RecordNamespace::HostExecution)
            .expect("claimed HostState");
        let epoch = authority.snapshot().expect("snapshot").sequence();
        let cut = cut_v1(authority.records().expect("records"), binding, epoch, false)
            .expect("protected cut");
        let hold = HostCurrentnessFenceV1 {
            store_binding: binding,
            effect_fence_digest: ObjectDigest::from_bytes(
                Sha256::digest(effect.encode().expect("effect bytes")).into(),
            ),
            pre_hold_epoch: epoch,
            pre_hold_cut: cut,
            commit_sequence: epoch + 2,
        };
        let hold_bytes = hold.encode().expect("canonical hold");
        let hold_transaction = JournalTransaction::new(
            [2; 16],
            vec![JournalRecord::put(
                RecordNamespace::HostExecution,
                HOST_CURRENTNESS_FENCE_KEY.to_vec(),
                hold_bytes.to_vec(),
            )],
        )
        .expect("hold transaction");
        assert!(matches!(
            authority.commit(&hold_transaction),
            Err(JournalError::ProtectedBoundary)
        ));
        authority
            .acquire_host_currentness_fence_v1(hold, &hold_transaction)
            .expect("typed HostState acquisition");
        for (index, key) in [PEER_CURRENT_KEY, CURRENTNESS_KEY, HOST_EVIDENCE_KEY]
            .into_iter()
            .enumerate()
        {
            let replace = JournalTransaction::new(
                [10 + index as u8; 16],
                vec![JournalRecord::put(
                    RecordNamespace::HostExecution,
                    key.to_vec(),
                    vec![99],
                )],
            )
            .expect("competing currentness write");
            assert!(matches!(
                authority.preflight_transactions(std::slice::from_ref(&replace)),
                Err(JournalError::ProtectedBoundary)
            ));
            assert!(matches!(
                authority.commit(&replace),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        for (index, record) in [
            JournalRecord::delete(
                RecordNamespace::HostExecution,
                HOST_CURRENTNESS_FENCE_KEY.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::HostExecution,
                HOST_CURRENTNESS_FENCE_KEY.to_vec(),
                hold_bytes.to_vec(),
            ),
            JournalRecord::delete(RecordNamespace::HostExecution, PEER_CURRENT_KEY.to_vec()),
        ]
        .into_iter()
        .enumerate()
        {
            let transaction = JournalTransaction::new([20 + index as u8; 16], vec![record])
                .expect("forbidden hold replacement or deletion");
            assert!(matches!(
                authority.commit(&transaction),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        drop(authority);
        assert!(matches!(
            journal.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(journal);

        let (mut cold, _) = Journal::open_protected_at_uid(
            directory.path(),
            "hoststate.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("cold HostState journal");
        let cold_authority = cold
            .claim_protected_authority(RecordNamespace::HostExecution)
            .expect("cold HostState claim");
        let recovered = load_host_currentness_fence_v1(
            &cold_authority,
            cold_authority.snapshot().expect("cold snapshot").sequence(),
        )
        .expect("cold exact hold");
        assert_eq!(recovered, Some(hold));
        assert!(validate_host_currentness_pair_v1(recovered, Some(effect), binding).is_ok());
        assert!(validate_host_currentness_pair_v1(recovered, None, binding).is_err());
        drop(cold_authority);
        drop(cold);

        let (mut rolled_back, _) = Journal::open_protected_at_uid(
            directory.path(),
            "prehold.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("one-sided HostState rollback fixture");
        let rolled_back_authority = rolled_back
            .claim_protected_authority(RecordNamespace::HostExecution)
            .expect("prehold claim");
        let absent = load_host_currentness_fence_v1(
            &rolled_back_authority,
            rolled_back_authority
                .snapshot()
                .expect("prehold snapshot")
                .sequence(),
        )
        .expect("no hold after rollback");
        assert!(validate_host_currentness_pair_v1(absent, Some(effect), binding).is_err());
        drop(rolled_back_authority);
        drop(rolled_back);

        let (mut recovery, _) = Journal::open_protected_at_uid(
            directory.path(),
            "recovery.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("Effect-first recovery fixture");
        let mut recovery_authority = recovery
            .claim_protected_authority(RecordNamespace::HostExecution)
            .expect("recovery HostState claim");
        let recovered_epoch = recovery_authority
            .snapshot()
            .expect("pre-hold epoch")
            .sequence();
        let completed = append_host_currentness_hold_v1(
            &mut recovery_authority,
            recovered_epoch,
            binding,
            effect,
        )
        .expect("typed recovery completion");
        assert_eq!(completed, hold);
        drop(recovery_authority);
        drop(recovery);
        let (mut recovery, _) = Journal::open_protected_at_uid(
            directory.path(),
            "recovery.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("cold recovered HostState");
        let recovery_authority = recovery
            .claim_protected_authority(RecordNamespace::HostExecution)
            .expect("cold recovery claim");
        let replayed = load_host_currentness_fence_v1(
            &recovery_authority,
            recovery_authority
                .snapshot()
                .expect("cold epoch")
                .sequence(),
        )
        .expect("cold recovery readback");
        assert_eq!(replayed, Some(completed));
        assert!(validate_host_currentness_pair_v1(replayed, Some(effect), binding).is_ok());
        drop(recovery_authority);
        drop(recovery);

        let (mut forged, _) = Journal::open_protected_at_uid(
            directory.path(),
            "forged.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("forged HostState fixture");
        let mut forged_authority = forged
            .claim_protected_authority(RecordNamespace::HostExecution)
            .expect("forged authority");
        let false_hold = HostCurrentnessFenceV1 {
            pre_hold_cut: ObjectDigest::from_bytes([88; 32]),
            ..hold
        };
        let false_transaction = JournalTransaction::new(
            [3; 16],
            vec![JournalRecord::put(
                RecordNamespace::HostExecution,
                HOST_CURRENTNESS_FENCE_KEY.to_vec(),
                false_hold.encode().expect("false hold bytes").to_vec(),
            )],
        )
        .expect("false hold transaction");
        assert!(matches!(
            forged_authority.acquire_host_currentness_fence_v1(false_hold, &false_transaction),
            Err(JournalError::ProtectedBoundary)
        ));
        forged_authority
            .inject_host_currentness_fence_for_test(&false_transaction)
            .expect("inject false cut for cold replay");
        drop(forged_authority);
        drop(forged);
        let (mut forged, _) = Journal::open_protected_at_uid(
            directory.path(),
            "forged.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("cold forged journal");
        let forged_authority = forged
            .claim_protected_authority(RecordNamespace::HostExecution)
            .expect("cold forged claim");
        assert!(
            load_host_currentness_fence_v1(
                &forged_authority,
                forged_authority
                    .snapshot()
                    .expect("forged snapshot")
                    .sequence(),
            )
            .is_err()
        );
    }
}

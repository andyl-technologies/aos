//! HostState/Effect fence join under the fixed owner lock order.
//!
//! The peer writer is claimed before the Effect writer. A cold owner claim
//! accepts either both exact fences or neither; a crash between their appends
//! is quarantined until an explicit recovery path is qualified. The pair can
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
        let snapshot = self.peer_authority.snapshot()?;
        if self.peer_fence.is_some()
            || snapshot.sequence() != self.protected_sequence
            || self.execution.load_host_execution_fence_v1()? != Some(effect_fence)
        {
            return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown.into());
        }
        let pre_hold_cut = cut_v1(
            self.peer_authority.records()?,
            self.execution_store_binding,
            snapshot.sequence(),
            false,
        )?;
        self.peer_authority
            .validate_snapshot_for_effect(&snapshot)?;

        let effect_bytes = effect_fence.encode()?;
        let fence = HostCurrentnessFenceV1 {
            store_binding: self.execution_store_binding,
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

        let committed = self
            .peer_authority
            .acquire_host_currentness_fence_v1(fence, &transaction)
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        if committed.commit_sequence != fence.commit_sequence
            || self
                .peer_authority
                .get(HOST_CURRENTNESS_FENCE_KEY)
                .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?
                != Some(bytes.as_slice())
        {
            return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown.into());
        }

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

        for name in ["prehold.journal", "forged.journal"] {
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

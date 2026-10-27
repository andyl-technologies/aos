//! Retains the paid method31 pending and completion State transactions.
//!
//! Only the actual admitted publication caller supplies these private owners.
//! Encoding, native append, exact readback and held-name posts reuse the same
//! State commit engine as other recurring effects. A pending record grants no
//! completion and a completed record cannot redispatch its old effect.

use super::*;
use crate::guest_root_attempt::{GuestRootAttemptPhaseV2, GUEST_ROOT_ATTEMPT_RECORD_BYTES};
use aos_sandbox_controller_domain::journal::{StorageStateNativeCommitAttemptV1, StorageStateNativeCommitClosedV1};

#[derive(Clone, Copy)]
enum Failure { Current, Payment, Sealed, Transaction, Native, Readback }

pub(crate) struct GuestRootStateRecordOriginalV2 {
    native: StorageStateNativeCommitAttemptV1,
    native_result: Option<Result<(), StorageStateNativeCommitClosedV1>>,
    current: Option<Result<(), StorageStateError>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    encoded: Option<Result<Vec<u8>, StorageStateError>>,
    transaction: Option<Result<JournalTransaction, JournalTransactionDataError>>,
    readback: Option<Result<(), StorageStateError>>,
    attempt: Option<GuestRootPublicationAttemptV2>,
    first: Option<Failure>,
    entered: bool,
    completed: bool,
}

impl GuestRootStateRecordOriginalV2 {
    pub(crate) fn new() -> Self {
        Self { native: StorageStateNativeCommitAttemptV1::new(), native_result: None,
            current: None, payment: None, encoded: None, transaction: None,
            readback: None, attempt: None, first: None, entered: false, completed: false }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            Failure::Current => error(&self.current),
            Failure::Payment => error(&self.payment),
            Failure::Sealed => error(&self.encoded),
            Failure::Transaction => error(&self.transaction),
            Failure::Native => self.native.failure().or_else(|| error(&self.native_result)),
            Failure::Readback => error(&self.readback),
        }
    }

    pub(crate) fn encoded_pending_v2(&self) -> Option<&[u8]> {
        if !self.completed || !matches!(self.attempt?.phase, GuestRootAttemptPhaseV2::Ambiguous) { return None; }
        self.encoded.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    pub(crate) fn attempt_v2(&self) -> Option<&GuestRootPublicationAttemptV2> {
        if !self.completed || self.first.is_some() { return None; }
        self.attempt.as_ref()
    }

    pub(crate) fn begin_pending_once_v2(
        &mut self, store: &mut StorageTransactionStore,
        attempt: GuestRootPublicationAttemptV2, sealed: &SealedStorageAdmission,
        current_boottime_nanoseconds: u64, receiving: &mut encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        if self.entered {
            self.completed = false;
            if !self.current.as_ref().is_some_and(Result::is_err) {
                self.current = Some(Err(StorageStateError::InvalidTransition));
            }
            self.first.get_or_insert(Failure::Current);
            return Err(StorageStateError::Receiving);
        }
        self.entered = true;
        self.attempt = Some(attempt);
        self.current = Some(Self::require_pending(store, attempt, sealed, current_boottime_nanoseconds));
        if !matches!(self.current, Some(Ok(()))) { self.first = Some(Failure::Current); return Err(StorageStateError::Receiving); }
        self.prepay_v2(receiving, 4, sealed.current_fence.len() + sealed.effect.len() + sealed.operation_fence.len())?;
        self.encoded = Some(store.key.seal_guest_root_publication_attempt(attempt));
        let Some(Ok(encoded)) = self.encoded.as_ref() else { self.first = Some(Failure::Sealed); return Err(StorageStateError::Receiving); };
        self.transaction = Some(JournalTransaction::new(
            guest_root_attempt_transaction_id(attempt.effect_operation), vec![
                JournalRecord::put(RecordNamespace::DesiredState, attempt.expected_proof.sandbox.to_vec(), sealed.current_fence.clone()),
                JournalRecord::put(RecordNamespace::Effect, attempt.request_id.to_vec(), sealed.effect.clone()),
                JournalRecord::put(RecordNamespace::AuthorityPublication, attempt.effect_operation.to_vec(), sealed.operation_fence.clone()),
                JournalRecord::put(RecordNamespace::StorageGuestRootPublicationAttempt, attempt.effect_operation.to_vec(), encoded.clone()),
            ],
        ));
        self.commit_v2(store, receiving)
    }

    pub(crate) fn complete_once_v2(
        &mut self, store: &mut StorageTransactionStore,
        pending: &GuestRootStateRecordOriginalV2,
        readback: &crate::guest_root_inventory::GuestRootTargetReadbackOriginalV2,
        receiving: &mut encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        if self.entered {
            self.completed = false;
            if !self.current.as_ref().is_some_and(Result::is_err) {
                self.current = Some(Err(StorageStateError::InvalidTransition));
            }
            self.first.get_or_insert(Failure::Current);
            return Err(StorageStateError::Receiving);
        }
        self.entered = true;
        self.current = Some((|| {
            store.ensure_authority_readable()?;
            let attempt = *pending.attempt_v2().ok_or(StorageStateError::InvalidTransition)?;
            if !readback.requires_pending_v2(pending)
                || store.guest_root_attempts.get(&attempt.effect_operation) != Some(&attempt) {
                return Err(StorageStateError::Equivocation);
            }
            self.attempt = Some(attempt.complete()?);
            Ok(())
        })());
        if !matches!(self.current, Some(Ok(()))) { self.first = Some(Failure::Current); return Err(StorageStateError::Receiving); }
        self.prepay_v2(receiving, 1, 0)?;
        let attempt = self.attempt.ok_or(StorageStateError::InvalidTransition)?;
        self.encoded = Some(store.key.seal_guest_root_publication_attempt(attempt));
        let Some(Ok(encoded)) = self.encoded.as_ref() else { self.first = Some(Failure::Sealed); return Err(StorageStateError::Receiving); };
        let digest = Sha256::new().chain_update(b"aos.sandbox.storage.guest-root-complete.v2\0")
            .chain_update(attempt.effect_operation).chain_update(encoded).finalize();
        let mut id = [0; 16]; id.copy_from_slice(&digest[..16]);
        self.transaction = Some(JournalTransaction::new(id, vec![JournalRecord::put(
            RecordNamespace::StorageGuestRootPublicationAttempt, attempt.effect_operation.to_vec(), encoded.clone(),
        )]));
        self.commit_v2(store, receiving)
    }

    fn prepay_v2(&mut self, receiving: &mut encoding::StateEncodingLoanV1<'_, '_>, records: usize, sealed: usize)
        -> Result<(), StorageStateError>
    {
        // The temporary record vector consumes bytes. Native append owns its
        // own actual journal indices; the upper Store adds one attempt-map row
        // only on first admission. Replacing that row on completion adds none.
        let bytes = 3 * std::mem::size_of::<Self>() + 3 * GUEST_ROOT_ATTEMPT_RECORD_BYTES
            + 3 * sealed + records * (std::mem::size_of::<JournalRecord>() + 16);
        let entries = usize::from(self.attempt.is_some_and(|attempt|
            matches!(attempt.phase, GuestRootAttemptPhaseV2::Ambiguous)));
        self.payment = Some(receiving.reserve_encoded_capacity_v1(bytes, entries));
        if matches!(self.payment, Some(Ok(()))) { Ok(()) }
        else { self.first = Some(Failure::Payment); Err(StorageStateError::Receiving) }
    }

    fn commit_v2(&mut self, store: &mut StorageTransactionStore, receiving: &mut encoding::StateEncodingLoanV1<'_, '_>)
        -> Result<(), StorageStateError>
    {
        let Some(Ok(transaction)) = self.transaction.as_ref() else {
            self.first = Some(Failure::Transaction); return Err(StorageStateError::Receiving);
        };
        self.payment = Some(receiving.reserve_append_v1(&store.journal, transaction));
        if !matches!(self.payment, Some(Ok(()))) { self.first = Some(Failure::Payment); return Err(StorageStateError::Receiving); }
        self.payment = Some(receiving.reserve_guest_root_commit_post_v2(&store.journal));
        if !matches!(self.payment, Some(Ok(()))) { self.first = Some(Failure::Payment); return Err(StorageStateError::Receiving); }
        self.native_result = Some(self.native.commit_once_v1(&mut store.journal, transaction));
        if !matches!(self.native_result, Some(Ok(()))) {
            store.commit_failed = true; self.first = Some(Failure::Native); return Err(StorageStateError::Receiving);
        }
        self.readback = Some(store.verify_journal_transaction_v1(transaction));
        if !matches!(self.readback, Some(Ok(()))) { self.first = Some(Failure::Readback); return Err(StorageStateError::Receiving); }
        let attempt = self.attempt.ok_or(StorageStateError::InvalidTransition)?;
        store.guest_root_attempts.insert(attempt.effect_operation, attempt);
        self.completed = true;
        Ok(())
    }

    fn require_pending(store: &StorageTransactionStore, attempt: GuestRootPublicationAttemptV2,
        sealed: &SealedStorageAdmission, current_boottime_nanoseconds: u64,
    ) -> Result<(), StorageStateError> {
        store.ensure_authority_readable()?;
        attempt.validate()?;
        if current_boottime_nanoseconds == 0
            || attempt.effect_deadline_boottime_nanoseconds <= current_boottime_nanoseconds
            || attempt.phase != crate::guest_root_attempt::GuestRootAttemptPhaseV2::Ambiguous
            || store
                .guest_root_attempts
                .contains_key(&attempt.effect_operation)
            || store.records.contains_key(&attempt.effect_operation)
            || store.guest_root_attempts.values().any(|existing| {
                existing.expected_proof.workspace_handle == attempt.expected_proof.workspace_handle
                    && !existing.permits_current_successor_v2(attempt)
                    && !existing.permits_fresh_retry(attempt, current_boottime_nanoseconds)
            })
            || store
                .journal
                .get(RecordNamespace::Effect, &attempt.request_id)
                .is_some()
            || store
                .journal
                .get(
                    RecordNamespace::AuthorityPublication,
                    &attempt.effect_operation,
                )
                .is_some()
            || sealed.current_fence.is_empty()
            || sealed.effect.is_empty()
            || sealed.operation_fence.is_empty()
            || sealed.current_fence.len() > MAXIMUM_RECORD_BYTES
            || sealed.effect.len() > MAXIMUM_RECORD_BYTES
            || sealed.operation_fence.len() > MAXIMUM_RECORD_BYTES
            || Sha256::digest(&sealed.effect).as_slice() != attempt.sealed_effect_digest
            || Sha256::digest(&sealed.operation_fence).as_slice() != attempt.operation_fence_digest
        {
            return Err(StorageStateError::Equivocation);
        }
        let proof = attempt.expected_proof;
        let creation = store
            .records
            .get(&proof.creation_operation)
            .filter(|record| record.phase == DurableStoragePhase::Committed)
            .and_then(|record| record.result)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let publication = store
            .publication_intents
            .get(&proof.creation_operation)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if creation.storage_handle() != Some(proof.workspace_handle)
            || creation.object_guid() != Some(proof.dataset_guid)
            || publication.assignment_digest().as_bytes() != &proof.assignment_digest
            || attempt.creation_arguments.assignment_data_v1()
                .map_err(|_| StorageStateError::AuthorityLinkMismatch)? != publication.portable_metadata().assignment()
            || publication.root_image().digest().as_bytes() != &proof.root_image_digest
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        Ok(())
    }
}

impl StorageTransactionStore {
    /// Selects the unique publication for the actual current assignment.
    ///
    /// Selection follows the independently opened current fence, never map
    /// order or the largest supplied generation. An unfinished current attempt
    /// blocks projection even if an older creation publication was complete.
    pub(crate) fn current_guest_root_attempt_v2(
        &self,
        workspace_handle: &[u8; 32],
        current: aos_sandbox_model::BrokerAssignment,
    ) -> Result<Option<&GuestRootPublicationAttemptV2>, StorageStateError> {
        self.ensure_authority_readable()?;
        let mut selected = None;
        for attempt in self.guest_root_attempts.values() {
            if &attempt.expected_proof.workspace_handle != workspace_handle {
                continue;
            }
            let assignment = attempt.current_publication.current_assignment_v2()
                .map_err(|_| StorageStateError::AuthorityLinkMismatch)?;
            if assignment != current {
                continue;
            }
            if selected.is_some() || attempt.phase != GuestRootAttemptPhaseV2::Complete {
                return Err(StorageStateError::InvalidTransition);
            }
            selected = Some(attempt);
        }
        Ok(selected)
    }
}

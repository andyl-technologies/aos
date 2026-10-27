//! Persists the real Capture fence and catalog reservation before native create.
//!
//! The sole caller is the fresh noncopyable Native Capture owner under the
//! continuously borrowed State codec. The same selected native commit engine
//! retains encoder/transaction/append causes. A completed pending record is an
//! ambiguity fence, never evidence that create, mount, EOF or completion ran.

use super::*;
use crate::authorization::{StorageAuthorityV1, StorageAdmissionError};
use crate::catalog_transition::CaptureCatalogResolutionV3;
use crate::execution_output::FreshCaptureCreateCommitV3;

#[derive(Clone, Copy)]
enum Failure { Current, Payment, Resolution, Seal, Reservation, Records, Transaction, Native, Readback }

pub(crate) struct CaptureStatePendingOriginalV3 {
    native: aos_sandbox_controller_domain::journal::StorageStateNativeCommitAttemptV1,
    native_status: Option<Result<(), aos_sandbox_controller_domain::journal::StorageStateNativeCommitClosedV1>>,
    transaction: Option<Result<JournalTransaction, JournalTransactionDataError>>,
    records: Option<Result<Vec<JournalRecord>, StorageStateError>>,
    reservation: Option<Result<CatalogReservation, StorageStateError>>,
    sealed: Option<Result<SealedStorageAdmission, StorageAdmissionError>>,
    resolution: Option<Result<CaptureCatalogResolutionV3, StorageStateError>>,
    codec: encoding::StateCodecOriginalV1,
    current: Option<Result<(), StorageStateError>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    readback: Option<Result<(), StorageStateError>>,
    first: Option<Failure>,
    entered: bool,
    completed: bool,
}

impl CaptureStatePendingOriginalV3 {
    pub(crate) fn new() -> Self {
        Self {
            native: aos_sandbox_controller_domain::journal::StorageStateNativeCommitAttemptV1::new(),
            native_status: None, transaction: None, records: None, reservation: None,
            sealed: None, resolution: None, codec: encoding::StateCodecOriginalV1::default(),
            current: None, payment: None, readback: None, first: None,
            entered: false, completed: false,
        }
    }

    pub(crate) fn completed_v3(&self) -> bool { self.completed && self.first.is_none() }

    pub(crate) fn resolution_v3(&self) -> Option<&CaptureCatalogResolutionV3> {
        if !self.completed_v3() { return None; }
        self.resolution.as_ref()?.as_ref().ok()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            Failure::Current => error(&self.current),
            Failure::Payment => error(&self.payment).or_else(|| self.codec.failure()),
            Failure::Resolution => error(&self.resolution),
            Failure::Seal => error(&self.sealed),
            Failure::Reservation => self.codec.failure().or_else(|| error(&self.reservation)),
            Failure::Records => self.codec.failure().or_else(|| error(&self.records)),
            Failure::Transaction => error(&self.transaction),
            Failure::Native => self.native.failure().or_else(|| error(&self.native_status)),
            Failure::Readback => error(&self.readback),
        }
    }

    pub(crate) fn begin_once_v3(
        &mut self,
        store: &mut StorageTransactionStore,
        authority: &StorageAuthorityV1,
        fresh: &FreshCaptureCreateCommitV3,
        receiving: &mut encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        if self.entered { return Err(StorageStateError::Receiving); }
        self.entered = true;
        self.first = Some(Failure::Current);
        self.current = Some(store.ensure_authority_readable()
            .and_then(|()| store.require_no_held_repair_guard_v1()));
        if !matches!(self.current, Some(Ok(()))) { return Err(StorageStateError::Receiving); }
        let admitted = fresh.admitted_v3();
        let source = admitted.source_v3().original_source_v1();
        let operation = *source.storage_create_operation().as_bytes();
        let request = *admitted.lifetime_v3().admission_v3().effect.request_id();
        let sandbox = *source.assignment().sandbox().as_bytes();
        // The inherited signed/typed owner is already paid by its caller.
        // Reserve all three actual bounded seal buffers and the concrete recipe
        // carriers before the first Vec/requirement clone is materialized.
        self.first = Some(Failure::Payment);
        let (_, _, _, _, _, _, _, requirement, _) = fresh.native_parts_v3();
        // The cloned requirement owns its root once directly and once in its
        // PlannedDataset, and owns the same dataset name in both fields.
        let names = requirement.root().pool().len()
            .checked_add(requirement.root().dataset_prefix().len())
            .and_then(|bytes| bytes.checked_add(requirement.dataset_name().len()))
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(StorageStateError::Receiving)?;
        let carriers = 3usize.checked_mul(MAXIMUM_RECORD_BYTES)
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<CaptureCatalogResolutionV3>()))
            .and_then(|bytes| bytes.checked_add(3 * (8 + 8 + 32 + 944 + 32 + 32)))
            .and_then(|bytes| names.checked_mul(3).and_then(|names| bytes.checked_add(names)))
            .ok_or(StorageStateError::Receiving)?;
        self.payment = Some(receiving.reserve_encoded_capacity_v1(carriers, 0));
        if !matches!(self.payment, Some(Ok(()))) { return Err(StorageStateError::Receiving); }
        self.first = Some(Failure::Resolution);
        self.resolution = Some(store.catalog_transitions.prepare_capture_resolution_v3(fresh));
        let Some(Ok(resolution)) = self.resolution.as_ref() else { return Err(StorageStateError::Receiving); };
        // Reentry cannot revive a historical424 or any already-entered State
        // effect. The current admission was verified over this held State.
        if store.records.contains_key(&operation) || store.atomic_snapshots.contains_key(&operation)
            || store.journal.get(RecordNamespace::Effect, &request).is_some()
            || store.journal.get(RecordNamespace::StorageCatalogReservation, &operation).is_some()
        {
            self.current = Some(Err(StorageStateError::Equivocation));
            self.first = Some(Failure::Current);
            return Err(StorageStateError::Receiving);
        }
        self.first = Some(Failure::Seal);
        self.sealed = Some(authority.seal(&sandbox, &request, &operation,
            admitted.lifetime_v3().admission_v3()));
        if !matches!(self.sealed, Some(Ok(_))) { return Err(StorageStateError::Receiving); }
        let mut context = encoding::StateEncodingContextV1::new(receiving, &mut self.codec);
        self.first = Some(Failure::Reservation);
        self.reservation = Some(store.catalog_transitions.reserve_capture_receiving_v3(
            resolution, store.key.key_id, &store.key.secret, &mut context,
        ));
        let Some(Ok(reservation)) = self.reservation.as_ref() else { return Err(StorageStateError::Receiving); };
        self.first = Some(Failure::Records);
        self.records = Some((|| {
            context.reserve_owned_capacity_v1(
                5usize.checked_mul(std::mem::size_of::<JournalRecord>() + 16)
                    .ok_or(aos_sandbox_model::AccountingError::ArithmeticOverflow {
                        dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
                    }), 2,
            )?;
            let Some(Ok(sealed)) = self.sealed.as_ref() else { return Err(StorageStateError::Receiving); };
            if [&sealed.current_fence, &sealed.effect, &sealed.operation_fence].iter()
                .any(|bytes| bytes.is_empty() || bytes.len() > MAXIMUM_RECORD_BYTES)
            { return Err(StorageStateError::InvalidValue); }
            let reservation_record = StorageCatalogTransitionProvider::reservation_record_receiving_v1(
                reservation, &mut context,
            )?;
            let capture_operation = resolution.operation_record_receiving_v3(
                store.key.key_id, &store.key.secret, &mut context,
            )?;
            let Some(Ok(sealed)) = self.sealed.take() else { std::process::abort(); };
            Ok(vec![
                JournalRecord::put(RecordNamespace::DesiredState, sandbox.to_vec(), sealed.current_fence),
                JournalRecord::put(RecordNamespace::Effect, request.to_vec(), sealed.effect),
                JournalRecord::put(RecordNamespace::AuthorityPublication, operation.to_vec(), sealed.operation_fence),
                reservation_record,
                capture_operation,
            ])
        })());
        if !matches!(self.records, Some(Ok(_))) { return Err(StorageStateError::Receiving); }
        drop(context);
        let Some(Ok(records)) = self.records.take() else { std::process::abort(); };
        let id = Sha256::new().chain_update(b"aos.sandbox.storage.capture-pending-transaction.v3\0")
            .chain_update(operation).chain_update(request).finalize();
        let mut transaction_id = [0; 16]; transaction_id.copy_from_slice(&id[..16]);
        self.first = Some(Failure::Transaction);
        self.transaction = Some(JournalTransaction::new(transaction_id, records));
        let Some(Ok(transaction)) = self.transaction.as_ref() else { return Err(StorageStateError::Receiving); };
        self.first = Some(Failure::Payment);
        self.payment = Some(receiving.reserve_append_v1(&store.journal, transaction));
        if !matches!(self.payment, Some(Ok(()))) { return Err(StorageStateError::Receiving); }
        self.first = Some(Failure::Native);
        self.payment = Some(receiving.reserve_capture_commit_post_v3(&store.journal));
        if !matches!(self.payment, Some(Ok(()))) {
            self.first = Some(Failure::Payment);
            return Err(StorageStateError::Receiving);
        }
        self.native_status = Some(self.native.commit_once_v1(&mut store.journal, transaction));
        if !matches!(self.native_status, Some(Ok(()))) {
            store.commit_failed = true;
            return Err(StorageStateError::Receiving);
        }
        self.first = Some(Failure::Readback);
        self.readback = Some(if transaction.records().iter().all(|record|
            store.journal.get(record.namespace(), record.key()) == record.value())
        { Ok(()) } else { Err(StorageStateError::CorruptRecord) });
        if !matches!(self.readback, Some(Ok(()))) {
            store.commit_failed = true;
            return Err(StorageStateError::Receiving);
        }
        let Some(Ok(reservation)) = self.reservation.take() else { std::process::abort(); };
        store.catalog_transitions.install_reservation(reservation);
        store.catalog_transitions.install_capture_operation_v3(resolution);
        self.first = None; self.completed = true;
        Ok(())
    }
}

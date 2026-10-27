//! Commits and cold-replays the exact native-created Capture catalog row.
//!
//! The same once-entered State loan survives pending, the occupied worker and
//! this commit. Only the owning actual authenticated worker report can enter;
//! parsed observations, historical attempts and Controller responses cannot.

use super::*;
use crate::catalog_transition::{CatalogPhysicalApplicationOriginalV1,
    CatalogTransitionPreparationOriginalV1, PreparedCatalogTransition};
use crate::catalog_transition::execution_capture::VerifiedCaptureDatasetV1;
use crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3;
use crate::process::NativeCaptureCreatedReadbackV3;

#[derive(Clone, Copy)]
enum Failure { Current, Report, Transition, Records, Transaction, Payment, Native,
    Readback, ReplayPayment, Replay, Dataset }

pub(crate) struct CaptureStateCatalogOriginalV3 {
    native: aos_sandbox_controller_domain::journal::StorageStateNativeCommitAttemptV1,
    native_status: Option<Result<(), aos_sandbox_controller_domain::journal::StorageStateNativeCommitClosedV1>>,
    current: Option<Result<(), StorageStateError>>,
    report: Option<Result<(), StorageStateError>>,
    transition: Option<Result<PreparedCatalogTransition, StorageStateError>>,
    preparation: CatalogTransitionPreparationOriginalV1,
    physical: CatalogPhysicalApplicationOriginalV1,
    codec: encoding::StateCodecOriginalV1,
    records: Option<Result<Vec<JournalRecord>, StorageStateError>>,
    transaction: Option<Result<JournalTransaction, JournalTransactionDataError>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    readback: Option<Result<(), StorageStateError>>,
    replay_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    replay_payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    replay: Option<Result<VerifiedStorageResolverJournalV1, StorageStateError>>,
    dataset: Option<Result<VerifiedCaptureDatasetV1,
        crate::catalog_transition::execution_capture::ExecutionCaptureDatasetErrorV1>>,
    source: Option<ObjectDigest>,
    durable_attempt: Option<ObjectDigest>,
    entered: bool,
    first: Option<Failure>,
}

impl CaptureStateCatalogOriginalV3 {
    pub(crate) fn new() -> Self {
        Self { native: aos_sandbox_controller_domain::journal::StorageStateNativeCommitAttemptV1::new(),
            native_status: None, current: None, report: None, transition: None,
            preparation: CatalogTransitionPreparationOriginalV1::new(),
            physical: CatalogPhysicalApplicationOriginalV1::new(),
            codec: encoding::StateCodecOriginalV1::default(), records: None,
            transaction: None, payment: None, readback: None, replay_demand: None,
            replay_payment: None, replay: None, dataset: None, source: None, durable_attempt: None, entered: false, first: None }
    }

    pub(crate) fn commit_once_v3(
        &mut self,
        store: &mut StorageTransactionStore,
        native: &NativeCaptureCreateOriginalV3,
        created: &NativeCaptureCreatedReadbackV3,
        receiving: &mut encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        if self.entered { return Err(StorageStateError::Receiving); }
        self.entered = true;
        self.first = Some(Failure::Current);
        self.current = Some(store.ensure_authority_readable()
            .and_then(|()| store.require_no_held_repair_guard_v1()));
        if !matches!(self.current, Some(Ok(()))) { return Err(StorageStateError::Receiving); }
        self.first = Some(Failure::Report);
        self.report = Some(created.require_native_v3(native));
        if !matches!(self.report, Some(Ok(()))) { return Err(StorageStateError::Receiving); }
        self.source = Some(native.admission_v3().source_v3().source_digest_v2());
        self.durable_attempt = Some(native.durable_attempt_digest_v3());
        let resolution = native.catalog_resolution_v3().ok_or(StorageStateError::Receiving)?;
        self.first = Some(Failure::Transition);
        self.transition = Some({
            let mut context = encoding::StateEncodingContextV1::new(receiving, &mut self.codec);
            store.catalog_transitions.prepare_capture_transition_receiving_v3(
                resolution, created.observed_v3(), store.key.key_id, &store.key.secret,
                &mut context, &mut self.preparation, &mut self.physical,
            )
        });
        let Some(Ok(transition)) = self.transition.as_ref() else { return Err(StorageStateError::Receiving); };
        self.first = Some(Failure::Records);
        self.records = Some(transition.records_receiving_v1(receiving));
        if !matches!(self.records, Some(Ok(_))) { return Err(StorageStateError::Receiving); }
        let Some(Ok(records)) = self.records.take() else { std::process::abort(); };
        let digest = Sha256::new().chain_update(b"aos.sandbox.storage.capture-catalog-transaction.v3\0")
            .chain_update(resolution.operation_v3())
            .chain_update(native.durable_attempt_digest_v3().as_bytes()).finalize();
        let mut transaction_id = [0; 16]; transaction_id.copy_from_slice(&digest[..16]);
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
        let Some(Ok(transition)) = self.transition.take() else { std::process::abort(); };
        store.catalog_transitions.install_transition(transition);
        // This is the same full protected resolver replay used by ordinary
        // effects: every ordinary/atomic/Capture operation and connected MAC
        // transition is validated. In-memory installation is never the proof.
        self.first = Some(Failure::ReplayPayment);
        self.replay_demand = Some(store.receiving_inventory_geometry_v1()
            .and_then(|geometry| geometry.retained_model_demand_v1()));
        let Some(demand) = self.replay_demand.as_ref().and_then(|result| result.as_ref().ok()).copied()
            else { return Err(StorageStateError::Receiving); };
        self.replay_payment = Some(receiving.reserve_preparation_models_v1(&store.journal, demand));
        if !matches!(self.replay_payment, Some(Ok(()))) { return Err(StorageStateError::Receiving); }
        self.first = Some(Failure::Replay);
        self.replay = Some(store.verified_resolver_journal());
        let Some(Ok(replayed)) = self.replay.as_ref() else { return Err(StorageStateError::Receiving); };
        self.first = Some(Failure::Dataset);
        self.dataset = Some(resolution.requirement_v3().verify_present(replayed.physical()));
        if !matches!(self.dataset, Some(Ok(_))) { return Err(StorageStateError::Receiving); }
        self.first = None;
        Ok(())
    }

    pub(crate) fn dataset_for_native_v3(&self, native: &NativeCaptureCreateOriginalV3)
        -> Option<&VerifiedCaptureDatasetV1>
    {
        if !self.entered || self.first.is_some()
            || self.source != Some(native.admission_v3().source_v3().source_digest_v2())
            || self.durable_attempt != Some(native.durable_attempt_digest_v3())
        { return None; }
        self.dataset.as_ref()?.as_ref().ok()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            Failure::Current => error(&self.current), Failure::Report => error(&self.report),
            Failure::Transition => self.codec.failure().or_else(|| self.physical.failure())
                .or_else(|| self.preparation.failure().map(|cause| cause as _))
                .or_else(|| error(&self.transition)),
            Failure::Records => error(&self.records), Failure::Transaction => error(&self.transaction),
            Failure::Payment => error(&self.payment),
            Failure::Native => self.native.failure().or_else(|| error(&self.native_status)),
            Failure::Readback => error(&self.readback),
            Failure::ReplayPayment => error(&self.replay_demand).or_else(|| error(&self.replay_payment)),
            Failure::Replay => error(&self.replay), Failure::Dataset => error(&self.dataset),
        }
    }
}


impl StorageTransactionStore {
    pub(crate) fn bind_capture_output_dataset_v3(
        &self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        original: &mut crate::execution_output::CapturePhysicalBindingOriginalV3,
        native: &NativeCaptureCreateOriginalV3,
        catalog: &CaptureStateCatalogOriginalV3,
        receiving: &mut encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), crate::execution_output::ExecutionOutputLedgerErrorV1> {
        output.bind_native_capture_dataset_v3(original, native, catalog, &self.journal, receiving)
    }
}

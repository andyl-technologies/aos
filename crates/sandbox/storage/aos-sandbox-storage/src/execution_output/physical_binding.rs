//! Retains the actual dedicated-dataset binding through native append/readback.
//!
//! The existing logical/physical codecs remain sole. The selected caller must
//! hold both the fresh Native issuer and its actual cold catalog original;
//! historical binding bytes cannot enter its one-shot physical writer route.

use super::*;
use crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3;
use crate::state::CaptureStateCatalogOriginalV3;

#[derive(Clone, Copy)]
enum Failure { Current, Payment, Logical, Match, Encoded, Existing, Transaction, Native, Readback }

pub(crate) struct CapturePhysicalBindingOriginalV3 {
    native: aos_sandbox_controller_domain::journal::StorageStateNativeCommitAttemptV1,
    native_status: Option<Result<(), aos_sandbox_controller_domain::journal::StorageStateNativeCommitClosedV1>>,
    current: Option<Result<(), ExecutionOutputLedgerErrorV1>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    native_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_controller_domain::JournalError>>,
    logical: Option<Result<RetainedOutputRecord, ExecutionOutputLedgerErrorV1>>,
    matches: Option<Result<(), ExecutionOutputLedgerErrorV1>>,
    physical: Option<PhysicalBindingRecord>,
    encoded: Option<Result<Vec<u8>, ExecutionOutputLedgerErrorV1>>,
    transaction: Option<Result<JournalTransaction, aos_sandbox_controller_domain::JournalError>>,
    readback: Option<Result<(), ExecutionOutputLedgerErrorV1>>,
    source: Option<ObjectDigest>,
    durable: Option<ObjectDigest>,
    digest: Option<ObjectDigest>,
    first: Option<Failure>,
    entered: bool,
}

impl CapturePhysicalBindingOriginalV3 {
    pub(crate) fn new() -> Self {
        Self { native: aos_sandbox_controller_domain::journal::StorageStateNativeCommitAttemptV1::new(),
            native_status: None, current: None, payment: None, native_demand: None, logical: None,
            matches: None, physical: None, encoded: None, transaction: None,
            readback: None, source: None, durable: None, digest: None, first: None, entered: false }
    }

    pub(crate) fn row_digest_for_native_v3(&self, native: &NativeCaptureCreateOriginalV3)
        -> Option<ObjectDigest>
    {
        if self.first.is_some() || !self.entered
            || self.source != Some(native.admission_v3().source_v3().source_digest_v2())
            || self.durable != Some(native.durable_attempt_digest_v3())
            || !matches!(self.native_status, Some(Ok(())))
            || !matches!(self.readback, Some(Ok(())))
        { return None; }
        self.digest
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            Failure::Current => error(&self.current), Failure::Payment => error(&self.native_demand).or_else(|| error(&self.payment)),
            Failure::Logical => error(&self.logical), Failure::Match | Failure::Existing => error(&self.matches),
            Failure::Encoded => error(&self.encoded), Failure::Transaction => error(&self.transaction),
            Failure::Native => self.native.failure().or_else(|| error(&self.native_status)),
            Failure::Readback => error(&self.readback),
        }
    }
}

impl ExecutionOutputLedgerV1 {
    pub(crate) fn bind_native_capture_dataset_v3(
        &mut self,
        original: &mut CapturePhysicalBindingOriginalV3,
        native: &NativeCaptureCreateOriginalV3,
        catalog: &CaptureStateCatalogOriginalV3,
        state: &aos_sandbox_controller_domain::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        if original.entered { return Err(ExecutionOutputLedgerErrorV1::Conflict); }
        original.entered = true;
        original.first = Some(Failure::Current);
        original.current = Some(self.journal.ensure_healthy().map_err(Into::into));
        if !matches!(original.current, Some(Ok(()))) { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        let verified = catalog.dataset_for_native_v3(native)
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let source = native.admission_v3().source_v3();
        original.source = Some(source.source_digest_v2());
        original.durable = Some(native.durable_attempt_digest_v3());
        let execution = *source.original_source_v1().settlement().execution().as_bytes();
        self.bind_capture_dataset_inner_v3(original, verified, execution, Some((state, receiving)))
    }

    fn bind_capture_dataset_inner_v3(
        &mut self,
        original: &mut CapturePhysicalBindingOriginalV3,
        verified: &VerifiedCaptureDatasetV1,
        execution: [u8; 16],
        mut selected: Option<(&aos_sandbox_controller_domain::Journal, &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>)>,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        // The only variable carrier is the existing bounded dataset name and
        // its canonical130-byte envelope. All actual Vec/TX/native carriers
        // and construction temporaries precede logical decode or allocation.
        let bytes = std::mem::size_of::<CapturePhysicalBindingOriginalV3>()
            .checked_add(std::mem::size_of::<JournalRecord>() + 17 + 130)
            .and_then(|bytes| bytes.checked_add(verified.dataset_name().len().checked_mul(2)?))
            .ok_or(ExecutionOutputLedgerErrorV1::Capacity)?;
        original.first = Some(Failure::Payment);
        if let Some((state, receiving)) = selected.as_mut() {
            original.native_demand = Some(aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1::
                named_demand_v1("execution-output.journal"));
            let Some(demand) = original.native_demand.as_ref().and_then(|result| result.as_ref().ok()).copied()
                else { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); };
            original.payment = Some(receiving.reserve_preparation_models_v1(state, demand));
            if !matches!(original.payment, Some(Ok(()))) { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        }
        if let Some((_, receiving)) = selected.as_mut() {
            original.payment = Some(receiving.reserve_encoded_capacity_v1(bytes, 0));
            if !matches!(original.payment, Some(Ok(()))) { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        }
        let logical_key = reservation_key(execution);
        original.first = Some(Failure::Logical);
        original.logical = Some(self.journal.get(NAMESPACE, &logical_key)
            .ok_or(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)
            .and_then(|bytes| decode_record(&logical_key, bytes, &self.key)));
        let Some(Ok(logical)) = original.logical.as_ref() else { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); };
        original.first = Some(Failure::Match);
        original.matches = Some(if logical.state == STATE_RETAINED
            && verified.matches_logical(logical.execution, logical.create, logical.claim_digest, logical.bytes)
        { Ok(()) } else { Err(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking) });
        if !matches!(original.matches, Some(Ok(()))) { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        let binding_key = physical_key(execution);
        original.physical = Some(PhysicalBindingRecord { binding: verified.binding(),
            claim_digest: logical.claim_digest, bytes: logical.bytes,
            creation_generation: verified.catalog_generation(), guid: verified.guid(),
            dataset_name: verified.dataset_name().to_owned() });
        let Some(physical) = original.physical.as_ref() else { std::process::abort(); };
        original.first = Some(Failure::Encoded);
        original.encoded = Some(encode_physical(&binding_key, physical, &self.key));
        let Some(Ok(encoded)) = original.encoded.as_ref() else { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); };
        #[cfg(test)]
        if selected.is_none() && self.journal.get(NAMESPACE, &binding_key) == Some(&encoded[..]) {
            original.first = None;
            return Ok(());
        }
        original.first = Some(Failure::Existing);
        // A prior physical row is historical/ambiguous. This freshly issued
        // native route cannot remint a writer even for byte-identical data.
        original.matches = Some(if self.journal.get(NAMESPACE, &binding_key).is_none()
            { Ok(()) } else { Err(ExecutionOutputLedgerErrorV1::Conflict) });
        if !matches!(original.matches, Some(Ok(()))) { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        original.first = Some(Failure::Transaction);
        original.transaction = Some(JournalTransaction::new(
            transaction_id(b"physical", &binding_key, verified.binding().as_bytes()),
            vec![JournalRecord::put(NAMESPACE, binding_key, encoded.clone())],
        ).map_err(aos_sandbox_controller_domain::JournalError::from));
        let Some(Ok(transaction)) = original.transaction.as_ref() else { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); };
        original.first = Some(Failure::Payment);
        if let Some((state, receiving)) = selected.as_mut() {
            original.payment = Some(receiving.reserve_capture_output_append_v3(state, &self.journal, transaction));
            if !matches!(original.payment, Some(Ok(()))) { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        }
        original.first = Some(Failure::Native);
        original.native_status = Some(original.native.commit_once_v1(&mut self.journal, transaction));
        if !matches!(original.native_status, Some(Ok(()))) { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        original.first = Some(Failure::Readback);
        original.readback = Some((|| {
            self.journal.ensure_healthy()?;
            let key = physical_key(execution);
            let actual = self.journal.get(NAMESPACE, &key).ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
            let decoded = decode_physical(&key, actual, &self.key)?;
            if actual != encoded || decoded != *physical { return Err(ExecutionOutputLedgerErrorV1::Corrupt); }
            Ok(())
        })());
        if !matches!(original.readback, Some(Ok(()))) { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        original.digest = Some(ObjectDigest::from_bytes(Sha256::digest(encoded).into()));
        original.first = None;
        Ok(())
    }
}


#[cfg(test)]
impl ExecutionOutputLedgerV1 {
    pub(super) fn bind_verified_capture_dataset_for_test_v3(
        &mut self,
        verified: &VerifiedCaptureDatasetV1,
        execution: [u8; 16],
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        let mut original = CapturePhysicalBindingOriginalV3::new();
        self.bind_capture_dataset_inner_v3(&mut original, verified, execution, None)
    }
}

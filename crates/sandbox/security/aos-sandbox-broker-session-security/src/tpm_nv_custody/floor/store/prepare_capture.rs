//! Retains the sole sidecar preparation builder's exact DATA prefix.
//!
//! The actual F owner must admit the passive supplier before calling this
//! builder. No journal, writer, floor, native completion or grant is created.

use super::*;
use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    JournalTransactionDataError,
    floor_sidecar_geometry::FloorSidecarAppendGeometryDataV2,
    transaction::PreparedTransactionEncodeCaptureV2,
};

/// Keeps the allocated intent record, encoder and constructed sidecar model.
pub(in crate::tpm_nv_custody::floor) struct SidecarPreparationOriginalV2 {
    id: Option<Result<[u8; 16], FloorErrorV1>>,
    intent_record: Option<JournalRecord>,
    transaction_key: Option<Vec<u8>>,
    encoder: PreparedTransactionEncodeCaptureV2,
    constructed: Option<Result<JournalTransaction, JournalTransactionDataError>>,
    geometry: Option<Result<FloorSidecarAppendGeometryDataV2, JournalTransactionDataError>>,
    shapes: Option<Result<(), FloorErrorV1>>,
    result: Option<Result<(), FloorErrorV1>>,
    entered: bool,
    reentry: Option<FloorErrorV1>,
}

impl SidecarPreparationOriginalV2 {
    /// Creates inert inline destinations without allocation or observation.
    pub(in crate::tpm_nv_custody::floor) const fn new() -> Self {
        Self {
            id: None,
            intent_record: None,
            transaction_key: None,
            encoder: PreparedTransactionEncodeCaptureV2::new(),
            constructed: None,
            geometry: None,
            shapes: None,
            result: None,
            entered: false,
            reentry: None,
        }
    }

    /// Measures actual encoder backing and the two canonical record carriers.
    ///
    /// Only the encoder's actual owning key index adds named entries. Sidecar
    /// keys, record-vector backing and control destinations contribute bytes.
    pub(in crate::tpm_nv_custody::floor) fn receiving_demand_v2(
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> Option<ResourceVector> {
        let encoder = PreparedTransactionEncodeCaptureV2::receiving_demand_v2(transaction, limits)?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(transaction_id_receiving_bytes_v2()?)?
            .checked_add(size_of::<JournalTransaction>())?
            .checked_add(size_of::<JournalRecord>().checked_mul(2)?)?
            .checked_add(INTENT_KEY.len())?
            .checked_add(TRANSACTION_KEY.len())?
            .checked_add(INTENT_BYTES)?;
        encoder.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)).ok()
    }

    /// Builds the canonical Broker or Online preparation after actual admission.
    ///
    /// # Errors
    /// Retains the original identity, encoder, construction or shape refusal.
    /// Reentry preserves every earlier result and allocated prefix.
    pub(in crate::tpm_nv_custody::floor) fn observe_once_v2(
        &mut self,
        intent: FloorIntentDataV1,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Unavailable);
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        let result = prepare_transaction_engine_v2(intent.into(), transaction, limits, Some(&mut *self));
        self.result = Some(result.map(|_| ()));
        self.result.as_ref().copied().unwrap_or(Err(FloorErrorV1::Unavailable))
    }

    /// Borrows only this builder's completed preparation DATA.
    pub(in crate::tpm_nv_custody::floor) fn completed_v2(&self) -> Option<&JournalTransaction> {
        if !matches!(self.result, Some(Ok(()))) || self.reentry.is_some() {
            return None;
        }
        self.constructed.as_ref()?.as_ref().ok()
    }

    /// Moves the completed DATA once, retaining the original one-shot fence.
    pub(in crate::tpm_nv_custody::floor) fn take_completed_v2(&mut self) -> Option<JournalTransaction> {
        self.completed_v2()?;
        match self.constructed.take() {
            Some(Ok(transaction)) => Some(transaction),
            other => {
                self.constructed = other;
                None
            }
        }
    }

    /// Borrows the first actual cause without discarding its owning prefix.
    pub(in crate::tpm_nv_custody::floor) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.id.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.encoder.failure().map(|cause| cause as _))
            .or_else(|| self.constructed.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.geometry.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.shapes.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

// Only retained mode uses the supplied capture. Ordinary mode keeps the old
// local record/byte/model lifetimes without constructing a capture-sized owner.
macro_rules! prepare_step {
    (Ordinary, id $original:ident, $value:expr) => { $value? };
    (Retained, id $original:ident, $value:expr) => {{
        $original.id = Some($value);
        match $original.id.as_ref() {
            Some(Ok(id)) => *id,
            Some(Err(cause)) => return Err(*cause),
            None => return Err(FloorErrorV1::Encoding),
        }
    }};
    (Ordinary, intent $original:ident, $value:expr) => { $value };
    (Retained, intent $original:ident, $value:expr) => {
        $original.intent_record = Some($value)
    };
    (Ordinary, key $original:ident, $value:expr) => { $value };
    (Retained, key $original:ident, $value:expr) => {
        $original.transaction_key = Some($value)
    };
    (Ordinary, encoded $original:ident, $transaction:ident, $limits:ident) => {
        $transaction.encode_prepared_v1($limits).map_err(|_| FloorErrorV1::Encoding)?
    };
    (Retained, encoded $original:ident, $transaction:ident, $limits:ident) => {{
        $original.encoder.encode_once_v2($transaction, $limits)
            .map_err(|_| FloorErrorV1::Encoding)?;
        $original.encoder.take_completed_v2().ok_or(FloorErrorV1::Encoding)?
    }};
    (Ordinary, intent_value $original:ident, $local:ident) => { $local };
    (Retained, intent_value $original:ident, $local:ident) => {
        $original.intent_record.take().ok_or(FloorErrorV1::Encoding)?
    };
    (Ordinary, key_value $original:ident, $local:ident) => { $local };
    (Retained, key_value $original:ident, $local:ident) => {
        $original.transaction_key.take().ok_or(FloorErrorV1::Encoding)?
    };
    (Ordinary, constructed $original:ident, $value:expr) => {
        $value.map_err(|_| FloorErrorV1::Encoding)?
    };
    (Retained, constructed $original:ident, $value:expr) => {{
        $original.constructed = Some($value);
        $original.constructed.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(FloorErrorV1::Encoding)?
    }};
    (Ordinary, geometry $original:ident, $value:expr) => {
        $value.map_err(|_| FloorErrorV1::Encoding)?
    };
    (Retained, geometry $original:ident, $value:expr) => {{
        $original.geometry = Some($value);
        $original.geometry.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(FloorErrorV1::Encoding)?
    }};
    (Ordinary, shapes $original:ident, $value:expr) => { $value? };
    (Retained, shapes $original:ident, $value:expr) => {{
        $original.shapes = Some($value);
        match $original.shapes.as_ref() {
            Some(Ok(())) => (),
            Some(Err(cause)) => return Err(*cause),
            None => return Err(FloorErrorV1::Encoding),
        }
    }};
    (Ordinary, finish $prepared:ident) => { Ok(Some($prepared)) };
    (Retained, finish $prepared:ident) => { Ok(None) };
}

// This is the one ordered ID/record/encode/constructor/shape recipe. The
// destination branches above change custody, never domains, bytes or guards.
macro_rules! prepare_recipe {
    ($mode:ident, $original:ident, $intent:ident, $transaction:ident, $limits:ident) => {{
        let id = prepare_step!($mode, id $original,
            transaction_id($intent.prepare_domain(), $intent));
        let _intent_record = prepare_step!($mode, intent $original, JournalRecord::put(
            $intent.namespace(), INTENT_KEY.to_vec(), $intent.encode().to_vec(),
        ));
        let _transaction_key = prepare_step!($mode, key $original, TRANSACTION_KEY.to_vec());
        let encoded = prepare_step!($mode, encoded $original, $transaction, $limits);
        // The checked nonzero ID and two records preserve the original
        // constructor invariant; retained mode keeps its real result/model.
        let prepared = prepare_step!($mode, constructed $original, JournalTransaction::new(id, vec![
            prepare_step!($mode, intent_value $original, _intent_record),
            JournalRecord::put($intent.namespace(),
                prepare_step!($mode, key_value $original, _transaction_key), encoded),
        ]));
        let geometry = prepare_step!($mode, geometry $original,
            FloorSidecarAppendGeometryDataV2::from_transaction_v2($transaction, $limits));
        prepare_step!($mode, shapes $original,
            require_record_shapes_v2(&prepared, geometry.preparation_records.into_iter()));
        prepare_step!($mode, finish prepared)
    }};
}

pub(super) fn prepare_transaction_engine_v2(
    intent: SidecarIntentDataV1,
    transaction: &JournalTransaction,
    main_limits: JournalLimits,
    capture: Option<&mut SidecarPreparationOriginalV2>,
) -> Result<Option<JournalTransaction>, FloorErrorV1> {
    match capture {
        Some(original) => prepare_recipe!(Retained, original, intent, transaction, main_limits),
        None => prepare_recipe!(Ordinary, original, intent, transaction, main_limits),
    }
}

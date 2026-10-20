//! Retains the sole finalization constructor's reached DATA prefix.
//!
//! The actual F owner prepays this passive supplier before allocating the
//! constructor. The sink creates neither authority nor a native completion.

use super::*;
use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError;

/// Keeps canonical finalization DATA and its first constructor refusal.
pub(in crate::tpm_nv_custody::floor) struct SidecarFinalizationOriginalV2 {
    id: Option<Result<[u8; 16], FloorErrorV1>>,
    checkpoint_record: Option<JournalRecord>,
    intent_key: Option<Vec<u8>>,
    transaction_key: Option<Vec<u8>>,
    constructed: Option<Result<JournalTransaction, JournalTransactionDataError>>,
    shapes: Option<Result<(), FloorErrorV1>>,
    returned: Option<Result<(), FloorErrorV1>>,
    entered: bool,
    reentry: Option<FloorErrorV1>,
}

impl SidecarFinalizationOriginalV2 {
    /// Creates inline destinations without allocation or observation.
    pub(in crate::tpm_nv_custody::floor) const fn new() -> Self {
        Self {
            id: None,
            checkpoint_record: None,
            intent_key: None,
            transaction_key: None,
            constructed: None,
            shapes: None,
            returned: None,
            entered: false,
            reentry: None,
        }
    }

    /// Prices the constructor, its move destination and canonical record bytes.
    ///
    /// These three ordered record slots and their keys are model backing, not
    /// map entries. No Metadata credit is inferred from Rust destinations.
    pub(in crate::tpm_nv_custody::floor) fn receiving_demand_v2() -> Option<ResourceVector> {
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(transaction_id_receiving_bytes_v2()?)?
            .checked_add(size_of::<JournalTransaction>())?
            .checked_add(size_of::<JournalRecord>().checked_mul(3)?)?
            .checked_add(CHECKPOINT_KEY.len())?
            .checked_add(INTENT_KEY.len())?
            .checked_add(TRANSACTION_KEY.len())?
            .checked_add(CHECKPOINT_BYTES)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Builds the same final suffix into retained DATA destinations once.
    ///
    /// # Errors
    /// Retains the original identity, transaction or record-shape refusal.
    /// Reentry preserves every earlier allocated prefix and original cause.
    pub(in crate::tpm_nv_custody::floor) fn observe_once_v2(
        &mut self,
        intent: FloorIntentDataV1,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Unavailable);
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;

        let result = finalize_transaction_engine_v2(intent.into(), Some(&mut *self));
        self.returned = Some(result.map(|_| ()));
        self.returned.as_ref().copied().unwrap_or(Err(FloorErrorV1::Unavailable))
    }

    /// Borrows only the completed canonical final suffix DATA.
    pub(in crate::tpm_nv_custody::floor) fn completed_v2(&self) -> Option<&JournalTransaction> {
        if !matches!(self.returned, Some(Ok(()))) || self.reentry.is_some() {
            return None;
        }
        self.constructed.as_ref()?.as_ref().ok()
    }

    /// Moves the completed DATA once while retaining its original entry fence.
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

    /// Borrows the first actual constructor refusal without replacing its owner.
    pub(in crate::tpm_nv_custody::floor) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.id.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.constructed.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.shapes.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

// Ordinary mode keeps its original locals. Only retained mode owns the sink;
// a None call never constructs a capture-sized stack value.
macro_rules! finalize_step {
    (Ordinary, id $original:ident, $value:expr) => { $value? };
    (Retained, id $original:ident, $value:expr) => {{
        $original.id = Some($value);
        match $original.id.as_ref() {
            Some(Ok(id)) => *id,
            Some(Err(cause)) => return Err(*cause),
            None => return Err(FloorErrorV1::Encoding),
        }
    }};
    (Ordinary, checkpoint $original:ident, $value:expr) => { $value };
    (Retained, checkpoint $original:ident, $value:expr) => {
        $original.checkpoint_record = Some($value)
    };
    (Ordinary, intent_key $original:ident, $value:expr) => { $value };
    (Retained, intent_key $original:ident, $value:expr) => {
        $original.intent_key = Some($value)
    };
    (Ordinary, transaction_key $original:ident, $value:expr) => { $value };
    (Retained, transaction_key $original:ident, $value:expr) => {
        $original.transaction_key = Some($value)
    };
    (Ordinary, checkpoint_value $original:ident, $local:ident) => { $local };
    (Retained, checkpoint_value $original:ident, $local:ident) => {
        $original.checkpoint_record.take().ok_or(FloorErrorV1::Encoding)?
    };
    (Ordinary, intent_value $original:ident, $local:ident) => { $local };
    (Retained, intent_value $original:ident, $local:ident) => {
        $original.intent_key.take().ok_or(FloorErrorV1::Encoding)?
    };
    (Ordinary, transaction_value $original:ident, $local:ident) => { $local };
    (Retained, transaction_value $original:ident, $local:ident) => {
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
    (Ordinary, shapes $original:ident, $value:expr) => { $value? };
    (Retained, shapes $original:ident, $value:expr) => {{
        $original.shapes = Some($value);
        match $original.shapes.as_ref() {
            Some(Ok(())) => (),
            Some(Err(cause)) => return Err(*cause),
            None => return Err(FloorErrorV1::Encoding),
        }
    }};
    (Ordinary, result $value:ident) => { Ok(Some($value)) };
    (Retained, result $value:ident) => { Ok(None) };
}

macro_rules! finalize_recipe {
    ($mode:ident, $intent:ident, $original:ident) => {{
        let id = finalize_step!($mode, id $original,
            transaction_id($intent.finalize_domain(), $intent));
        let checkpoint = finalize_step!($mode, checkpoint $original,
            JournalRecord::put($intent.namespace(), CHECKPOINT_KEY.to_vec(),
                $intent.target_bytes().to_vec()));
        let intent_key = finalize_step!($mode, intent_key $original, INTENT_KEY.to_vec());
        let transaction_key = finalize_step!($mode, transaction_key $original,
            TRANSACTION_KEY.to_vec());

        // The validated nonzero ID and these three records satisfy the existing
        // JournalTransaction constructor invariant before moving their backing.
        let finalized = finalize_step!($mode, constructed $original,
            JournalTransaction::new(id, vec![
                finalize_step!($mode, checkpoint_value $original, checkpoint),
                JournalRecord::delete($intent.namespace(),
                    finalize_step!($mode, intent_value $original, intent_key)),
                JournalRecord::delete($intent.namespace(),
                    finalize_step!($mode, transaction_value $original, transaction_key)),
            ]));
        finalize_step!($mode, shapes $original,
            require_record_shapes_v2(&finalized, aos_sandbox_protocol::domain_ledger::
                floor_sidecar_geometry::finalization_record_shapes_v2().into_iter()));
        finalize_step!($mode, result finalized)
    }};
}

pub(super) fn finalize_transaction_engine_v2(
    intent: SidecarIntentDataV1,
    original: Option<&mut SidecarFinalizationOriginalV2>,
) -> Result<Option<JournalTransaction>, FloorErrorV1> {
    match original {
        None => finalize_recipe!(Ordinary, intent, unused),
        Some(original) => finalize_recipe!(Retained, intent, original),
    }
}

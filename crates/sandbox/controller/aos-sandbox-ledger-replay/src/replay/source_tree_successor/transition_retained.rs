//! Retains reached saved Source transition DATA and the original typed cause.

use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
use std::mem::size_of;

use super::*;
use super::retained::SourceFamilyOriginalsV1;

/// Borrows the exact reached transition destinations without IO or authority.
pub type SourceTransitionSinksV1<'a, E, H, R> = (
    Option<&'a mut SourceFamilyOriginalsV1<E, H, R>>, Option<&'a mut SourceFamilyOriginalsV1<E, H, R>>,
    Option<&'a mut Option<SourceFirstSuccessorRowsV2>>,
    Option<&'a mut Option<SourceFirstSuccessorReceiptV2>>,
    Option<&'a mut Option<SourceFirstSuccessorPendingV2>>,
    Option<&'a mut Option<GlobalCapacityReservationRequestV1>>,
    Option<&'a mut Option<JournalRecord>>, Option<&'a mut Option<SourceFirstSuccessorAckV2>>,
    Option<&'a mut Option<JournalRecord>>, Option<&'a mut Option<State>>,
    Option<&'a mut Option<SourceFirstSuccessorRowsV2>>,
    Option<&'a mut crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1<E, H, R>>,
);

/// Retains one complete transition comparison and its first typed cause.
pub struct SourceTransitionOriginalsV1<E = JournalError, H = DomainLedgerDataError, R = crate::genesis::SourceGenesisReceiptDataErrorV1> {
    /// Retains the reached before family DATA at its original frontier.
    pub before_family: SourceFamilyOriginalsV1<E, H, R>,
    /// Retains the reached after family DATA at its original frontier.
    pub after_family: SourceFamilyOriginalsV1<E, H, R>,
    /// Retains the reached rows DATA at its original frontier.
    pub rows: Option<SourceFirstSuccessorRowsV2>,
    /// Retains the reached receipt DATA at its original frontier.
    pub receipt: Option<SourceFirstSuccessorReceiptV2>,
    /// Retains the reached pending DATA at its original frontier.
    pub pending: Option<SourceFirstSuccessorPendingV2>,
    /// Retains the reached request DATA at its original frontier.
    pub request: Option<GlobalCapacityReservationRequestV1>,
    /// Retains the reached expected capacity DATA at its original frontier.
    pub expected_capacity: Option<JournalRecord>,
    /// Retains the reached ack DATA at its original frontier.
    pub ack: Option<SourceFirstSuccessorAckV2>,
    /// Retains the reached expected deletion DATA at its original frontier.
    pub expected_deletion: Option<JournalRecord>,
    /// Retains the reached after DATA at its original frontier.
    pub after: Option<State>,
    /// Retains the reached next rows DATA at its original frontier.
    pub next_rows: Option<SourceFirstSuccessorRowsV2>,
    /// Retains the reached members DATA at its original frontier.
    pub members: crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1<E, H, R>,
    /// Retains the reached result DATA at its original frontier.
    pub result: Option<Result<Option<[u8; 32]>, E>>,
    /// Retains the reached closed DATA at its original frontier.
    pub closed: Option<E>,
    /// Retains the reached entered DATA at its original frontier.
    pub entered: bool,
}

impl<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceTransitionOriginalsV1<E, H, R> {
    /// Creates an inert, allocation-free historical comparison destination.
    pub fn new() -> Self {
        Self {
            before_family: SourceFamilyOriginalsV1::<E, H, R>::new(),
            after_family: SourceFamilyOriginalsV1::<E, H, R>::new(),
            rows: None, receipt: None, pending: None, request: None,
            expected_capacity: None, ack: None, expected_deletion: None,
            after: None, next_rows: None,
            members: crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1::<E, H, R>::new(),
            result: None, closed: None, entered: false,
        }
    }

    /// Runs the original one-shot saved comparison without native authority.
    ///
    /// # Errors
    /// Rejects an incomplete, invalid or repeated comparison.
    pub fn observe_once(
        &mut self,
        state: &State,
        transaction: &JournalTransaction,
        phase: Option<FirstSourceSuccessorNativePhaseV2>,
        recipe: SourceSuccessorFamilyRecipeV3,
    ) -> Result<Option<[u8; 32]>, E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        self.result = Some(require_source_transition_engine::<E, H, R>(state, transaction, phase, recipe, Some(self)));
        match &self.result {
            Some(Ok(value)) => Ok(*value),
            _ => Err(E::from(JournalError::ProtectedBoundary)),
        }
    }

    /// Borrows the original first typed comparison cause.
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before_family.genesis_rows.cause()
            .or_else(|| self.before_family.members.failure())
            .or_else(|| self.members.failure())
            .or_else(|| self.after_family.genesis_rows.cause())
            .or_else(|| self.after_family.members.failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Prices actual compiled byte carriers without namespace field fees.
    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        let (family_bytes, _family_cells) = SourceFamilyOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let (member_bytes, _member_cells) = crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(family_bytes.checked_sub(size_of::<SourceFamilyOriginalsV1<E, H, R>>().checked_mul(2)?)?.checked_mul(2)?)?
            .checked_add(member_bytes.checked_sub(size_of::<crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorRowsV2>>().checked_mul(2)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorReceiptV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorPendingV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, GlobalCapacityReservationRequestV1>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, JournalRecord>>().checked_mul(2)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorAckV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, State>>())?
            .checked_add(size_of::<SourceTransitionSinksV1<'static, E, H, R>>())?
            .checked_add(size_of::<Option<&'static mut Self>>().checked_mul(3)?)?
            .checked_add(fixed_recipe_footprint_v1()?.0)?
            .checked_add(size_of::<aos_sandbox_model::ResourceVector>().checked_mul(4)?)?
            .checked_add(size_of::<Result<aos_sandbox_model::ResourceVector, E>>())?
            .checked_add(size_of::<[aos_sandbox_model::ResourceDimension; aos_sandbox_model::ResourceDimension::COUNT]>().checked_mul(2)?)?
            .checked_add(size_of::<std::array::IntoIter<aos_sandbox_model::ResourceDimension, { aos_sandbox_model::ResourceDimension::COUNT }>>())?
            .checked_add(size_of::<u64>().checked_mul(2)?)?
            // Explicit lower/Native result projection carriers, all DATA.
            .checked_add(size_of::<Result<aos_sandbox_model::ResourceVector, JournalError>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<Option<[u8; 32]>, JournalError>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<bool, JournalError>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), JournalError>>().checked_mul(2)?)?;
        // Compiled fields and controls are bytes, not namespace entries.
        Some((bytes, 0))
    }
}

/// Retains one complete raw-COMMIT Source fold without issuing authority.
pub struct SourceReplayTransactionOriginalsV1<E = JournalError, H = DomainLedgerDataError, R = crate::genesis::SourceGenesisReceiptDataErrorV1> {
    /// Retains the reached source DATA at its original frontier.
    pub source: SourceTransitionOriginalsV1<E, H, R>,
    /// Retains the reached project DATA at its original frontier.
    pub project: SourceProjectGenesisOriginalsV1<E, H, R>,
    /// Retains the reached genesis DATA at its original frontier.
    pub genesis: crate::replay::source_tree_genesis::SourceGenesisMutationOriginalsV1<E, H, R>,
    /// Retains the reached result DATA at its original frontier.
    pub result: Option<Result<bool, E>>,
    /// Retains the reached closed DATA at its original frontier.
    pub closed: Option<E>,
    /// Retains the reached entered DATA at its original frontier.
    pub entered: bool,
}

impl<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceReplayTransactionOriginalsV1<E, H, R> {
    /// Creates an inert, allocation-free historical comparison destination.
    pub fn new() -> Self {
        Self {
            source: SourceTransitionOriginalsV1::<E, H, R>::new(),
            project: SourceProjectGenesisOriginalsV1::<E, H, R>::new(),
            genesis: crate::replay::source_tree_genesis::SourceGenesisMutationOriginalsV1::<E, H, R>::new(),
            result: None, closed: None, entered: false,
        }
    }

    /// Runs the original one-shot saved comparison without native authority.
    ///
    /// # Errors
    /// Rejects an incomplete, invalid or repeated comparison.
    pub fn observe_once(
        &mut self,
        state: &State,
        transaction: &JournalTransaction,
        limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
    ) -> Result<bool, E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        self.result = Some(validate_replayed_transaction_with_originals::<E, H, R>(
            state, transaction, limits, Some(&mut self.source), Some(&mut self.genesis), Some(&mut self.project),
        ));
        match &self.result {
            Some(Ok(value)) => Ok(*value),
            _ => Err(E::from(JournalError::ProtectedBoundary)),
        }
    }

    /// Runs the original one-shot saved comparison without native authority.
    ///
    /// # Errors
    /// Rejects an incomplete, invalid or repeated comparison.
    pub fn require_complete(&self) -> Result<(), E> {
        if self.closed.is_none() && matches!(self.result, Some(Ok(_))) { Ok(()) }
        else { Err(E::from(JournalError::ProtectedBoundary)) }
    }

    /// Borrows the original first typed comparison cause.
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.project.cause()
            .or_else(|| self.source.cause())
            .or_else(|| self.genesis.cause())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Prices lazy diagnostic ownership beside the unchanged constructor peak.
    ///
    /// The fixed footprint covers the constructor's nested pieces and returned
    /// value. This adds the distinct resident pointee before that value moves,
    /// its optional Box handle and compiled allocation-layout carrier. No
    /// placement elision, namespace fee or native resampling is assumed.
    /// A genuine caller must pay this DATA before entering the semantic hook.
    #[must_use]
    pub fn boxed_footprint_v1() -> Option<(usize, usize)> {
        let (bytes, cells) = Self::fixed_footprint_v1()?;
        let bytes = bytes
            .checked_add(size_of::<Self>())?
            .checked_add(size_of::<Option<Box<Self>>>())?
            .checked_add(size_of::<std::alloc::Layout>())?;
        Some((bytes, cells))
    }

    /// Prices actual compiled byte carriers without namespace field fees.
    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        let (bytes, _cells) = SourceTransitionOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let (project_bytes, _project_cells) = SourceProjectGenesisOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let (genesis_bytes, _genesis_cells) = crate::replay::source_tree_genesis::SourceGenesisMutationOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        Some((size_of::<Self>().checked_mul(2)?
            .checked_add(project_bytes.checked_sub(size_of::<SourceProjectGenesisOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(genesis_bytes.checked_sub(size_of::<crate::replay::source_tree_genesis::SourceGenesisMutationOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(bytes.checked_sub(size_of::<SourceTransitionOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<&'static mut Option<Self>>())?
            .checked_add(size_of::<bool>().checked_mul(2)?)?
            .checked_add(size_of::<Result<bool, E>>())?,
            // Compiled fields and controls are bytes, not namespace entries.
            0))
    }
}

// These are the exact already-existing closed sizing and comparison recipes.
// Their fixed backing does not depend on trusting a supplied capacity value.
fn fixed_recipe_footprint_v1() -> Option<(usize, usize)> {
    use aos_sandbox_protocol::domain_ledger::capacity::{RESERVATION_KEY_BYTES_V1, VALUE_BYTES_V2};
    let expected_records = RESERVATION_KEY_BYTES_V1.checked_mul(2)?.checked_add(VALUE_BYTES_V2)?;
    let suffix = PENDING_KEY.len().checked_add(ACK_PREFIX.len())?.checked_add(16)?
        .checked_add(ACK_SIZING_BYTES)?.checked_add(RESERVATION_KEY_BYTES_V1)?;
    let comparisons = PENDING_KEY.len().checked_add(RECEIPT_PREFIX.len())?.checked_add(16)?
        .checked_add(ACK_PREFIX.len())?.checked_add(16)?;
    let bytes = expected_records.checked_add(suffix)?.checked_add(comparisons)?
        .checked_add(size_of::<[JournalRecord; 3]>())?
        .checked_add(size_of::<JournalRecord>().checked_mul(3)?)?
        .checked_add(size_of::<Vec<JournalRecord>>().checked_mul(2)?)?
        .checked_add(size_of::<JournalTransaction>().checked_mul(3)?)?
        .checked_add(size_of::<GlobalCapacityReservationRequestV1>().checked_mul(2)?)?;
    // These are compiled carriers and backing bytes, not namespace entries.
    // No FD or authority is represented.
    Some((bytes, 0))
}

/// Bounds the original map entries and byte backing from actual reached rows.
///
/// # Errors
/// Rejects checked arithmetic overflow in the reached-state bound.
pub fn dynamic_demand_v1(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<aos_sandbox_model::ResourceVector, JournalError> {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    use crate::replay::source_tree_genesis::SourceGenesisAckV1;
    let overflow = || JournalError::LimitExceeded("Source COMMIT family backing");
    let mut count = state.len();
    let mut encoded = 0usize;
    for ((_, key), value) in state {
        encoded = encoded.checked_add(key.len()).and_then(|bytes| bytes.checked_add(value.len())).ok_or_else(overflow)?;
    }
    for record in transaction.records() {
        if let Some(value) = record.value() {
            count = count.checked_add(1).ok_or_else(overflow)?;
            encoded = encoded.checked_add(record.key().len()).and_then(|bytes| bytes.checked_add(value.len())).ok_or_else(overflow)?;
        }
    }
    fn nodes<T>(count: usize) -> Option<usize> {
        size_of::<T>().checked_mul(11)?.checked_add(size_of::<usize>().checked_mul(12)?)?.checked_mul(count)
    }
    let successor = nodes::<(ProjectId, SourceFirstSuccessorReceiptV2)>(count)
        .and_then(|bytes| bytes.checked_add(nodes::<(ProjectId, SourceFirstSuccessorAckV2)>(count)?))
        .and_then(|bytes| bytes.checked_mul(3)).ok_or_else(overflow)?;
    // Before/after and predecessor folds plus their four member owners have
    // seven concrete genesis decoder destinations. Final mutation is separate.
    let genesis = nodes::<(ProjectId, crate::genesis::SourceTreeGenesisReceiptV1)>(count)
        .and_then(|bytes| bytes.checked_add(nodes::<(ProjectId, SourceGenesisAckV1)>(count)?))
        .and_then(|bytes| bytes.checked_mul(7)).ok_or_else(overflow)?;
    let families = successor.checked_add(genesis).ok_or_else(overflow)?;
    let bytes = nodes::<((RecordNamespace, Vec<u8>), Vec<u8>)>(count)
        .and_then(|bytes| bytes.checked_add(families))
        // One materialized State plus the seven named genesis byte planes.
        .and_then(|bytes| bytes.checked_add(encoded.checked_mul(8)?)).ok_or_else(overflow)?;
    // Six successor maps, fourteen genesis maps and actual State entries.
    // Key/value and receipt byte backing is already paid in MemoryBytes.
    let cells = count.checked_mul(6 + 14 + 1).ok_or_else(overflow)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow())?)
        .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| overflow())?))
}

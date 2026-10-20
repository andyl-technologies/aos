//! Retains the actual first-successor genesis-predecessor comparison.

use std::mem::size_of;
use aos_sandbox_core::bounded_codec::CaptureOnDropV1;

use super::*;
use super::retained::SourceFamilyOriginalsV1;
use crate::replay::source_tree_genesis::SourceGenesisRowsV1;

pub struct SourceGenesisPredecessorOriginalsV1<E = JournalError, H = DomainLedgerDataError, R = crate::genesis::SourceGenesisReceiptDataErrorV1> {
    pub family: SourceFamilyOriginalsV1<E, H, R>,
    pub replay: SourceReplayFamilyOriginalsV1<E, H, R>,
    pub genesis: Option<SourceGenesisRowsV1>,
    pub rows: Option<SourceFirstSuccessorRowsV2>,
    pub receipt: Option<SourceFirstSuccessorReceiptV2>,
    pub result: Option<Result<(), E>>,
    pub closed: Option<E>,
    pub entered: bool,
}

impl<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceGenesisPredecessorOriginalsV1<E, H, R> {
    pub fn new() -> Self {
        Self {
            family: SourceFamilyOriginalsV1::new(), replay: SourceReplayFamilyOriginalsV1::new(),
            genesis: None, rows: None, receipt: None, result: None, closed: None, entered: false,
        }
    }

    pub fn observe_once(&mut self, state: &State, transaction: &JournalTransaction) -> Result<(), E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        self.result = Some(require_genesis_predecessor_engine(state, transaction, Some(self)));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(E::from(JournalError::ProtectedBoundary)) }
    }

    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.family.genesis_rows.cause()
            .or_else(|| self.family.members.failure())
            .or_else(|| self.replay.cause())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        let (family_bytes, family_cells) = SourceFamilyOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let (replay_bytes, replay_cells) = SourceReplayFamilyOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(family_bytes.checked_sub(size_of::<SourceFamilyOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(replay_bytes.checked_sub(size_of::<SourceReplayFamilyOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceGenesisRowsV1>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorRowsV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorReceiptV2>>())?
            .checked_add(size_of::<Option<&'static mut Self>>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&'static mut SourceFamilyOriginalsV1<E, H, R>>>())?
            .checked_add(size_of::<Option<&'static mut SourceReplayFamilyOriginalsV1<E, H, R>>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceGenesisRowsV1>>>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&'static mut Option<SourceFirstSuccessorRowsV2>>>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&'static mut Option<SourceFirstSuccessorReceiptV2>>>().checked_mul(2)?)?;
        // Eight slots, concrete nested destinations, three two-field guards,
        // two three-root returned families and ten actual optional loan lanes.
        Some((bytes, 8usize.checked_add(family_cells)?.checked_add(replay_cells)?.checked_add(3 * 2 + 2 * 3 + 10)?))
    }
}

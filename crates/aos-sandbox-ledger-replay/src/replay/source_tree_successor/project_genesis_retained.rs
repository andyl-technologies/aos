//! Keeps the actual project-genesis selection and before/after comparison DATA.

use super::*;
use aos_sandbox_core::bounded_codec::CaptureOnDropV1;
use super::retained::SourceFamilyOriginalsV1;
use crate::replay::source_tree_genesis::{SourceGenesisRowsV1};
use super::super::source_tree_genesis::{SourceGenesisMutationOriginalsV1, SourceGenesisRowsOriginalsV1};
use crate::genesis::SourceTreeGenesisReceiptV1;
use std::mem::size_of;
type SourceGenesisReceiptDecodeOriginalsV1<R> =
    crate::genesis::SourceGenesisReceiptDecodeOriginalsV1<R>;

pub struct SourceGenesisSelectionOriginalsV1<E = JournalError, R = crate::genesis::SourceGenesisReceiptDataErrorV1> {
    pub receipt: Option<SourceTreeGenesisReceiptV1>,
    pub receipt_decode: Option<SourceGenesisReceiptDecodeOriginalsV1<R>>,
    pub parser: SourceGenesisRowsOriginalsV1<E, R>,
    pub rows: Option<SourceGenesisRowsV1>,
    pub result: Option<Result<Option<ProjectId>, E>>,
    pub closed: Option<E>,
    pub entered: bool,
}

impl<E: From<JournalError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceGenesisSelectionOriginalsV1<E, R> {
    pub fn new() -> Self {
        Self {
            receipt: None,
            receipt_decode: None,
            parser: SourceGenesisRowsOriginalsV1::new(),
            rows: None,
            result: None,
            closed: None,
            entered: false,
        }
    }

    pub fn observe_once(
        &mut self,
        state: &State,
        transaction: &JournalTransaction,
        phase: Option<FirstSourceSuccessorNativePhaseV2>,
    ) -> Result<Option<ProjectId>, E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        self.result = Some(select_replayed_genesis_project_engine(state, transaction, phase, Some(self)));
        match &self.result {
            Some(Ok(project)) => Ok(*project),
            _ => Err(E::from(JournalError::ProtectedBoundary)),
        }
    }

    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.parser.cause()
            .or_else(|| self.receipt_decode.as_ref().and_then(|capture| capture.failure()))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        let (receipt_bytes, receipt_cells) = SourceGenesisReceiptDecodeOriginalsV1::<R>::fixed_footprint_v1()?;
        let (parser_bytes, parser_cells) = SourceGenesisRowsOriginalsV1::<E, R>::fixed_footprint_v1()?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(receipt_bytes.checked_sub(size_of::<SourceGenesisReceiptDecodeOriginalsV1<R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<Option<&mut Option<SourceGenesisReceiptDecodeOriginalsV1<R>>>>())?
            .checked_add(parser_bytes.checked_sub(size_of::<SourceGenesisRowsOriginalsV1<E, R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceTreeGenesisReceiptV1>>())?
            .checked_add(size_of::<SourceGenesisRowsV1>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&'static mut Self>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceTreeGenesisReceiptV1>>>())?
            .checked_add(size_of::<Option<&'static mut SourceGenesisRowsOriginalsV1<E, R>>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceGenesisRowsV1>>>())?
            .checked_add(size_of::<Result<Option<ProjectId>, E>>())?;
        // Seven owner fields; receipt decoder/parser; receipt guard2; two returned-row
        // namespaces3 each; four concrete optional loans; whole result cell.
        Some((bytes, 6usize.checked_add(receipt_cells)?.checked_add(parser_cells)?.checked_add(2 + 2 * 3 + 4 + 1)?))
    }
}

pub struct SourceProjectGenesisOriginalsV1<E = JournalError, H = DomainLedgerDataError, R = crate::genesis::SourceGenesisReceiptDataErrorV1> {
    pub selection: SourceGenesisSelectionOriginalsV1<E, R>,
    pub before_family: SourceFamilyOriginalsV1<E, H, R>,
    pub after_family: SourceFamilyOriginalsV1<E, H, R>,
    pub before: Option<SourceFirstSuccessorRowsV2>,
    pub next: Option<SourceFirstSuccessorRowsV2>,
    pub receipt: Option<SourceTreeGenesisReceiptV1>,
    pub receipt_decode: Option<SourceGenesisReceiptDecodeOriginalsV1<R>>,
    pub anchor_parser: SourceGenesisRowsOriginalsV1<E, R>,
    pub anchor_rows: Option<SourceGenesisRowsV1>,
    pub mutation: SourceGenesisMutationOriginalsV1<E, H, R>,
    pub after: Option<State>,
    pub result: Option<Result<(), E>>,
    pub closed: Option<E>,
    pub entered: bool,
}

impl<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceProjectGenesisOriginalsV1<E, H, R> {
    pub fn new() -> Self {
        Self {
            selection: SourceGenesisSelectionOriginalsV1::new(),
            before_family: SourceFamilyOriginalsV1::new(),
            after_family: SourceFamilyOriginalsV1::new(),
            before: None,
            next: None,
            receipt: None,
            receipt_decode: None,
            anchor_parser: SourceGenesisRowsOriginalsV1::new(),
            anchor_rows: None,
            mutation: SourceGenesisMutationOriginalsV1::new(),
            after: None,
            result: None,
            closed: None,
            entered: false,
        }
    }

    pub fn observe_once(
        &mut self,
        state: &State,
        transaction: &JournalTransaction,
        project: ProjectId,
    ) -> Result<(), E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        self.result = Some(require_project_genesis_transition_engine(state, transaction, project, Some(self)));
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(E::from(JournalError::ProtectedBoundary))
        }
    }

    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.selection.cause()
            .or_else(|| self.before_family.genesis_rows.cause())
            .or_else(|| self.before_family.members.failure())
            .or_else(|| self.receipt_decode.as_ref().and_then(|capture| capture.failure()))
            .or_else(|| self.anchor_parser.cause())
            .or_else(|| self.mutation.cause())
            .or_else(|| self.after_family.genesis_rows.cause())
            .or_else(|| self.after_family.members.failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        let (receipt_bytes, receipt_cells) = SourceGenesisReceiptDecodeOriginalsV1::<R>::fixed_footprint_v1()?;
        let (selection_bytes, selection_cells) = SourceGenesisSelectionOriginalsV1::<E, R>::fixed_footprint_v1()?;
        let (family_bytes, family_cells) = SourceFamilyOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let (anchor_bytes, anchor_cells) = SourceGenesisRowsOriginalsV1::<E, R>::fixed_footprint_v1()?;
        let (mutation_bytes, mutation_cells) = SourceGenesisMutationOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(receipt_bytes.checked_sub(size_of::<SourceGenesisReceiptDecodeOriginalsV1<R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<Option<&mut Option<SourceGenesisReceiptDecodeOriginalsV1<R>>>>())?
            .checked_add(selection_bytes.checked_sub(size_of::<SourceGenesisSelectionOriginalsV1<E, R>>().checked_mul(2)?)?)?
            .checked_add(family_bytes.checked_sub(size_of::<SourceFamilyOriginalsV1<E, H, R>>().checked_mul(2)?)?.checked_mul(2)?)?
            .checked_add(anchor_bytes.checked_sub(size_of::<SourceGenesisRowsOriginalsV1<E, R>>().checked_mul(2)?)?)?
            .checked_add(mutation_bytes.checked_sub(size_of::<SourceGenesisMutationOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorRowsV2>>().checked_mul(2)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceTreeGenesisReceiptV1>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, State>>())?
            .checked_add(size_of::<SourceGenesisRowsV1>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&'static mut SourceFamilyOriginalsV1<E, H, R>>>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&'static mut Option<SourceFirstSuccessorRowsV2>>>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&'static mut Option<SourceTreeGenesisReceiptV1>>>())?
            .checked_add(size_of::<Option<&'static mut SourceGenesisRowsOriginalsV1<E, R>>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceGenesisRowsV1>>>())?
            .checked_add(size_of::<Option<&'static mut SourceGenesisMutationOriginalsV1<E, H, R>>>())?
            .checked_add(size_of::<Option<&'static mut Option<State>>>())?
            .checked_add(size_of::<Option<&'static mut Self>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), E>>())?;
        // Fourteen owner fields, including the concrete receipt decoder; four guards2,
        // two returned successor namespaces3, two anchor-row namespaces3,
        // the State root1, nine sink loans +three wrapper/reborrow lanes,
        // mismatch DATA and the returned whole result.
        let cells = 13usize.checked_add(receipt_cells)?.checked_add(selection_cells)?
            .checked_add(family_cells.checked_mul(2)?)?.checked_add(anchor_cells)?
            .checked_add(mutation_cells)?.checked_add(4 * 2 + 2 * 3 + 2 * 3 + 1 + 12 + 2)?;
        Some((bytes, cells))
    }
}



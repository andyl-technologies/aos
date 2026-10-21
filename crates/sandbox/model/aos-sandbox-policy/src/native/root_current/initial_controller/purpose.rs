//! Borrows actual finite Controller purposes through their same native replay.
//!
//! Every variant holds genuine earlier phase and received-input owners. DATA
//! receipts constrain comparison only; no caller can select a phase or install
//! a completed admission through this private borrowed sum.

pub(super) use super::super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1;
pub(super) use super::super::use_tail::{
    admitted::RootUseAdmittedOriginalV1,
    reserved::{RootUseReservedOriginalV1, RootUseReservedReceivedOriginalV1},
    signed::{RootSignedBoundOriginalV1, RootSignedBoundErrorV1},
    signed_input::{RootSignedInputOriginalV1, RootSignedInputErrorV1},
    outcome::{RootUseOutcomeOriginalV1, RootUseOutcomeErrorV1},
    outcome_input::{RootOutcomeInputOriginalV1, RootOutcomeInputErrorV1},
    closed::input::{RootReleaseInputOriginalV1, RootReleaseInputErrorV1},
};
use super::*;

#[derive(Clone, Copy)]
pub(super) enum RootControllerPurposeBorrowV1<'purpose> {
    Initial,
    Reserved {
        authorization: &'purpose RootInitialUseAuthorizedOriginalV1,
        received: &'purpose RootUseReservedReceivedOriginalV1,
    },
    Signed {
        authorization: &'purpose RootInitialUseAuthorizedOriginalV1,
        received: &'purpose RootUseReservedReceivedOriginalV1,
        reserved: &'purpose RootUseReservedOriginalV1,
        admitted: &'purpose RootUseAdmittedOriginalV1,
        input: &'purpose RootSignedInputOriginalV1,
    },
    Outcome {
        authorization: &'purpose RootInitialUseAuthorizedOriginalV1,
        received: &'purpose RootUseReservedReceivedOriginalV1,
        reserved: &'purpose RootUseReservedOriginalV1,
        admitted: &'purpose RootUseAdmittedOriginalV1,
        signed: &'purpose RootSignedBoundOriginalV1,
        input: &'purpose RootOutcomeInputOriginalV1,
    },
    Closed {
        authorization: &'purpose RootInitialUseAuthorizedOriginalV1,
        received: &'purpose RootUseReservedReceivedOriginalV1,
        reserved: &'purpose RootUseReservedOriginalV1,
        signed: &'purpose RootSignedBoundOriginalV1,
        outcome: &'purpose RootUseOutcomeOriginalV1,
        input: &'purpose RootReleaseInputOriginalV1,
    },
}

impl RootControllerPurposeBorrowV1<'_> {
    pub(super) fn segments_v1(self) -> usize {
        match self {
            Self::Initial => 3,
            Self::Reserved { .. } => 6,
            Self::Signed { .. } => 7,
            Self::Outcome { .. } => 10,
            Self::Closed { .. } => 12,
        }
    }

    pub(super) fn readback_v1(
        self,
        open: &RootInitialOpenPreparedOriginalV1,
        authority: &crate::native::RootPolicyJournalV1,
        policy: &crate::native::RootPolicyTargetOriginalV1,
    ) -> Result<(), RootInitialOpenErrorV1> {
        match self {
            Self::Initial => open.readback_current_v1(authority, policy).map(|_| ()),
            Self::Reserved { authorization, .. } => authorization.readback_current_v1(authority, policy).map(|_| ()),
            Self::Signed { admitted, .. } => admitted.readback_current_v1(authority, policy).map(|_| ()),
            Self::Outcome { signed, .. } => signed.readback_current_v1(authority, policy).map(|_| ()),
            Self::Closed { outcome, .. } => outcome.readback_current_v1(authority, policy).map(|_| ()),
        }
    }

    pub(super) fn after_end_v1(
        self,
        lane: [u8; 16],
        receipt: InputsReadyNativeReceiptDataV1<'_>,
        state: &RootInitialControllerReadonlyBodyV1,
    ) -> Result<u64, E> {
        match self {
            Self::Initial => Ok(receipt.after_end),
            Self::Reserved { received, .. } => received.receipt_v1(lane)
                .map(|receipt| receipt.after_end).map_err(|_| E::Incomplete),
            Self::Signed { .. } => state.signed_suffix.positions_v1().map(|positions| positions[1].1),
            Self::Outcome { input, .. } => input.recorded_receipt_v1(lane)
                .map(|receipt| receipt.after_end).map_err(|_| E::Incomplete),
            Self::Closed { input, .. } => input.controller_receipt_v1(lane)
                .map(|receipt| receipt.after_end).map_err(|_| E::Incomplete),
        }
    }
}

// This finite owed destination needs no new healthy/predecessor borrower. An
// earlier body failure cannot suppress its independently owed same-name work.
#[derive(Clone, Copy)]
pub(super) enum RootControllerPostPurposeBorrowV1<'purpose> {
    Initial,
    Reserved { authorization: &'purpose RootInitialUseAuthorizedOriginalV1,
        received: &'purpose RootUseReservedReceivedOriginalV1 },
    Signed { admitted: &'purpose RootUseAdmittedOriginalV1 },
    Outcome { signed: &'purpose RootSignedBoundOriginalV1, input: &'purpose RootOutcomeInputOriginalV1 },
    Closed { outcome: &'purpose RootUseOutcomeOriginalV1, input: &'purpose RootReleaseInputOriginalV1 },
}

impl<'purpose> RootControllerPurposeBorrowV1<'purpose> {
    pub(super) fn post_v1(self) -> RootControllerPostPurposeBorrowV1<'purpose> {
        match self {
            Self::Initial => RootControllerPostPurposeBorrowV1::Initial,
            Self::Reserved { authorization, received } => RootControllerPostPurposeBorrowV1::Reserved { authorization, received },
            Self::Signed { admitted, .. } => RootControllerPostPurposeBorrowV1::Signed { admitted },
            Self::Outcome { signed, input, .. } => RootControllerPostPurposeBorrowV1::Outcome { signed, input },
            Self::Closed { outcome, input, .. } => RootControllerPostPurposeBorrowV1::Closed { outcome, input },
        }
    }
}

impl RootControllerPostPurposeBorrowV1<'_> {
    pub(super) fn readback_v1(self, open: &RootInitialOpenPreparedOriginalV1,
        authority: &crate::native::RootPolicyJournalV1, policy: &crate::native::RootPolicyTargetOriginalV1)
        -> Result<(), RootInitialOpenErrorV1>
    {
        match self {
            Self::Initial => open.readback_current_v1(authority, policy).map(|_| ()),
            Self::Reserved { authorization, .. } => authorization.readback_current_v1(authority, policy).map(|_| ()),
            Self::Signed { admitted } => admitted.readback_current_v1(authority, policy).map(|_| ()),
            Self::Outcome { signed, .. } => signed.readback_current_v1(authority, policy).map(|_| ()),
            Self::Closed { outcome, .. } => outcome.readback_current_v1(authority, policy).map(|_| ()),
        }
    }

    pub(super) fn after_end_v1(self, lane: [u8;16], receipt: InputsReadyNativeReceiptDataV1<'_>,
        state: &RootInitialControllerReadonlyBodyV1) -> Result<u64,E>
    {
        match self {
            Self::Initial => Ok(receipt.after_end),
            Self::Reserved { received, .. } => received.receipt_v1(lane).map(|receipt|receipt.after_end).map_err(|_|E::Incomplete),
            Self::Signed { .. } => state.signed_suffix.positions_v1().map(|positions|positions[1].1),
            Self::Outcome { input, .. } => input.recorded_receipt_v1(lane).map(|receipt|receipt.after_end).map_err(|_|E::Incomplete),
            Self::Closed { input, .. } => input.controller_receipt_v1(lane).map(|receipt|receipt.after_end).map_err(|_|E::Incomplete),
        }
    }
}

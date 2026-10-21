//! Retains finite predecessor failures without a recursive public error enum.
//!
//! The same private body owns each returned earlier-purpose error. Public
//! Controller errors remain nonissuing markers for these resident causes.

use super::purpose::*;
use super::*;

#[derive(Debug, thiserror::Error)]
pub(super) enum TailPurposeErrorV1 {
    #[error(transparent)]
    Admitted(#[from] super::super::use_tail::admitted::RootUseAdmittedErrorV1),
    #[error(transparent)]
    Signed(#[from] RootSignedBoundErrorV1),
    #[error(transparent)]
    SignedInput(#[from] RootSignedInputErrorV1),
    #[error(transparent)]
    Outcome(#[from] RootUseOutcomeErrorV1),
    #[error(transparent)]
    OutcomeInput(#[from] RootOutcomeInputErrorV1),
    #[error(transparent)]
    Release(#[from] RootReleaseInputErrorV1),
    #[error(transparent)]
    Authorization(#[from] super::super::initial_use_authorized::RootInitialUseAuthorizedErrorV1),
    #[error(transparent)]
    Reserved(#[from] super::super::use_tail::reserved::RootUseReservedErrorV1),
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    #[error("Controller purpose belongs to another original")]
    Boundary,
}

impl RootControllerPurposeBorrowV1<'_> {
    pub(super) fn require_preparation_v1(
        self,
        _open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), TailPurposeErrorV1> {
        match self {
            Self::Signed {
                admitted, input, ..
            } => {
                admitted.require_complete_v1()?;
                input.require_received_v1()?;
            }
            Self::Outcome { signed, input, .. } => {
                signed.require_complete_v1()?;
                input.require_received_v1()?;
            }
            Self::Closed { outcome, input, .. } => {
                outcome.require_complete_v1()?;
                input.require_complete_v1()?;
            }
            Self::Initial | Self::Reserved { .. } => {}
        }
        Ok(())
    }

    pub(super) fn require_stage_v1(
        self,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), TailPurposeErrorV1> {
        match self {
            Self::Signed {
                authorization,
                admitted,
                reserved,
                ..
            } => {
                admitted.require_complete_v1()?;
                authorization.require_complete_v1()?;
                reserved.require_complete_v1()?;
                let actual = authorization.completed_body_v1()?;
                let body = open.body_v1()?;
                if actual.root_nonce != body.root_nonce
                    || actual.ready != body.open.ready
                    || actual.association.controller_nonce != body.open.controller_nonce
                {
                    return Err(TailPurposeErrorV1::Boundary);
                }
            }
            Self::Outcome {
                authorization,
                reserved,
                signed,
                ..
            } => {
                signed.require_original_chain_v1(open, authorization, reserved)?;
            }
            Self::Closed {
                authorization,
                reserved,
                signed,
                outcome,
                ..
            } => {
                outcome.require_original_chain_v1(open, authorization, reserved, signed)?;
            }
            Self::Initial | Self::Reserved { .. } => {}
        }
        Ok(())
    }

    pub(super) fn same_financial_v1(self, financial: &RootJournalFinancialOriginalV1) -> bool {
        match self {
            Self::Initial | Self::Reserved { .. } => true,
            Self::Signed {
                authorization,
                reserved,
                admitted,
                ..
            } => {
                authorization.same_financial_v1(financial)
                    && reserved.same_financial_v1(financial)
                    && admitted.same_financial_v1(financial)
            }
            Self::Outcome {
                authorization,
                reserved,
                signed,
                ..
            } => {
                authorization.same_financial_v1(financial)
                    && reserved.same_financial_v1(financial)
                    && signed.same_financial_v1(financial)
            }
            Self::Closed {
                authorization,
                reserved,
                signed,
                outcome,
                ..
            } => {
                authorization.same_financial_v1(financial)
                    && reserved.same_financial_v1(financial)
                    && signed.same_financial_v1(financial)
                    && outcome.same_financial_v1(financial)
            }
        }
    }
}

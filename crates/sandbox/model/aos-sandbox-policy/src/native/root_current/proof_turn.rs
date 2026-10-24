//! Borrows the actual Initial or completed Reserved proof predecessors.
//!
//! Only private native call sites construct these finite loans. The checksum
//! is comparison DATA; it cannot supply the native Reserved owner it describes.

use aos_sandbox_model::ResourceVector;
use aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1};
use crate::native::journal::RootPolicyJournalV1;
use crate::native::target::RootPolicyTargetOriginalV1;
use super::initial_open::{RootInitialOpenErrorV1 as E, RootInitialOpenPreparedOriginalV1};
use super::initial_trust::RootInitialTrustOriginalV1;
use super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1;
use super::use_tail::reserved::RootUseReservedOriginalV1;

#[derive(Clone, Copy)]
pub(super) enum RootCurrentProofTurnV1<'current> {
    Initial,
    Reserved {
        authorization: &'current RootInitialUseAuthorizedOriginalV1,
        reserved: &'current RootUseReservedOriginalV1,
    },
}

impl RootCurrentProofTurnV1<'_> {
    pub(super) fn authorization_checksum_v1(self, open: &RootInitialOpenPreparedOriginalV1)
        -> Result<Option<[u8; 32]>, E>
    {
        match self {
            Self::Initial => Ok(None),
            Self::Reserved { authorization, reserved } => {
                authorization.require_complete_v1().map_err(|_| E::Boundary)?;
                reserved.require_complete_v1().map_err(|_| E::Boundary)?;
                let lane = open.body_v1()?.open.lane;
                let receipt = authorization.completed_receipt_v1().map_err(|_| E::Boundary)?;
                let key = KeyV1::new(lane, OwnerV1::Root, 2)?;
                let phase = PhaseV1::new(OwnerV1::Root, 2)?;
                Ok(Some(RecordEnvelopeV1::decode(receipt.record, key, phase)?.checksum()))
            }
        }
    }

    pub(super) fn readback_v1(
        self,
        open: &RootInitialOpenPreparedOriginalV1,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
    ) -> Result<(), E> {
        match self {
            Self::Initial => open.readback_current_v1(authority, policy).map(|_| ()),
            Self::Reserved { authorization, .. } => authorization.readback_current_v1(authority, policy).map(|_| ()),
        }
    }

    pub(super) fn query_prefix_v1(self, trust: &RootInitialTrustOriginalV1) -> Result<ResourceVector, E> {
        match self {
            Self::Initial => trust.completed_prefix_v1().map_err(|_| E::Boundary),
            Self::Reserved { reserved, .. } => reserved.completed_prefix_v1().map_err(|_| E::Boundary),
        }
    }

    pub(super) fn same_query_financial_v1(
        self,
        trust: &RootInitialTrustOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
    ) -> bool {
        match self {
            Self::Initial => trust.same_financial_v1(financial),
            Self::Reserved { authorization, reserved } => authorization.same_financial_v1(financial)
                && reserved.same_financial_v1(financial),
        }
    }
}

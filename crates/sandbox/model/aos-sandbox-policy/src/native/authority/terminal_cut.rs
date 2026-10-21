//! Lends actual earned Root history and its authenticated next terminal packet.
//!
//! This closed role borrows the same native Authority, full prefix and genuine
//! gen1. It cannot be created from passive terminal recipes or currentness DATA.

use super::binding_history::RootAuthorityQ04HistoryV1;
use super::gen1::RootAuthorityGen1LoanV1;
use super::{RootAuthorityErrorV1, RootAuthorityQ04FlightOriginalV1};
use crate::q04_data::{
    PolicyQ04DataErrorV1, Q04AcknowledgementKindV1, Q04AcknowledgementV1, Q04RootStageRecipeV1,
};

pub(in crate::native) struct RootAuthorityQ04TerminalLoanV1<'loan, 'packet, 'origin, 'startup> {
    gen1: RootAuthorityGen1LoanV1<'loan, 'origin, 'startup>,
    history: &'loan RootAuthorityQ04HistoryV1,
    stage: &'loan Q04RootStageRecipeV1,
    kind: Q04AcknowledgementKindV1,
    frame: &'packet [u8],
}

impl<'loan, 'packet, 'origin, 'startup>
    RootAuthorityQ04TerminalLoanV1<'loan, 'packet, 'origin, 'startup>
{
    pub(in crate::native) fn gen1_v1(&self) -> &RootAuthorityGen1LoanV1<'loan, 'origin, 'startup> {
        &self.gen1
    }

    pub(in crate::native) fn history_v1(&self) -> &RootAuthorityQ04HistoryV1 {
        self.history
    }

    pub(in crate::native) fn acknowledgement_v1(
        &self,
    ) -> Result<Q04AcknowledgementV1<'packet>, RootAuthorityErrorV1> {
        use aos_sandbox_protocol::source_genesis_wire::{
            Q04TransferWireErrorV1 as WireError, RootCreateQ04TransferKindV1 as Transfer,
            decode_root_create_q04_transfer_v1,
        };
        let transfer = match self.kind {
            Q04AcknowledgementKindV1::Policy => Transfer::PolicyAcknowledgement,
            Q04AcknowledgementKindV1::Release => Transfer::ReleaseAcknowledgement,
            Q04AcknowledgementKindV1::Settlement => Transfer::SettlementAcknowledgement,
            Q04AcknowledgementKindV1::Clearance => Transfer::ClearanceAcknowledgement,
        };
        let packet = decode_root_create_q04_transfer_v1(
            self.frame,
            transfer,
            self.history.identity().nonce(),
        )
        .map_err(|error| match error {
            WireError::ChangedCut => RootAuthorityErrorV1::from(PolicyQ04DataErrorV1::ChangedCut),
            WireError::Allocation(error) => RootAuthorityErrorV1::Allocation(error),
        })?;
        let (names, _) = self.original_controller_data_v1();
        self.gen1
            .acknowledgement(self.kind, packet, self.history.identity(), names)
    }

    pub(super) const fn kind_v1(&self) -> Q04AcknowledgementKindV1 {
        self.kind
    }

    pub(super) const fn frame_data_v1(&self) -> &'packet [u8] {
        self.frame
    }

    pub(in crate::native) fn original_controller_data_v1(
        &self,
    ) -> (
        aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
        u64,
    ) {
        self.history.controller_before_data_v1()
    }

    pub(in crate::native) fn stage_v1(&self) -> &Q04RootStageRecipeV1 {
        self.stage
    }

}

impl<'authority, 'origin, 'startup>
    RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>
{
    pub(in crate::native) fn borrow_q04_terminal_cut_v1<'loan, 'packet>(
        &'loan mut self,
        stage: &'loan Q04RootStageRecipeV1,
        kind: Q04AcknowledgementKindV1,
        frame: &'packet [u8],
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<
        RootAuthorityQ04TerminalLoanV1<'loan, 'packet, 'origin, 'startup>,
        RootAuthorityErrorV1,
    > {
        let controls = std::mem::size_of::<RootAuthorityQ04TerminalLoanV1<'_, '_, '_, '_>>()
            .checked_sub(std::mem::size_of::<RootAuthorityGen1LoanV1<'_, '_, '_>>())
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<
                        Result<
                            RootAuthorityQ04TerminalLoanV1<'_, '_, '_, '_>,
                            RootAuthorityErrorV1,
                        >,
                    >()
                    .checked_mul(3)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        self.authority.journal.admit_role_observation_v1(
            aos_sandbox_model::ResourceVector::ZERO
                .with(aos_sandbox_model::ResourceDimension::MemoryBytes, controls),
        )?;
        self.q04_recheck_original_binding_prefix_v1(stage, source_packet)?;
        self.accept_historical_controller_readback_v1(controller_packet)?;
        let gen1 = self.completed_gen1_after_accepted_v1(controller_packet, source_packet)?;
        let history = self.q04_history_v1()?;
        // Strict completed-gen1 construction already performs its original
        // observations. No hidden repeated prefix or ACK sample is added.
        Ok(RootAuthorityQ04TerminalLoanV1 {
            gen1,
            history,
            stage,
            kind,
            frame,
        })
    }
}

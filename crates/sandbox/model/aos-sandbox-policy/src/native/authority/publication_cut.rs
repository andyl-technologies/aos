//! Lends the actually committed binding prefix to the same Target publication.
//!
//! This role cannot be constructed from a count, successful preflight or raw
//! suffix. The real Flight first rejoins its earned native prefix and Stage,
//! then strictly refreshes the same completed Controller/Source association.
//! Immutable Authority and History loans remain through Target mutation.

use super::binding_history::RootAuthorityQ04HistoryV1;
use super::gen1::RootAuthorityGen1LoanV1;
use super::{RootAuthorityErrorV1, RootAuthorityQ04FlightOriginalV1};
use crate::q04_data::{PolicyQ04DataErrorV1, Q04RootStageRecipeV1};

pub(in crate::native) struct RootAuthorityQ04PublicationLoanV1<'loan, 'origin, 'startup> {
    gen1: RootAuthorityGen1LoanV1<'loan, 'origin, 'startup>,
    history: &'loan RootAuthorityQ04HistoryV1,
    stage: &'loan Q04RootStageRecipeV1,
}

impl<'loan, 'origin, 'startup> RootAuthorityQ04PublicationLoanV1<'loan, 'origin, 'startup> {
    pub(in crate::native) fn gen1_v1(&self) -> &RootAuthorityGen1LoanV1<'loan, 'origin, 'startup> {
        &self.gen1
    }

    pub(in crate::native) fn recheck_v1(&self) -> Result<(), RootAuthorityErrorV1> {
        self.require_binding_prefix_v1()?;
        let journal = self.gen1.current.owner.journal;
        self.gen1.current.owner.recheck()?;
        self.history.require_fixed_original(journal)?;
        self.gen1.recheck()?;
        super::append_context::require_stage_cut_v1(
            self.gen1.floor(),
            self.gen1.current.owner.nonce_data_v1()?,
            self.history.identity(),
            self.stage,
        )?;
        self.history.require_original_stage_row_v1(
            journal,
            self.stage,
            self.history.committed(),
        )?;
        self.gen1.current.owner.recheck()
    }

    fn require_binding_prefix_v1(&self) -> Result<(), RootAuthorityErrorV1> {
        if self.history.failure_v1().is_some()
            || self.history.committed() != self.history.binding_prefix_end()?
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        Ok(())
    }
}

impl<'authority, 'origin, 'startup>
    RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>
{
    pub(in crate::native) fn borrow_q04_publication_cut_v1<'loan>(
        &'loan mut self,
        stage: &'loan Q04RootStageRecipeV1,
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<RootAuthorityQ04PublicationLoanV1<'loan, 'origin, 'startup>, RootAuthorityErrorV1>
    {
        {
            let history = self.q04_history_v1()?;
            if history.committed() != history.binding_prefix_end()? {
                return Err(PolicyQ04DataErrorV1::ChangedCut.into());
            }
        }
        // The gen1 constructor pays its embedded floor/source loan. This
        // finite role additionally pays the new history/stage references and
        // its distinct Result/constructor/return controls before construction.
        let controls = std::mem::size_of::<RootAuthorityQ04PublicationLoanV1<'_, '_, '_>>()
            .checked_sub(std::mem::size_of::<RootAuthorityGen1LoanV1<'_, '_, '_>>())
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<
                        Result<RootAuthorityQ04PublicationLoanV1<'_, '_, '_>, RootAuthorityErrorV1>,
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
        // Mutation of the actual Controller acceptance ends before the
        // immutable history/gen1/Authority loans are created below.
        self.accept_historical_controller_readback_v1(controller_packet)?;
        let gen1 = self.completed_gen1_after_accepted_v1(controller_packet, source_packet)?;
        let history = self.q04_history_v1()?;
        let loan = RootAuthorityQ04PublicationLoanV1 {
            gen1,
            history,
            stage,
        };
        loan.recheck_v1()?;
        Ok(loan)
    }
}

//! Records terminal Q04 retention without refunding unsupported owner costs.
//!
//! The original preparation and compound grant remain immutable history. One
//! exact terminal successor commits the original use and advances its Sandbox
//! head once. Legacy T01 keeps full C; T02 keeps the genuinely admitted U from
//! Q02 without refund. Neither row constructs new operation authority.
//! Source/Cache physical owners and remote retention lack a complete disposal
//! recipe, so every resource dimension remains charged at its original value.
//!
//! The private native format is fixed and uses the existing claim/head codecs:
//! ```text
//! AOSRST01 | original-id16 | co-issuance-sha32 | terminal-tx16
//!          | Controller-names48 | terminal-NEXT8 | prior-end8 | Root-final32
//!          | eight origins(id16, ordered-member-sha32, commit8, end8) | SHA32
//! AOSRST02 | same fixed712 layout, closed only with AOSRSQ02 co-issuance
//! ```
//! A row is replay DATA. The same original native parser must independently
//! verify its whole transaction, all eight origins and exact chronological cut.

use crate::journal::{CommitResult, ControllerQ04TransitionV1};
use crate::policy_compiler::create_q04::{
    CreateQ04ErrorV1, OriginalQ04FinalRootObservationV1,
};
use crate::Journal;

use super::{
    AccountTransition, ResourceReservationErrorV1,
    bank,
};


#[derive(Clone, Copy, Eq, PartialEq)]
struct NativeOrigin {
    id: [u8; 16],
    members: [u8; 32],
    returned: CommitResult,
}

/// Owns a terminal mutation prepared under the genuine final Root borrower.
///
/// Construction is private to the completed original Q04 route. The value
/// preserves the old full charge; it is not a current-purpose allocation loan.
pub(crate) struct Q04TerminalDispositionV1 {
    pub(super) transition: AccountTransition,
}

impl Q04TerminalDispositionV1 {
    /// Prepares full-charge retention under all eight returned native origins.
    ///
    /// # Errors
    /// Refuses absent/failed outcomes, a changed original terminal borrower,
    /// nonmatching native membership or a changed account predecessor.
    pub(crate) fn prepare(
        journal: &Journal,
        root: &OriginalQ04FinalRootObservationV1<'_, '_, '_>,
        original: &super::Q04ResourceTransferV1,
        recipes: &[ControllerQ04TransitionV1<'_>],
        returned: &[Option<Result<CommitResult, CreateQ04ErrorV1>>; 8],
    ) -> Result<Self, CreateQ04ErrorV1> {
        root.recheck()?;
        if recipes.len() != 8 || original.crossing_failure().is_some()
            || !recipes.first().and_then(|recipe| recipe.resource_transfer())
                .is_some_and(|held| std::ptr::eq(held, original))
            || returned.iter().any(|result| !matches!(result, Some(Ok(_))))
            || recipes.iter().enumerate().any(|(index, recipe)| {
                !std::ptr::eq(recipe.identity(), root.identity())
                    || recipe.phase_number() as usize != index + 1
                    || !recipe.same_original_cut(&recipes[0])
            })
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        original.require_readback(journal).map_err(resource_error)?;
        original.require_last_clock().map_err(resource_error)?;
        journal.require_controller_resource_q04_prefix_v1(recipes)?;

        let mut origins = [NativeOrigin {
            id: [0; 16], members: [0; 32],
            returned: CommitResult { commit_sequence: 0, durable_bytes: 0 },
        }; 8];
        let mut next = recipes[0].ledger().original_next();
        let mut prior_end = 0;
        for (index, recipe) in recipes.iter().enumerate() {
            let result = returned[index].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let frames = u64::try_from(recipe.transaction().records().len())
                .map_err(|_| CreateQ04ErrorV1::Bounds)?
                .checked_add(2).ok_or(CreateQ04ErrorV1::Bounds)?;
            if result.commit_sequence.checked_add(1) != next.checked_add(frames)
                || (index != 0 && result.durable_bytes <= prior_end)
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            origins[index] = NativeOrigin {
                id: *recipe.transaction().id(),
                members: bank::transaction_digest(recipe.transaction()).map_err(ResourceReservationErrorV1::from).map_err(resource_error)?,
                returned: *result,
            };
            next = result.commit_sequence.checked_add(1).ok_or(CreateQ04ErrorV1::Bounds)?;
            prior_end = result.durable_bytes;
        }
        journal.require_q04_returned_commit_v1(&origins[7].returned)?;
        let state = journal.controller_resource_state_v1()?;
        let use_claim = original.binding.native_fields().use_claim;
        let before = bank::find_head(state, use_claim.native_fields().account).map_err(ResourceReservationErrorV1::from).map_err(resource_error)?;
        let mut transition = AccountTransition::settle(before, use_claim, true)
            .map_err(resource_error)?;
        transition.original_clock = Some(original.original_clock);
        let binding = bank::TerminalBinding::from_parts((
            original.binding.native_fields().has_input_origin,
            original.binding.native_fields().original_claim.native_fields().id,
            original.binding.commitment().map_err(ResourceReservationErrorV1::from).map_err(resource_error)?,
            transition.transaction_id,
            journal.protected_writer_physical_names_v1()?,
            next, prior_end,
            *root.terminal_digest()?.as_bytes(),
            origins.map(|origin| (
                origin.id, origin.members, origin.returned.commit_sequence, origin.returned.durable_bytes,
            )),
        ));
        binding.require_predecessor(state, transition.history()).map_err(ResourceReservationErrorV1::from).map_err(resource_error)?;
        transition.terminal = Some(binding);
        root.recheck()?;
        Ok(Self { transition })
    }
}
fn resource_error(error: ResourceReservationErrorV1) -> CreateQ04ErrorV1 {
    CreateQ04ErrorV1::ResourceReservation(Box::new(error))
}

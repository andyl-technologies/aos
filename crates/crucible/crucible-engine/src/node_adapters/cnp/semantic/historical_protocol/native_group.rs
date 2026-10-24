//! Checks all three native historical demands before reconstructing any owner.
//!
//! This bank retains independent encoded copies and alias summaries throughout
//! reconstruction. Host2 backing, original Core content, allocator nodes,
//! control blocks and stacks remain separate accounting obligations.

use super::*;
use crate::node_contract::OriginalLineageRestoration;

/// Retains three signed native data owners under one known-layout allowance.
///
/// This holder grants no live enrollment, complete physical memory admission or
/// source-journal verification. Equal content never discounts another owner.
pub struct PacketCompleteHistoricalNativeGroup {
    process: u32,
    thread: ThreadId,
    owners: [Option<PacketCompleteHistoricalProtocolData>; 3],
    maximum_known_requested_bytes: usize,
    known_requested_bytes: Option<usize>,
    attempted: bool,
    failed: bool,
}

impl PacketCompleteHistoricalNativeGroup {
    /// Transfers three unspent data holders after authenticating their source.
    ///
    /// After transfer every failure retains all owners in the destination.
    /// Each input must already contain its independently reserved Source banks.
    ///
    /// # Errors
    /// Refuses occupied output, missing/repeated owners, changed source, spent
    /// reconstruction, foreign custody or unsupported known-layout allowance.
    pub fn prepare_into(
        owners: &mut [Option<PacketCompleteHistoricalProtocolData>; 3],
        source: &CompleteOriginalRestorationSource,
        maximum_known_requested_bytes: usize,
        completed: &mut Option<Self>,
    ) -> Result<(), OperationFailure> {
        if completed.is_some()
            || maximum_known_requested_bytes == 0
            || maximum_known_requested_bytes > MAXIMUM_DATA_BYTES
        {
            return Err(refused("historical native aggregate allowance unavailable"));
        }
        for (index, slot) in owners.iter().enumerate() {
            let owner = slot
                .as_ref()
                .ok_or_else(|| refused("historical native data owner absent"))?;
            owner.ensure_origin()?;
            if owner.attempted || owner.failed || owner.historical.is_some() {
                return Err(refused("historical native data owner is spent"));
            }
            let ticket = owner
                .ticket
                .as_ref()
                .ok_or_else(|| refused("historical native ticket absent"))?;
            ticket.authenticate_source(source).map_err(unknown)?;
            let selected = ticket.owner().map_err(unknown)?;
            for previous in &owners[..index] {
                let previous = previous
                    .as_ref()
                    .and_then(|value| value.ticket.as_ref())
                    .ok_or_else(|| refused("historical native previous ticket absent"))?
                    .owner()
                    .map_err(unknown)?;
                if previous.owner == selected.owner
                    || previous
                        .participants
                        .iter()
                        .any(|node| selected.participants.contains(node))
                {
                    return Err(refused("historical native aggregate repeats an owner"));
                }
            }
        }

        *completed = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            owners: std::array::from_fn(|index| owners[index].take()),
            maximum_known_requested_bytes,
            known_requested_bytes: None,
            attempted: false,
            failed: false,
        });
        Ok(())
    }

    /// Validates all demands and their simultaneous total before typed allocation.
    ///
    /// Partial reconstructed owners remain held if a later reconstruction fails.
    /// Source payload copies and complete alias capacities coexist throughout.
    ///
    /// # Errors
    /// Refuses foreign origin, repeated attempts, malformed data, aggregate
    /// exhaustion or any SDK reconstruction/owner correspondence failure.
    pub fn reconstruct_historical_data(&mut self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.attempted || self.failed {
            return Err(refused("historical native aggregate attempt is spent"));
        }
        self.attempted = true;
        let result = (|| {
            let mut totals = [0usize; 3];
            for (index, slot) in self.owners.iter_mut().enumerate() {
                let owner = slot
                    .as_mut()
                    .ok_or_else(|| refused("historical native aggregate owner absent"))?;
                owner.ensure_origin()?;
                let plan = ValidatedOwnedProtocol11::validate(
                    &owner.payload,
                    owner.budget.limits,
                    &mut owner.aliases,
                )
                .map_err(unknown)?;
                plan.require_complete_reader_state().map_err(unknown)?;
                if plan.complete_schema_identity().map_err(unknown)?
                    != (COMPLETE_CONTROLLER_FORMAT, COMPLETE_CONNECTION_FORMAT)
                {
                    return Err(refused(
                        "native aggregate complete backend identity differs",
                    ));
                }
                let demand = *plan.allocation_demand();
                owner.demand = Some(demand);
                totals[index] = sum_known_requested(
                    &demand,
                    owner.payload.capacity(),
                    owner
                        .aliases
                        .capacity()
                        .checked_mul(size_of::<HistoricalAliasSummary>())
                        .ok_or_else(|| refused("historical native alias extent overflow"))?,
                    size_of::<PacketCompleteHistoricalProtocolData>(),
                    owner.budget.maximum_known_requested_bytes,
                )?;
                owner.known_requested_bytes = Some(totals[index]);
            }
            self.known_requested_bytes = Some(sum_group_requested(
                totals,
                size_of::<PacketCompleteHistoricalProtocolData>(),
                size_of::<Self>(),
                self.maximum_known_requested_bytes,
            )?);

            for slot in &mut self.owners {
                slot.as_mut()
                    .ok_or_else(|| refused("historical native aggregate owner lost"))?
                    .reconstruct_historical_data()?;
            }
            self.ensure_origin()
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Authenticates each original ticket against the same actual Core target.
    ///
    /// This recheck does not enroll historical data or issue a live SDK token.
    ///
    /// # Errors
    /// Refuses foreign custody, incomplete/failed data or another target context.
    pub fn authenticate_context(
        &self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.failed || !self.attempted || self.known_requested_bytes.is_none() {
            return Err(refused("historical native aggregate is incomplete"));
        }
        for slot in &self.owners {
            let owner = slot
                .as_ref()
                .ok_or_else(|| refused("historical native aggregate owner absent"))?;
            owner.historical_data()?;
            owner
                .ticket
                .as_ref()
                .ok_or_else(|| refused("historical native aggregate ticket absent"))?
                .authenticate_context(context)
                .map_err(unknown)?;
        }
        Ok(())
    }

    /// Borrows one completed historical owner without transferring its ticket.
    ///
    /// # Errors
    /// Refuses foreign origin, invalid index or failed/incomplete reconstruction.
    pub fn historical_data(
        &self,
        index: usize,
    ) -> Result<&HistoricalControllerState, OperationFailure> {
        self.ensure_origin()?;
        if self.failed {
            return Err(refused("historical native aggregate refused"));
        }
        self.owners
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(|| refused("historical native aggregate index unavailable"))?
            .historical_data()
    }

    fn ensure_origin(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused("historical native aggregate has another origin"));
        }
        Ok(())
    }
}

fn sum_group_requested(
    totals: [usize; 3],
    owner_layout: usize,
    group_layout: usize,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    totals.into_iter().try_fold(group_layout, |total, owner| {
        owner
            .checked_sub(owner_layout)
            .and_then(|backing| total.checked_add(backing))
            .filter(|sum| *sum <= maximum)
            .ok_or_else(|| refused("historical native simultaneous aggregate exceeds allowance"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separately_fitting_owners_must_fit_together_with_group_inline_storage() {
        assert!(sum_group_requested([100; 3], 20, 80, 100).is_err());
        assert_eq!(sum_group_requested([100; 3], 20, 80, 320).ok(), Some(320));
        assert!(sum_group_requested([100; 3], 20, 80, 319).is_err());
    }

    #[test]
    fn inline_underflow_and_combined_overflow_refuse() {
        assert!(sum_group_requested([19, 100, 100], 20, 80, 320).is_err());
        assert!(sum_group_requested([usize::MAX; 3], 0, 1, usize::MAX).is_err());
    }
}

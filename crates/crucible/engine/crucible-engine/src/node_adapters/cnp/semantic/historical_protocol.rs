//! Precharges source-owned historical protocol data before typed reconstruction.
//!
//! A signed Core native ticket identifies the owner and verified payload closure.
//! This helper retains that ticket, a distinct encoded payload copy and actual
//! alias-summary allocation before invoking the complete borrowed SDK validator.
//! It admits the simultaneous known requested backing before typed owners exist.
//!
//! Logical tree entry layouts and shared payload views do not prove allocator
//! node/control-block geometry or compiler/thread stack. This data-only helper
//! grants no complete physical peak, native enrollment, Capture or Ready rights.
//! The source-specific journal/native suffix and fresh target association remain
//! independent requirements for any installed archive factory.

use std::{mem::size_of, thread::ThreadId};

use crucible_node_format::ContentRef;
use crucible_node_transport::protocol_snapshot::owned11::{
    aliases::HistoricalAliasSummary,
    outer::{
        COMPLETE_CONNECTION_FORMAT, COMPLETE_CONTROLLER_FORMAT, HistoricalControllerState,
        OwnedProtocol11AllocationDemand, OwnedProtocol11DataLimits, ValidatedOwnedProtocol11,
    },
};

use super::{refused, unknown};
use crate::{
    node_contract::OperationFailure,
    node_state::{CompleteOriginalNativeTicket, CompleteOriginalRestorationSource},
};

mod native_group;
pub use native_group::PacketCompleteHistoricalNativeGroup;

const MAXIMUM_DATA_BYTES: usize = 512 * 1024 * 1024;
const MAXIMUM_METADATA_ROWS: usize = 131_072;

/// Bounds historical data copying without granting physical or live admission.
#[derive(Clone, Copy)]
pub struct PacketCompleteHistoricalProtocolDataBudget {
    limits: OwnedProtocol11DataLimits,
    maximum_known_requested_bytes: usize,
}

impl PacketCompleteHistoricalProtocolDataBudget {
    /// Names the fixed source backend and required complete connection class.
    ///
    /// A measured archive factory must retain this tuple in its codec/schema
    /// identity. The fixed value is not a decoded selector or live permission.
    pub const fn backend_schema_identity(&self) -> (&'static str, &'static str, &'static str) {
        (
            "source-owned.packet-complete-historical-protocol/11",
            COMPLETE_CONTROLLER_FORMAT,
            COMPLETE_CONNECTION_FORMAT,
        )
    }

    /// Selects bounded SDK grammar and a simultaneous known-backing allowance.
    ///
    /// The allowance counts recorded backing views conservatively. It is not a
    /// complete Node memory budget or an allocator/control-block qualification.
    ///
    /// # Errors
    /// Refuses zero/excessive byte or row limits and arithmetic overflow.
    pub fn new(
        limits: OwnedProtocol11DataLimits,
        maximum_known_requested_bytes: usize,
    ) -> Result<Self, OperationFailure> {
        if maximum_known_requested_bytes == 0
            || maximum_known_requested_bytes > MAXIMUM_DATA_BYTES
            || limits.json.maximum_input_bytes == 0
            || limits.json.maximum_input_bytes > MAXIMUM_DATA_BYTES
            || limits.maximum_metadata_rows == 0
            || limits.maximum_metadata_rows > MAXIMUM_METADATA_ROWS
        {
            return Err(refused("historical protocol data allowance is unsupported"));
        }
        limits
            .maximum_metadata_rows
            .checked_mul(size_of::<HistoricalAliasSummary>())
            .ok_or_else(|| refused("historical protocol summary extent overflow"))?;
        Ok(Self {
            limits,
            maximum_known_requested_bytes,
        })
    }
}

/// Reports actual Source banks and admitted requested layouts as data only.
#[derive(Clone, Copy, Debug)]
pub struct PacketCompleteHistoricalAllocationFacts {
    /// Counts the independent Source-owned encoded payload allocation.
    pub payload_capacity_bytes: usize,
    /// Counts the entire precharged summary bank, including unused entries.
    pub alias_summary_capacity_bytes: usize,
    /// Counts this inline holder, including the optional final historical state.
    pub holder_layout_bytes: usize,
    /// Reports the checked aggregate after the complete borrowed SDK pass.
    pub known_requested_total_bytes: Option<usize>,
}

/// Retains bounded historical data and its actual signed Core owner ticket.
///
/// This is neither a live controller nor a restoration permission constructor.
/// The explicit reader-complete class is required; old partial tuples are refused.
/// No original live Source allocation or opaque payload accompaniment is needed
/// to decode historical data. Full source journal/factory verification and a
/// genuine fresh target context are still mandatory for live enrollment.
pub struct PacketCompleteHistoricalProtocolData {
    process: u32,
    thread: ThreadId,
    ticket: Option<CompleteOriginalNativeTicket>,
    location: PayloadLocation,
    payload: Vec<u8>,
    aliases: Vec<HistoricalAliasSummary>,
    budget: PacketCompleteHistoricalProtocolDataBudget,
    demand: Option<OwnedProtocol11AllocationDemand>,
    known_requested_bytes: Option<usize>,
    historical: Option<HistoricalControllerState>,
    attempted: bool,
    failed: bool,
}

impl PacketCompleteHistoricalProtocolData {
    /// Retains an authenticated owner-linked payload and precharges its summaries.
    ///
    /// The payload must be the owner's state, direct evidence or artifact. This
    /// establishes signed data membership only; the complete local journal must
    /// separately authenticate the host protocol role before live factory use.
    /// The actual ticket is transferred into the destination before allocations.
    ///
    /// # Errors
    /// Refuses another source, owner-external payload, unsupported codec, occupied
    /// destination or insufficient capacity. After transfer any refusal retains
    /// the original ticket and every partially reserved bank in the destination.
    pub fn reserve_from_ticket_into(
        ticket: &mut Option<CompleteOriginalNativeTicket>,
        source: &CompleteOriginalRestorationSource,
        reference: &ContentRef,
        budget: PacketCompleteHistoricalProtocolDataBudget,
        completed: &mut Option<Self>,
    ) -> Result<(), OperationFailure> {
        let original = ticket
            .as_ref()
            .ok_or_else(|| refused("historical protocol ticket absent"))?;
        original.authenticate_source(source).map_err(unknown)?;
        if completed.is_some() {
            return Err(refused("historical protocol data slot occupied"));
        }
        let owner = original.owner().map_err(unknown)?;
        let schema =
            crucible_node_transport::reference_packet::service::native_owned11_snapshot_schema()
                .map_err(unknown)?;
        if owner.key.schema != schema {
            return Err(refused(
                "historical protocol owner uses another continuation schema",
            ));
        }
        let location = if owner.state == *reference {
            PayloadLocation::State
        } else if let Some(index) = owner.evidence.iter().position(|one| one == reference) {
            PayloadLocation::Evidence(index)
        } else if let Some(index) = owner
            .artifacts
            .iter()
            .position(|one| one.content == *reference)
        {
            PayloadLocation::Artifact(index)
        } else {
            return Err(refused(
                "historical protocol payload is outside the selected owner",
            ));
        };
        let bytes = original
            .content()
            .map_err(unknown)?
            .get(reference)
            .ok_or_else(|| refused("historical protocol verified payload absent"))?;
        reference.verify(bytes).map_err(unknown)?;
        let summary_bytes = budget
            .limits
            .maximum_metadata_rows
            .checked_mul(size_of::<HistoricalAliasSummary>())
            .ok_or_else(|| refused("historical protocol summary extent overflow"))?;
        let initial = bytes
            .len()
            .checked_add(summary_bytes)
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .ok_or_else(|| refused("historical protocol initial extent overflow"))?;
        if bytes.len() > budget.limits.json.maximum_input_bytes
            || initial > budget.maximum_known_requested_bytes
        {
            return Err(refused(
                "historical protocol initial banks exceed allowance",
            ));
        }

        *completed = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            ticket: None,
            location,
            payload: Vec::new(),
            aliases: Vec::new(),
            budget,
            demand: None,
            known_requested_bytes: None,
            historical: None,
            attempted: false,
            failed: false,
        });
        let state = completed
            .as_mut()
            .ok_or_else(|| refused("historical protocol slot absent"))?;
        state.ticket = ticket.take();
        let result = (|| {
            let original = state
                .ticket
                .as_ref()
                .ok_or_else(|| refused("historical protocol ticket lost"))?;
            let bytes = original
                .content()
                .map_err(unknown)?
                .get(reference)
                .ok_or_else(|| refused("historical protocol payload lost"))?;
            state
                .payload
                .try_reserve_exact(bytes.len())
                .map_err(|_| refused("historical protocol payload bank unavailable"))?;
            state
                .aliases
                .try_reserve_exact(budget.limits.maximum_metadata_rows)
                .map_err(|_| refused("historical protocol alias bank unavailable"))?;
            let facts = state.allocation_facts()?;
            if facts
                .payload_capacity_bytes
                .checked_add(facts.alias_summary_capacity_bytes)
                .and_then(|n| n.checked_add(facts.holder_layout_bytes))
                .is_none_or(|n| n > budget.maximum_known_requested_bytes)
            {
                return Err(refused("historical protocol actual banks exceed allowance"));
            }
            state.payload.extend_from_slice(bytes);
            state.aliases.resize(
                budget.limits.maximum_metadata_rows,
                HistoricalAliasSummary::default(),
            );
            original.authenticate_source(source).map_err(unknown)
        })();
        if result.is_err() {
            state.failed = true;
        }
        result
    }

    /// Validates the entire graph and aggregate before constructing typed data.
    ///
    /// Reader fields must be explicitly captured in the selected complete class.
    /// Recorded shared backing views are conservatively summed; equal hashes
    /// and group labels never deduct Source/Core allocations. The SDK summary
    /// requirement is already inside the actual precharged bank and is not an
    /// additional allocation. Separate physical terms remain unqualified.
    ///
    /// # Errors
    /// Retains all owners on repeated attempts, malformed fields/aliases, aggregate
    /// exhaustion, reconstruction refusal or changed owner correspondence.
    pub fn reconstruct_historical_data(&mut self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.attempted || self.failed {
            return Err(refused("historical protocol data attempt is spent"));
        }
        self.attempted = true;
        let result = (|| {
            let alias_bytes = self
                .aliases
                .capacity()
                .checked_mul(size_of::<HistoricalAliasSummary>())
                .ok_or_else(|| refused("historical protocol actual alias extent overflow"))?;
            let mut plan = ValidatedOwnedProtocol11::validate(
                &self.payload,
                self.budget.limits,
                &mut self.aliases,
            )
            .map_err(unknown)?;
            plan.require_complete_reader_state().map_err(unknown)?;
            if plan.complete_schema_identity().map_err(unknown)?
                != (COMPLETE_CONTROLLER_FORMAT, COMPLETE_CONNECTION_FORMAT)
            {
                return Err(refused(
                    "historical protocol complete backend identity differs",
                ));
            }
            let demand = *plan.allocation_demand();
            self.demand = Some(demand);
            self.known_requested_bytes = Some(sum_known_requested(
                &demand,
                self.payload.capacity(),
                alias_bytes,
                size_of::<Self>(),
                self.budget.maximum_known_requested_bytes,
            )?);
            // Only historical owners follow. This guarded allocation does not
            // enroll a codec, registrar, clock, stream, target or native token.
            plan.reconstruct_complete_into(&mut self.historical)
                .map_err(unknown)?;
            let owner = self
                .ticket
                .as_ref()
                .ok_or_else(|| refused("historical protocol ticket absent"))?
                .owner()
                .map_err(unknown)?;
            let historical = self
                .historical
                .as_ref()
                .ok_or_else(|| refused("historical protocol result absent"))?;
            if owner.participants.as_slice() != std::slice::from_ref(&historical.node)
                || owner.owner != historical.execution_owner
            {
                return Err(refused(
                    "historical protocol data has another participant or owner",
                ));
            }
            self.ensure_origin()
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Borrows successfully reconstructed historical data without live enrollment.
    ///
    /// # Errors
    /// Refuses foreign origin, incomplete or failed reconstruction.
    pub fn historical_data(&self) -> Result<&HistoricalControllerState, OperationFailure> {
        self.ensure_origin()?;
        if self.failed {
            return Err(refused("historical protocol data attempt refused"));
        }
        self.historical
            .as_ref()
            .ok_or_else(|| refused("historical protocol data is incomplete"))
    }

    /// Borrows the original owner-linked reference without an independent clone.
    ///
    /// # Errors
    /// Refuses foreign origin or a missing original owner/reference slot.
    pub fn payload_reference(&self) -> Result<&ContentRef, OperationFailure> {
        self.ensure_origin()?;
        let owner = self
            .ticket
            .as_ref()
            .ok_or_else(|| refused("historical protocol ticket absent"))?
            .owner()
            .map_err(unknown)?;
        match self.location {
            PayloadLocation::State => Ok(&owner.state),
            PayloadLocation::Evidence(index) => owner
                .evidence
                .get(index)
                .ok_or_else(|| refused("historical protocol evidence slot absent")),
            PayloadLocation::Artifact(index) => owner
                .artifacts
                .get(index)
                .map(|one| &one.content)
                .ok_or_else(|| refused("historical protocol artifact slot absent")),
        }
    }

    /// Borrows complete checked demand without treating it as physical authority.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody.
    pub fn allocation_demand(
        &self,
    ) -> Result<Option<&OwnedProtocol11AllocationDemand>, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.demand.as_ref())
    }

    /// Reports current actual Source bank capacities without granting memory credit.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody or capacity arithmetic overflow.
    pub fn allocation_facts(
        &self,
    ) -> Result<PacketCompleteHistoricalAllocationFacts, OperationFailure> {
        self.ensure_origin()?;
        Ok(PacketCompleteHistoricalAllocationFacts {
            payload_capacity_bytes: self.payload.capacity(),
            alias_summary_capacity_bytes: self
                .aliases
                .capacity()
                .checked_mul(size_of::<HistoricalAliasSummary>())
                .ok_or_else(|| refused("historical protocol alias capacity overflow"))?,
            holder_layout_bytes: size_of::<Self>(),
            known_requested_total_bytes: self.known_requested_bytes,
        })
    }

    fn ensure_origin(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused("historical protocol data has another origin"));
        }
        Ok(())
    }
}

fn sum_known_requested(
    demand: &OwnedProtocol11AllocationDemand,
    payload_bytes: usize,
    alias_bytes: usize,
    holder_bytes: usize,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    if demand.alias_summary_layout_bytes > alias_bytes {
        return Err(refused(
            "historical protocol aliases exceed the actual summary bank",
        ));
    }
    [
        payload_bytes,
        alias_bytes,
        holder_bytes,
        demand.recorded_string_bytes,
        demand.recorded_vector_bytes,
        demand.literal_backing_bytes,
        demand.tree_entry_layout_bytes,
        demand.boxed_value_bytes,
        demand.shared_view_bytes,
        demand.selected_group_lookup_bytes,
        demand.content_group_lookup_bytes,
        demand.selected_slice_staging_bytes,
    ]
    .into_iter()
    .try_fold(0usize, |sum, bytes| {
        sum.checked_add(bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| refused("historical protocol aggregate exceeds allowance"))
    })
}

#[derive(Clone, Copy)]
enum PayloadLocation {
    State,
    Evidence(usize),
    Artifact(usize),
}

impl Drop for PacketCompleteHistoricalProtocolData {
    fn drop(&mut self) {
        if self.process != std::process::id() {
            // An inherited process cannot invoke original archive/factory
            // destructors. Historical typed buffers contain data only.
            std::mem::forget(self.ticket.take());
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "aggregate backing control assertions")]
mod tests {
    use super::*;

    fn demand() -> OwnedProtocol11AllocationDemand {
        // This synthetic additive ledger grants no allocation authority. Its
        // tree shape uses the actual controller custody key/value types; its
        // shared alignment uses the actual Rc<Vec<u8>> content backing type.
        type CustodyValue = crucible_node_transport::client::ClientOriginal;
        let tree_layout = size_of::<crucible_node_format::Id>() + size_of::<CustodyValue>();
        let tree_alignment = std::mem::align_of::<crucible_node_format::Id>()
            .max(std::mem::align_of::<CustodyValue>());
        OwnedProtocol11AllocationDemand {
            recorded_string_bytes: 20,
            recorded_vector_bytes: 30,
            literal_backing_bytes: 40,
            tree_entries: 1,
            tree_entry_layout_bytes: 10,
            tree_containers: 1,
            maximum_tree_key_value_bytes: tree_layout,
            maximum_tree_entry_alignment: tree_alignment,
            shared_backing_views: 1,
            maximum_shared_value_alignment: std::mem::align_of::<Vec<u8>>(),
            boxed_value_bytes: 10,
            shared_view_bytes: 10,
            alias_groups: 1,
            alias_rows: 2,
            alias_summary_entries: 1,
            alias_summary_layout_bytes: 10,
            selected_group_lookup_bytes: 20,
            content_group_lookup_bytes: 5,
            selected_slice_staging_bytes: 7,
        }
    }

    #[test]
    fn simultaneous_categories_and_actual_source_banks_require_one_aggregate_allowance() {
        // Each term fits 100; the simultaneous owned/requested total does not.
        // The precharged 50-byte alias bank is counted once, including unused
        // entries; its required ten-byte subextent adds no second allocation.
        assert!(sum_known_requested(&demand(), 40, 50, 30, 100).is_err());
        assert_eq!(
            sum_known_requested(&demand(), 40, 50, 30, 272).unwrap(),
            272
        );
        assert!(sum_known_requested(&demand(), 41, 50, 30, 272).is_err());
    }

    #[test]
    fn aggregate_refuses_alias_bank_shortfall_and_all_arithmetic_overflow() {
        assert!(sum_known_requested(&demand(), 40, 9, 30, 272).is_err());
        let mut report = demand();
        report.recorded_vector_bytes = usize::MAX;
        assert!(sum_known_requested(&report, 40, 50, 30, usize::MAX).is_err());
    }
}

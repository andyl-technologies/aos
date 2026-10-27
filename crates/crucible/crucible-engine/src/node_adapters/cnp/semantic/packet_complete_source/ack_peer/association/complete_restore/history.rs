//! Borrows every independently retained legacy restoration partial as history.
//!
//! Selected phase12 uses distinct transfer owners, but its base slot still owns
//! real reserved banks. A partially used legacy slot retains its ticket,
//! mapping, typed journal/request/context and normalized copies independently.
//! The archive Source definition is encoded once outside this view; its ticket
//! contributes only its actual same-Source edge in the joint alias namespace.
//!
//! ```text
//! {ticket,mapping,journal,journal_capacities,request,request_capacities,
//!  context,context_capacities,normalized,normalized_capacities,banks,
//!  bank_capacities,assigned_digest,prepared,ready,signing_started,sealed,
//!  publishing_started,frame_maximum}
//! ```

use super::*;
use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacitySink;

use crate::node_contract::{
    RuntimeError,
    restored_owner_history::{
        OriginalRestoredOwnerCapacityAliases, OriginalRestoredOwnerCapacityRow,
        OriginalRestoredOwnerCapacityRows, OriginalRestoredOwnerCapacityWalk,
    },
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::{cell::RefCell, mem::size_of};

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct SourceCompleteRestoreHistory<
    'a,
> {
    original: &'a OriginalCompleteRestoreAttempt,
    archive: &'a CompleteOriginalRestorationSource,
    aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
}

impl OriginalCompleteRestoreAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_data<'a>(
        &'a self,
        archive: &'a CompleteOriginalRestorationSource,
        aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
    ) -> SourceCompleteRestoreHistory<'a> {
        SourceCompleteRestoreHistory {
            original: self,
            archive,
            aliases,
        }
    }

    /// Counts only these actual Source children, not the external archive graph.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_common_metadata_demand_data(
        &self,
        archive: &CompleteOriginalRestorationSource,
    ) -> Result<(usize, usize), RuntimeError> {
        let mut rows = 0usize;
        let mut shared = 0usize;
        let mut add = |demand: Result<(usize, usize), RuntimeError>| -> Result<(), RuntimeError> {
            let (count, edges) = demand?;
            rows = rows.checked_add(count).ok_or(RuntimeError::ResourceLimit)?;
            shared = shared
                .checked_add(edges)
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        };
        add(OriginalRestoredOwnerCapacityRows(&self.journal).metadata_demand_data())?;
        add(OriginalRestoredOwnerCapacityRows(&self.request).metadata_demand_data())?;
        add(OriginalRestoredOwnerCapacityRows(&self.context).metadata_demand_data())?;
        add(OriginalRestoredOwnerCapacityRows(self.normalized.as_slice()).metadata_demand_data())?;
        add(OriginalRestoredOwnerCapacityRows(self.banks.as_slice()).metadata_demand_data())?;
        if let Some(ticket) = &self.ticket {
            ticket.borrowed_settled_history_data(archive)?;
            rows = rows.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
            shared = shared.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok((rows, shared))
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_counter_scratch_data()
    -> usize {
        crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data()
            + CompleteOriginalNativeTicket::settled_history_counter_scratch_data()
            + size_of::<SourceCompleteRestoreHistory<'static>>()
            + size_of::<&SourceCompleteRestoreHistory<'static>>()
            + size_of::<TicketData<'static>>() + size_of::<Option<TicketData<'static>>>()
            + size_of::<&Option<TicketData<'static>>>()
            + size_of::<&OriginalCompleteRestoreAttempt>()
            + size_of::<&CompleteOriginalRestorationSource>()
            + size_of::<&RefCell<OriginalRestoredOwnerCapacityAliases>>()
            + size_of::<&Option<CompleteOriginalNativeTicket>>()
            + size_of::<Option<&CompleteOriginalNativeTicket>>()
            + size_of::<&CompleteOriginalNativeTicket>()
            + size_of::<&Option<PreparedArchivedProtocolMapping>>()
            + size_of::<&PreparedArchivedProtocolMapping>()
            + size_of::<&Option<crate::node_adapters::cnp::PacketCompleteSettledJournal>>()
            + size_of::<&Option<PacketCompleteRestoreRequest>>()
            + size_of::<&Option<PacketCompleteRestoreContext>>()
            + size_of::<&[Option<serde_json::Value>; 6]>()
            + size_of::<&[Vec<u8>; 6]>() + size_of::<&Option<[u8; 32]>>()
            + size_of::<&bool>() + size_of::<&usize>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<(usize, usize)>()
            + portable_counter_scratch_data()
    }
}

struct TicketData<'a>(
    &'a CompleteOriginalNativeTicket,
    &'a CompleteOriginalRestorationSource,
    &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
);

impl Serialize for TicketData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.0
            .borrowed_settled_history_data(self.1)
            .map_err(S::Error::custom)?
            .with_aliases(self.2)
            .serialize(serializer)
    }
}

impl Serialize for SourceCompleteRestoreHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let OriginalCompleteRestoreAttempt {
            ticket,
            mapping,
            journal,
            request,
            context,
            normalized,
            banks,
            assigned_digest,
            prepared,
            ready,
            signing_started,
            sealed,
            publishing_started,
            frame_maximum,
        } = self.original;
        if mapping.is_some() {
            // Selected phase12 has its own complete transfer owner. A live or
            // failed legacy mapping cannot be represented by its normalization
            // tuple without losing original ownership, so this cut is unsupported.
            return Err(serde::ser::Error::custom(
                "settled17 cannot archive an active legacy restoration mapping",
            ));
        }
        let mut state = serializer.serialize_struct("SourceCompleteRestoreHistory", 19)?;
        state.serialize_field(
            "ticket",
            &ticket
                .as_ref()
                .map(|ticket| TicketData(ticket, self.archive, self.aliases)),
        )?;
        state.serialize_field("mapping", &None::<&serde_json::Value>)?;
        state.serialize_field("journal", journal)?;
        state.serialize_field(
            "journal_capacities",
            &OriginalRestoredOwnerCapacityRows(journal),
        )?;
        state.serialize_field("request", request)?;
        state.serialize_field(
            "request_capacities",
            &OriginalRestoredOwnerCapacityRows(request),
        )?;
        state.serialize_field("context", context)?;
        state.serialize_field(
            "context_capacities",
            &OriginalRestoredOwnerCapacityRows(context),
        )?;
        state.serialize_field("normalized", normalized)?;
        state.serialize_field(
            "normalized_capacities",
            &OriginalRestoredOwnerCapacityRows(normalized.as_slice()),
        )?;
        state.serialize_field("banks", banks)?;
        state.serialize_field(
            "bank_capacities",
            &OriginalRestoredOwnerCapacityRows(banks.as_slice()),
        )?;
        state.serialize_field("assigned_digest", assigned_digest)?;
        state.serialize_field("prepared", prepared)?;
        state.serialize_field("ready", ready)?;
        state.serialize_field("signing_started", signing_started)?;
        state.serialize_field("sealed", sealed)?;
        state.serialize_field("publishing_started", publishing_started)?;
        state.serialize_field("frame_maximum", frame_maximum)?;
        state.end()
    }
}

// Public DTO fields are exhaustively named here. The actual provider serializers
// remain unchanged; these walks add only inert common capacity rows.
macro_rules! fields {
    ($ty:ty; $($owned:ident),*; $($inline:ident),* $(,)?) => {
        impl OriginalRestoredOwnerCapacityWalk for $ty {
            fn capacities(&self, depth: usize, sink: &mut dyn OriginalRestoredOwnerCapacitySink) -> Result<(), RuntimeError> {
                let inline_fields: &[&str] = &[$(stringify!($inline)),*];
                sink.visit_work(1 + inline_fields.len())?;
                let Self { $($owned,)* $($inline: _,)* } = self;
                $($owned.capacities(depth, sink)?;)*
                Ok(())
            }
        }
    };
}

fields!(PacketCompleteRestoreRequest;
    schema, archive_index, capture_manifest, owner_state, journal, source_runtime,
    backend_implementation, backend_schema, target_world, target_owner,
    target_owner_binding, target_activation, mapping, nonce;
    archived_cut, archived_ordinal, target_generation, target_owner_generation);

fields!(PacketCompleteRestoreContext;
    schema, algorithm, source_birth, kernel_binding, policy_binding, host_registration,
    native_registration, hello_request, hello_response, assigned_restore, archive_binding,
    target_binding, mapping_binding, request_binding;);

fields!(crucible_node_transport::reference_packet::service::ack_emitter::PacketCanonicalAckAdmissionContext;
    schema, algorithm, source_birth, kernel_binding, policy_binding, host_registration,
    native_registration, hello_request, hello_response, assigned_admit;);

fields!(crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationRequest;
    schema, capture_request_id, capture_request_hash, capture_operation_id, capture_terminal_hash,
    native_snapshot_ref, native_control_ref, native_anchor_ref; capture_terminal_sequence);

fields!(crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationReceipt;
    schema, capture, native_after_ref; native_after_capacity);

fields!(crate::node_adapters::cnp::PacketCompleteSettledJournal;
    schema, owner, participants, runtime, backend_implementation, semantic, ancestry,
    native_snapshot, native_control, native_anchor, native_after_protocol, host_protocol,
    host_extension_registry, confirmation_request, confirmation; cut, ordinal);

fn portable_counter_scratch_data() -> usize {
    // Field references are named by the exact full DTO view rather than by
    // multiplying an unrelated pointer layout or charging their encoded lengths.
    fn fields<T>(_: impl FnOnce(&'static PacketCompleteRestoreRequest) -> T) -> usize {
        size_of::<T>()
    }
    fields(|request| {
        let PacketCompleteRestoreRequest {
            schema,
            archive_index,
            capture_manifest,
            owner_state,
            journal,
            source_runtime,
            backend_implementation,
            backend_schema,
            archived_cut,
            archived_ordinal,
            target_world,
            target_owner,
            target_owner_binding,
            target_activation,
            target_generation,
            target_owner_generation,
            mapping,
            nonce,
        } = request;
        (
            schema,
            archive_index,
            capture_manifest,
            owner_state,
            journal,
            source_runtime,
            backend_implementation,
            backend_schema,
            archived_cut,
            archived_ordinal,
            target_world,
            target_owner,
            target_owner_binding,
            target_activation,
            target_generation,
            target_owner_generation,
            mapping,
            nonce,
        )
    }) + size_of::<&mut dyn OriginalRestoredOwnerCapacitySink>()
        + size_of::<OriginalRestoredOwnerCapacityRow>()
        + size_of::<usize>()
}

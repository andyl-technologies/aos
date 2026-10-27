//! Walks every actual generic current17 operation and input container in place.
//!
//! The old Initial15 metadata admission retains its empty-map guard. This
//! separate defining support is selected by actual17 capture and includes each
//! independently owned request/result copy, failed original and retained context.

use crate::node_adapters::cnp::semantic::state::{
    OriginalCancellation, OriginalInput, OriginalInputCommit, OriginalOperation,
};
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityRow as Row, OriginalRestoredOwnerCapacitySink,
    OriginalRestoredOwnerCapacityWalk as Walk,
};
use crate::node_contract::{OperationFailure, RuntimeError};
use crate::node_scheduling::{InputCustodyCommit, NativeInputAcknowledgement};
use crucible_node_transport::bodies::{BeginRequest, InputRequest, InputResult};
use crucible_node_transport::envelope::Nullable;

macro_rules! fields {
    ($type:ty; $($owned:ident),+; $($scalar:ident),* $(,)?) => {
        impl Walk for $type {
            fn capacities(&self, depth: usize, sink: &mut dyn OriginalRestoredOwnerCapacitySink)
                -> Result<(), RuntimeError>
            {
                let inline_fields: &[&str] = &[$(stringify!($scalar)),*];
                sink.visit_work(1 + inline_fields.len())?;
                let Self { $($owned,)+ $($scalar: _,)* } = self;
                $($owned.capacities(depth, sink)?;)+
                Ok(())
            }
        }
    };
}

fields!(InputCustodyCommit; activation, node, stage_operation, batch, inventory; cutoff);
fields!(crucible_node_format::Event;
    id, source, destination, causal_parent_ids, payload, provenance_ref, extensions;
    schema_version, position, stage, publication_position, delivery_position, source_sequence);
fields!(BeginRequest; binding_hash, activation_id, arguments, extensions;
    kind, owner_generation, world_generation);
fields!(InputRequest; binding_hash, batch_id, input_epoch, events, batch_hash, extensions;
    owner_generation, batch_sequence);
fields!(InputResult; accepted_event_ids, custody_receipt, inventory_hash; input_watermark);
fields!(OriginalOperation;
    admission, begin, outcome, failure, cancellation, retirement;
    polls, begin_acknowledged, acknowledged);
fields!(OriginalInput;
    original, acknowledgement, request, commitment, response; watermark);
fields!(OriginalInputCommit; original, request_id, extensions, context, response;);

impl<T: Walk> Walk for Nullable<T> {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        self.0.capacities(depth, sink)
    }
}

impl Walk for serde_json::Map<String, serde_json::Value> {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        if depth >= 128 {
            return Err(RuntimeError::ResourceLimit);
        }
        sink.capacity_row(Row::tree_population_data::<String, serde_json::Value>(
            self.len(),
        ))?;
        for (key, value) in self {
            key.capacities(depth + 1, sink)?;
            value.capacities(depth + 1, sink)?;
        }
        Ok(())
    }
}

impl Walk for OriginalCancellation {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        match self {
            Self::Failed(failure) => failure.capacities(depth, sink),
            Self::NotAttempted | Self::Pending | Self::Requested | Self::Unsupported => Ok(()),
        }
    }
}

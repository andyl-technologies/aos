//! Records actual common-owner capacities without copying their contents.
//!
//! Rows follow a fixed typed field walk. They are historical allocation facts,
//! never a live grant or a promise that an allocator will reproduce a layout.
//! The finite restored Producer grammar refuses unsupported common variants.

use crate::node_contract::{
    ActivationRecord, NodeRoute, OperationAdmission, OperationOutcome, OperationRequest,
    OperationToken, OwnerIdentity, PreparedWorldPublication, ProgressEvidence, ReadyAttestation,
    RuntimeError, ValidatedNodePreparation, WorldActivation,
};
use crate::node_scheduling::event::Delivery;
use crate::node_scheduling::{
    InputIdentity, InputPayload, NativeExternalInput, NativeExternalInputInventory,
    NativeInputProgress, NativeProducerBound, NativePublication, NativeSchedulingObservation,
    RuntimeInputBatch,
};
use crucible_node_format::{Bytes, ContentRef, Endpoint, HashRef, Id, Position, U64};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::{
    cell::RefCell,
    mem::{align_of, align_of_val, size_of, size_of_val},
    rc::Rc,
};

mod aliases;
mod metadata;
mod values;

pub(crate) use aliases::OriginalRestoredOwnerCapacityAliases;
pub(crate) use metadata::{OriginalOwnerCapacityMetadataData, merge_capacity_metadata_data};
pub(crate) use values::OriginalRestoredOwnerHistory;

const MAXIMUM_ROWS: usize = 131_072;
const MAXIMUM_DEPTH: usize = 128;

/// Describes one real container in the defining traversal order.
#[derive(Serialize)]
pub(crate) struct OriginalRestoredOwnerCapacityRow {
    kind: &'static str,
    length: usize,
    capacity: Option<usize>,
    element_bytes: usize,
    alignment: usize,
    shared_group: Option<usize>,
    #[serde(skip)]
    identity: Option<*const ()>,
}

impl OriginalRestoredOwnerCapacityRow {
    /// Describes an actual byte buffer whose defining owner exposes both facts.
    ///
    /// This covers non-UTF-8 path/OS buffers without converting or copying them.
    /// Values are historical DATA, never authority to allocate that capacity.
    ///
    /// # Errors
    /// Refuses an initialized length beyond its actual retained capacity.
    pub(crate) fn byte_buffer_data(length: usize, capacity: usize) -> Result<Self, RuntimeError> {
        if length > capacity {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(Self {
            kind: "vector",
            length,
            capacity: Some(capacity),
            element_bytes: size_of::<u8>(),
            alignment: align_of::<u8>(),
            shared_group: None,
            identity: None,
        })
    }

    /// Describes exposed tree population without inventing hidden node capacity.
    pub(crate) fn tree_population_data<K, V>(length: usize) -> Self {
        Self {
            kind: "tree",
            length,
            capacity: None,
            element_bytes: size_of::<(K, V)>(),
            alignment: align_of::<(K, V)>(),
            shared_group: None,
            identity: None,
        }
    }
}

/// Receives independent allocation rows and typed traversal-work observations.
///
/// Historical serializers implement only the row callback. Work events never
/// enter their row stream or consume legacy row or alias slots.
pub(crate) trait OriginalRestoredOwnerCapacitySink {
    /// Retains or serializes one real allocation observation.
    ///
    /// # Errors
    /// Refuses invalid geometry, exhausted backing or the receiving writer's error.
    fn capacity_row(&mut self, row: OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>;

    /// Counts actual typed visits, including inline fields and empty wrappers.
    ///
    /// # Errors
    /// Refuses checked traversal-work overflow in observers that retain work.
    fn visit_work(&mut self, _visits: usize) -> Result<(), RuntimeError> {
        Ok(())
    }
}

impl<F> OriginalRestoredOwnerCapacitySink for F
where
    F: FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
{
    fn capacity_row(&mut self, row: OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError> {
        self(row)
    }
}

/// Walks the actual owners in a fixed defining order without creating a row bank.
pub(crate) trait OriginalRestoredOwnerCapacityWalk {
    /// Identifies leaves whose traversal is exactly one allocation-free visit.
    ///
    /// Containers aggregate these visits without dispatching once per byte.
    /// Implementations setting this flag must emit no row or child visit and
    /// perform exactly one successful work visit.
    const INLINE_WORK_LEAF: bool = false;

    /// Lends this owner's actual rows and visits in the defining field order.
    ///
    /// # Errors
    /// Refuses unsupported variants, depth limits or a sink error.
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError>;
}

/// Streams a checked capacity walk without a temporary row vector.
pub(crate) struct OriginalRestoredOwnerCapacityRows<'a, T: ?Sized>(pub &'a T);

impl<'a, T: OriginalRestoredOwnerCapacityWalk + ?Sized> OriginalRestoredOwnerCapacityRows<'a, T> {
    /// Counts actual rows and shared edge occurrences before lookup allocation.
    ///
    /// # Errors
    /// Refuses unsupported common variants or a traversal beyond its finite limits.
    pub(crate) fn metadata_demand_data(&self) -> Result<(usize, usize), RuntimeError> {
        let mut rows = 0usize;
        let mut shared = 0usize;
        self.0
            .capacities(0, &mut |row: OriginalRestoredOwnerCapacityRow| {
                rows = rows.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
                if rows > MAXIMUM_ROWS {
                    return Err(RuntimeError::ResourceLimit);
                }
                if row.identity.is_some() {
                    shared = shared.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
                }
                Ok(())
            })?;
        Ok((rows, shared))
    }

    /// Links shared rows through the same caller-precharged graph lookup.
    pub(crate) fn with_aliases(
        &self,
        aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
    ) -> OriginalRestoredSharedOwnerCapacityRows<'a, T> {
        OriginalRestoredSharedOwnerCapacityRows {
            value: self.0,
            aliases,
        }
    }
}

/// Lends a checked walk using the enclosing graph's same reserved alias bank.
pub(crate) struct OriginalRestoredSharedOwnerCapacityRows<'a, T: ?Sized> {
    value: &'a T,
    aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
}

impl<T: OriginalRestoredOwnerCapacityWalk + ?Sized> Serialize
    for OriginalRestoredOwnerCapacityRows<'_, T>
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_rows(self.0, None, serializer)
    }
}

impl<T: OriginalRestoredOwnerCapacityWalk + ?Sized> Serialize
    for OriginalRestoredSharedOwnerCapacityRows<'_, T>
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_rows(self.value, Some(self.aliases), serializer)
    }
}

fn serialize_rows<T: OriginalRestoredOwnerCapacityWalk + ?Sized, S: Serializer>(
    value: &T,
    aliases: Option<&RefCell<OriginalRestoredOwnerCapacityAliases>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;

    let mut count = 0usize;
    value
        .capacities(0, &mut |row: OriginalRestoredOwnerCapacityRow| {
            if row.identity.is_some() && aliases.is_none() {
                return Err(RuntimeError::InvalidReceipt);
            }
            count = count.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
            if count > MAXIMUM_ROWS {
                return Err(RuntimeError::ResourceLimit);
            }
            Ok(())
        })
        .map_err(S::Error::custom)?;

    let mut rows = serializer.serialize_seq(Some(count))?;
    let mut failure = None;
    value
        .capacities(0, &mut |mut row: OriginalRestoredOwnerCapacityRow| {
            if let Some(identity) = row.identity {
                row.shared_group = Some(
                    aliases
                        .ok_or(RuntimeError::InvalidReceipt)?
                        .try_borrow_mut()
                        .map_err(|_| RuntimeError::OwnerBusy)?
                        .group(identity)?,
                );
            }
            if let Err(error) = rows.serialize_element(&row) {
                failure = Some(error);
                return Err(RuntimeError::InvalidReceipt);
            }
            Ok(())
        })
        .map_err(|error| failure.unwrap_or_else(|| S::Error::custom(error)))?;
    rows.end()
}

macro_rules! no_capacity {
    ($($ty:ty),* $(,)?) => {$(
        impl OriginalRestoredOwnerCapacityWalk for $ty {
            const INLINE_WORK_LEAF: bool = true;

            fn capacities(
                &self,
                _depth: usize,
                sink: &mut dyn OriginalRestoredOwnerCapacitySink,
            ) -> Result<(), RuntimeError> {
                sink.visit_work(1)
            }
        }
    )*};
}

no_capacity!((), u8, U64, Position);

impl OriginalRestoredOwnerCapacityWalk for String {
    fn capacities(
        &self,
        _depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        sink.capacity_row(OriginalRestoredOwnerCapacityRow {
            kind: "string",
            length: self.len(),
            capacity: Some(self.capacity()),
            element_bytes: 1,
            alignment: 1,
            shared_group: None,
            identity: None,
        })
    }
}

impl OriginalRestoredOwnerCapacityWalk for Id {
    fn capacities(
        &self,
        _depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        sink.capacity_row(OriginalRestoredOwnerCapacityRow {
            kind: "string",
            length: self.as_str().len(),
            capacity: Some(self.allocated_capacity()),
            element_bytes: 1,
            alignment: 1,
            shared_group: None,
            identity: None,
        })
    }
}

impl<T: OriginalRestoredOwnerCapacityWalk> OriginalRestoredOwnerCapacityWalk for Option<T> {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        match self {
            Some(value) => value.capacities(depth, sink),
            None => Ok(()),
        }
    }
}

impl<T: OriginalRestoredOwnerCapacityWalk> OriginalRestoredOwnerCapacityWalk for Vec<T> {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        sink.capacity_row(OriginalRestoredOwnerCapacityRow {
            kind: "vector",
            length: self.len(),
            capacity: Some(self.capacity()),
            element_bytes: size_of::<T>(),
            alignment: align_of::<T>(),
            shared_group: None,
            identity: None,
        })?;
        if T::INLINE_WORK_LEAF {
            return sink.visit_work(self.len());
        }
        for value in self {
            value.capacities(depth, sink)?;
        }
        Ok(())
    }
}

impl<T: OriginalRestoredOwnerCapacityWalk> OriginalRestoredOwnerCapacityWalk for [T] {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        if T::INLINE_WORK_LEAF {
            return sink.visit_work(self.len());
        }
        for value in self {
            value.capacities(depth, sink)?;
        }
        Ok(())
    }
}

impl<T: OriginalRestoredOwnerCapacityWalk + ?Sized> OriginalRestoredOwnerCapacityWalk for Rc<T> {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        sink.capacity_row(OriginalRestoredOwnerCapacityRow {
            kind: "shared",
            length: 1,
            capacity: None,
            element_bytes: size_of_val(self.as_ref()),
            alignment: align_of_val(self.as_ref()),
            shared_group: None,
            identity: Some(Rc::as_ptr(self).cast()),
        })?;
        self.as_ref().capacities(depth, sink)
    }
}

impl<T: OriginalRestoredOwnerCapacityWalk + ?Sized> OriginalRestoredOwnerCapacityWalk for Box<T> {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        sink.capacity_row(OriginalRestoredOwnerCapacityRow {
            kind: "boxed",
            length: 1,
            capacity: None,
            element_bytes: size_of_val(self.as_ref()),
            alignment: align_of_val(self.as_ref()),
            shared_group: None,
            identity: None,
        })?;
        self.as_ref().capacities(depth, sink)
    }
}

impl<T: Ord + OriginalRestoredOwnerCapacityWalk> OriginalRestoredOwnerCapacityWalk
    for std::collections::BTreeSet<T>
{
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        if depth >= MAXIMUM_DEPTH {
            return Err(RuntimeError::ResourceLimit);
        }
        // A set exposes key population, not hidden BTree node capacity. Its
        // zero-sized value is not an independently owned payload allocation.
        sink.capacity_row(OriginalRestoredOwnerCapacityRow::tree_population_data::<
            T,
            (),
        >(self.len()))?;
        for value in self {
            value.capacities(depth + 1, sink)?;
        }
        Ok(())
    }
}

macro_rules! capacity_fields {
    ($ty:ty; $($field:ident),+; $($scalar:ident),* $(,)?) => {
        impl OriginalRestoredOwnerCapacityWalk for $ty {
            fn capacities(
                &self,
                depth: usize,
                sink: &mut dyn OriginalRestoredOwnerCapacitySink,
            ) -> Result<(), RuntimeError> {
                let inline_fields: &[&str] = &[$(stringify!($scalar)),*];
                sink.visit_work(1 + inline_fields.len())?;
                let Self { $($field,)+ $($scalar: _,)* } = self;
                $($field.capacities(depth, sink)?;)+
                Ok(())
            }
        }
    };
}

capacity_fields!(HashRef; algorithm, domain, digest;);
capacity_fields!(ContentRef; hash, media_type; length);
capacity_fields!(Endpoint; node_id, port_id, lane_id;);
capacity_fields!(OwnerIdentity; owner, incarnation; generation);
capacity_fields!(NodeRoute; node, owners;);
capacity_fields!(ActivationRecord; activation_id, world_binding_hash, owners; generation, boundary);
capacity_fields!(InputPayload; reference, bytes;);
capacity_fields!(InputIdentity; producer; source_sequence);
capacity_fields!(NativeProducerBound; producer, proof_ref; bound);
capacity_fields!(NativePublication; publication_id, endpoint, causal_parents, payload, payload_bytes;
    native_sequence, publication, evaluation);
capacity_fields!(NativeInputProgress; batch, consumed, proof_ref;);
capacity_fields!(NativeExternalInput; event_id, payload, payload_bytes, provenance_ref;
    native_sequence, publication);
capacity_fields!(NativeExternalInputInventory; endpoint, inputs, proof_ref; closed_before);
capacity_fields!(NativeSchedulingObservation;
    node, owners, bounds, publications, input_progress, external_inputs, proof_ref; reached, closed_prefix);
capacity_fields!(OperationOutcome;
    operation, node, owners, progress, retained_outputs, scheduling;);
capacity_fields!(ReadyAttestation; owners, state_inventory, ready_receipt; boundary);
capacity_fields!(crucible_node_format::PreparedOwner;
    owner_id, incarnation_id, prepared_token, binding_hashes, ready_receipt, extensions; owner_generation);
capacity_fields!(ValidatedNodePreparation; node, readiness, prepared_owners;);
capacity_fields!(PreparedWorldPublication; nodes, owners, coordinator;);
capacity_fields!(WorldActivation; authority, record, nodes, preparation;);
capacity_fields!(OperationToken; authority, operation, route;);
capacity_fields!(OperationAdmission; token, request, activation, inputs;);
capacity_fields!(RuntimeInputBatch;
    activation, node, stage_operation, batch, owners, inventory, deliveries, payloads; cutoff);
capacity_fields!(Delivery;
    connection_id, connection_policy_ref, external_root, provenance_ref,
    publication_id, producer, consumer, producer_endpoint, consumer_endpoint,
    causal_parents, payload; source_sequence, native_sequence, evaluation,
    publication, delivery);

impl OriginalRestoredOwnerCapacityWalk for OperationRequest {
    fn capacities(
        &self,
        _depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        match self {
            Self::ExactRun {
                start: _,
                limit: _,
                boundary_policy: _,
            }
            | Self::BoundarySettle { start: _, limit: _ }
            | Self::Pause
            | Self::Observe
            | Self::Capture
            | Self::Shutdown => Ok(()),
            _ => Err(RuntimeError::UnsupportedFacet),
        }
    }
}

impl OriginalRestoredOwnerCapacityWalk for ProgressEvidence {
    fn capacities(
        &self,
        _depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        match self {
            Self::Exact {
                reached: _,
                stop: _,
            }
            | Self::Administrative => Ok(()),
            _ => Err(RuntimeError::UnsupportedFacet),
        }
    }
}

impl OriginalRestoredOwnerCapacityWalk for serde_json::Value {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        if depth >= MAXIMUM_DEPTH {
            return Err(RuntimeError::ResourceLimit);
        }
        match self {
            Self::Null | Self::Bool(_) | Self::Number(_) => Ok(()),
            Self::String(value) => value.capacities(depth + 1, sink),
            Self::Array(values) => values.capacities(depth + 1, sink),
            Self::Object(values) => {
                // serde_json's tree exposes population, not node capacity.
                // Preserve that distinction instead of inventing spare nodes.
                sink.capacity_row(OriginalRestoredOwnerCapacityRow {
                    kind: "tree",
                    length: values.len(),
                    capacity: None,
                    element_bytes: size_of::<(String, serde_json::Value)>(),
                    alignment: align_of::<(String, serde_json::Value)>(),
                    shared_group: None,
                    identity: None,
                })?;
                for (key, value) in values {
                    key.capacities(depth + 1, sink)?;
                    value.capacities(depth + 1, sink)?;
                }
                Ok(())
            }
        }
    }
}

impl OriginalRestoredOwnerCapacityWalk for Bytes {
    fn capacities(
        &self,
        _depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        sink.capacity_row(OriginalRestoredOwnerCapacityRow {
            kind: "vector",
            length: self.as_slice().len(),
            capacity: Some(self.allocation_capacity()),
            element_bytes: 1,
            alignment: 1,
            shared_group: None,
            identity: None,
        })
    }
}

impl<K: Ord + OriginalRestoredOwnerCapacityWalk, V: OriginalRestoredOwnerCapacityWalk>
    OriginalRestoredOwnerCapacityWalk for std::collections::BTreeMap<K, V>
{
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        if depth >= MAXIMUM_DEPTH {
            return Err(RuntimeError::ResourceLimit);
        }
        sink.capacity_row(
            OriginalRestoredOwnerCapacityRow::tree_population_data::<K, V>(self.len()),
        )?;
        for (key, value) in self {
            key.capacities(depth + 1, sink)?;
            value.capacities(depth + 1, sink)?;
        }
        Ok(())
    }
}

capacity_fields!(crucible_node_transport::bodies::BlobBeginRequest; transfer_id, content, extensions;);
capacity_fields!(crucible_node_transport::bodies::BlobChunkRequest; transfer_id, bytes, extensions; offset);
capacity_fields!(crucible_node_transport::bodies::BlobFinishRequest; transfer_id, extensions;);

/// Names defining borrowed rows, shared lookup and complete local return views.
///
/// Serializer output and prospective recorded rows are independent dynamic
/// terms. This fixed demand grants no permission to allocate either bank.
pub(crate) fn original_restored_owner_capacity_counter_scratch_data() -> usize {
    use std::cell::{BorrowMutError, RefMut};

    let terms = [
        values::counter_scratch_data(),
        size_of::<&[&str]>(),
        size_of::<usize>(),
        size_of::<(usize, usize)>(),
        size_of::<Result<(usize, usize), RuntimeError>>(),
        size_of::<OriginalRestoredOwnerCapacityRow>(),
        size_of::<Result<OriginalRestoredOwnerCapacityRow, RuntimeError>>(),
        size_of::<&mut OriginalRestoredOwnerCapacityAliases>(),
        size_of::<&std::sync::Arc<()>>(),
        size_of::<&std::rc::Weak<()>>(),
        size_of::<std::rc::Weak<()>>(),
        size_of::<Option<usize>>(),
        size_of::<OriginalRestoredOwnerCapacityRows<'static, OperationAdmission>>(),
        size_of::<OriginalRestoredOwnerCapacityRows<'static, [OwnerIdentity]>>(),
        size_of::<OriginalRestoredSharedOwnerCapacityRows<'static, OperationAdmission>>(),
        size_of::<OriginalRestoredSharedOwnerCapacityRows<'static, [OwnerIdentity]>>(),
        size_of::<OriginalRestoredOwnerCapacityAliases>(),
        size_of::<Option<OriginalRestoredOwnerCapacityAliases>>(),
        size_of::<Result<OriginalRestoredOwnerCapacityAliases, RuntimeError>>(),
        size_of::<&mut Option<OriginalRestoredOwnerCapacityAliases>>(),
        size_of::<Option<&mut OriginalRestoredOwnerCapacityAliases>>(),
        size_of::<std::iter::Enumerate<std::slice::Iter<'static, *const ()>>>(),
        size_of::<&OriginalRestoredOwnerCapacityAliases>(),
        size_of::<RefCell<OriginalRestoredOwnerCapacityAliases>>(),
        size_of::<RefMut<'static, OriginalRestoredOwnerCapacityAliases>>(),
        size_of::<Result<RefMut<'static, OriginalRestoredOwnerCapacityAliases>, BorrowMutError>>(),
        size_of::<Option<&RefCell<OriginalRestoredOwnerCapacityAliases>>>(),
        size_of::<&mut dyn OriginalRestoredOwnerCapacitySink>(),
        size_of::<Result<(), RuntimeError>>(),
        size_of::<Result<usize, RuntimeError>>(),
        size_of::<Option<usize>>(),
        size_of::<Option<serde_json::Error>>(),
        size_of::<std::slice::Iter<'static, *const ()>>(),
        size_of::<std::slice::Iter<'static, ValidatedNodePreparation>>(),
        size_of::<std::slice::Iter<'static, OwnerIdentity>>(),
        size_of::<std::slice::Iter<'static, NativePublication>>(),
        size_of::<std::slice::Iter<'static, NativeExternalInput>>(),
        size_of::<std::slice::Iter<'static, NativeExternalInputInventory>>(),
        size_of::<std::slice::Iter<'static, Delivery>>(),
        size_of::<std::slice::Iter<'static, InputPayload>>(),
        size_of::<std::slice::Iter<'static, Id>>(),
        size_of::<std::collections::btree_set::Iter<'static, Id>>(),
        size_of::<&Box<String>>(),
        size_of::<&std::collections::BTreeSet<Id>>(),
        size_of::<std::slice::Iter<'static, Position>>(),
        size_of::<std::slice::Iter<'static, NativeProducerBound>>(),
        size_of::<std::slice::Iter<'static, InputIdentity>>(),
        size_of::<std::slice::Iter<'static, ContentRef>>(),
        size_of::<std::slice::Iter<'static, HashRef>>(),
        size_of::<std::slice::Iter<'static, u8>>(),
        MAXIMUM_DEPTH
            * (size_of::<std::collections::btree_map::Iter<'static, String, serde_json::Value>>()
                + size_of::<std::slice::Iter<'static, serde_json::Value>>()
                + size_of::<&serde_json::Value>()),
    ];
    let array_bytes = size_of_val(&terms);
    let mut iterator = terms.into_iter();
    let iterator_bytes = size_of_val(&iterator);
    let Some(initial) = array_bytes.checked_add(iterator_bytes) else {
        return usize::MAX;
    };
    iterator
        .try_fold(initial, usize::checked_add)
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "pure actual-capacity controls assert checked serialization"
)]
mod tests {
    use super::*;

    #[test]
    fn empty_vectors_keep_spare_capacity_and_nested_strings_keep_independent_banks() {
        let empty = Vec::<Id>::with_capacity(7);
        let row = serde_json::to_value(OriginalRestoredOwnerCapacityRows(&empty)).unwrap();
        assert_eq!(row[0]["length"], 0);
        assert_eq!(row[0]["capacity"], empty.capacity());
        assert_eq!(row[0]["element_bytes"], size_of::<Id>());

        let mut text = String::with_capacity(173);
        text.push_str("retained");
        let actual_capacity = text.capacity();
        let mut array = Vec::with_capacity(5);
        array.push(serde_json::Value::String(text));
        let actual_array_capacity = array.capacity();
        let value = serde_json::Value::Array(array);
        let rows = serde_json::to_value(OriginalRestoredOwnerCapacityRows(&value)).unwrap();
        assert_eq!(rows[0]["capacity"], actual_array_capacity);
        assert_eq!(rows[1]["capacity"], actual_capacity);
        assert_eq!(rows[1]["length"], "retained".len());
    }

    #[test]
    fn shared_rows_require_the_real_lookup_and_preserve_alias_groups() {
        let original = Rc::new(String::from("same data"));
        let alias = Rc::clone(&original);
        let independent = Rc::new(String::from("same data"));
        let mut bytes = Vec::new();
        assert!(
            serde_json::to_writer(&mut bytes, &OriginalRestoredOwnerCapacityRows(&original))
                .is_err()
        );
        assert!(bytes.is_empty());

        let mut slot = None;
        OriginalRestoredOwnerCapacityAliases::reserve_into(2, &mut slot).unwrap();
        let bank = RefCell::new(slot.unwrap());
        bank.borrow_mut().begin_pass().unwrap();
        let first =
            serde_json::to_value(OriginalRestoredOwnerCapacityRows(&original).with_aliases(&bank))
                .unwrap();
        let second =
            serde_json::to_value(OriginalRestoredOwnerCapacityRows(&alias).with_aliases(&bank))
                .unwrap();
        let third = serde_json::to_value(
            OriginalRestoredOwnerCapacityRows(&independent).with_aliases(&bank),
        )
        .unwrap();
        assert_eq!(first[0]["shared_group"], 0);
        assert_eq!(second[0]["shared_group"], 0);
        assert_eq!(third[0]["shared_group"], 1);
        assert!(first[0].get("identity").is_none());
        assert!(first[0]["capacity"].is_null());
        assert_eq!(first[0]["element_bytes"], size_of::<String>());
    }

    #[test]
    fn boxed_and_set_owners_keep_payload_layout_population_and_actual_child_capacity() {
        let mut text = String::with_capacity(97);
        text.push_str("boxed");
        let actual_capacity = text.capacity();
        let boxed = Box::new(text);
        let rows = serde_json::to_value(OriginalRestoredOwnerCapacityRows(&boxed)).unwrap();
        assert_eq!(rows[0]["kind"], "boxed");
        assert_eq!(rows[0]["element_bytes"], size_of::<String>());
        assert_eq!(rows[0]["alignment"], align_of::<String>());
        assert_eq!(rows[1]["capacity"], actual_capacity);
        let mut values = std::collections::BTreeSet::new();
        values.insert(String::from("a"));
        values.insert(String::from("b"));
        let rows = serde_json::to_value(OriginalRestoredOwnerCapacityRows(&values)).unwrap();
        assert_eq!(rows[0]["kind"], "tree");
        assert_eq!(rows[0]["length"], 2);
        assert!(rows[0]["capacity"].is_null());
        assert_eq!(rows[0]["element_bytes"], size_of::<(String, ())>());
        assert_eq!(rows.as_array().unwrap().len(), 3);
    }

    #[test]
    fn byte_buffer_rows_keep_spare_raw_capacity_without_utf8_or_allocation() {
        use std::os::unix::ffi::OsStrExt;
        let mut path = std::path::PathBuf::with_capacity(97);
        path.push(std::ffi::OsStr::from_bytes(b"/non-utf8-\xff"));
        let row = OriginalRestoredOwnerCapacityRow::byte_buffer_data(
            path.as_os_str().as_bytes().len(),
            path.capacity(),
        )
        .unwrap();
        let actual = serde_json::to_value(&row).unwrap();
        assert_eq!(actual["length"], path.as_os_str().as_bytes().len());
        assert_eq!(actual["capacity"], path.capacity());
        assert_eq!(actual["element_bytes"], 1);
        assert_eq!(actual["alignment"], 1);
        assert!(path.to_str().is_none());
        assert!(OriginalRestoredOwnerCapacityRow::byte_buffer_data(2, 1).is_err());
    }

    #[test]
    fn scalar_administrative_history_is_preserved_without_heap_or_live_permission() {
        for request in [
            OperationRequest::Pause,
            OperationRequest::Observe,
            OperationRequest::Capture,
            OperationRequest::Shutdown,
        ] {
            let rows = serde_json::to_value(OriginalRestoredOwnerCapacityRows(&request)).unwrap();
            assert_eq!(rows, serde_json::json!([]));
            assert_eq!(
                serde_json::from_value::<OperationRequest>(serde_json::to_value(&request).unwrap())
                    .unwrap(),
                request
            );
        }
        assert_eq!(
            serde_json::to_value(OriginalRestoredOwnerCapacityRows(
                &ProgressEvidence::Administrative
            ))
            .unwrap(),
            serde_json::json!([])
        );
    }

    #[test]
    fn unsupported_common_variants_and_excess_depth_refuse_before_output() {
        let mut bytes = Vec::new();
        assert!(
            serde_json::to_writer(
                &mut bytes,
                &OriginalRestoredOwnerCapacityRows(&OperationRequest::QuantumClose {
                    window: Id::new("unsupported-quantum").unwrap(),
                })
            )
            .is_err()
        );
        assert!(bytes.is_empty());

        let mut value = serde_json::Value::Null;
        for _ in 0..=MAXIMUM_DEPTH {
            value = serde_json::Value::Array(vec![value]);
        }
        assert!(
            serde_json::to_writer(&mut bytes, &OriginalRestoredOwnerCapacityRows(&value)).is_err()
        );
        assert!(bytes.is_empty());
        assert!(value.is_array());
    }
}

pub(crate) mod finalizers17;

// These common records are consumed by both native/Host and Node history.
// Keep their exhaustive defining walk here rather than in either adapter path.
impl OriginalRestoredOwnerCapacityWalk for crate::node_contract::OperationFailure {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        let Self { effects, reason } = self;
        reason.capacities(depth, sink)?;
        effects.capacities(depth, sink)
    }
}

impl OriginalRestoredOwnerCapacityWalk for crate::node_scheduling::NativeInputAcknowledgement {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        let Self {
            stage_operation,
            batch,
            node,
            owners,
            cutoff: _,
            inventory,
            proof_ref,
        } = self;
        stage_operation.capacities(depth, sink)?;
        batch.capacities(depth, sink)?;
        node.capacities(depth, sink)?;
        owners.capacities(depth, sink)?;
        inventory.capacities(depth, sink)?;
        proof_ref.capacities(depth, sink)
    }
}

#[cfg(test)]
mod shared_failure_capacity_tests {
    use super::*;
    use crate::node_contract::{EffectKnowledge, OperationFailure};

    #[test]
    fn committed_prefix_ids_remain_in_shared_failure_capacity_walk() {
        let none = OperationFailure {
            effects: EffectKnowledge::None,
            reason: "retained refusal".into(),
        };
        let prefix = OperationFailure {
            effects: EffectKnowledge::CommittedPrefix(vec![
                crucible_node_format::Id::new("retained/original-output").unwrap(),
            ]),
            reason: none.reason.clone(),
        };

        let empty = OriginalRestoredOwnerCapacityRows(&none)
            .metadata_demand_data()
            .unwrap();
        let retained = OriginalRestoredOwnerCapacityRows(&prefix)
            .metadata_demand_data()
            .unwrap();

        assert!(retained.0 > empty.0);
    }
}

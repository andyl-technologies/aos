//! Bridges actual common-owner capacity walks to packet metadata geometry.
//!
//! Four-field packet rows retain compiled layouts and original capacities. Raw
//! pointer observations and common-history alias groups never enter this bank.
//! Shared views receive no deduplication credit. This capacity-only adapter does
//! not count scalar traversal work or provide a Source action or allocation right.

use super::{OriginalRestoredOwnerCapacityRow, OriginalRestoredOwnerCapacityWalk};
use crate::node_contract::RuntimeError;
use crucible_node_transport::{
    ProviderError,
    retained_metadata::{
        RetainedProtocolMetadataFacts,
        records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
    },
};
use std::{
    mem::{align_of, size_of},
    rc::{Rc, Weak},
};

/// Observes original capacities while optionally retaining their physical rows.
pub(crate) struct OriginalOwnerCapacityMetadataData<'a> {
    facts: RetainedProtocolMetadataFacts,
    maximum_rows: usize,
    bank: Option<&'a mut PacketRuntimeMetadataRecordBank>,
}

impl<'a> OriginalOwnerCapacityMetadataData<'a> {
    /// Creates allocation-free DATA controls within an independently selected bound.
    pub(crate) fn new(
        maximum_rows: usize,
        bank: Option<&'a mut PacketRuntimeMetadataRecordBank>,
    ) -> Self {
        Self {
            facts: Default::default(),
            maximum_rows,
            bank,
        }
    }

    /// Visits the actual common owner's defining capacity roster.
    ///
    /// # Errors
    /// Refuses unsupported owners, invalid or overflowing layout, exhausted rows
    /// or an unready physical bank. Earlier physical rows remain retained.
    pub(crate) fn observe<T: OriginalRestoredOwnerCapacityWalk + ?Sized>(
        &mut self,
        owner: &T,
    ) -> Result<(), RuntimeError> {
        owner.capacities(0, &mut |row| self.record(packet_row_data(row)?))
    }

    /// Joins a closed SDK capture component and preserves earlier physical rows.
    ///
    /// # Errors
    /// Refuses SDK origin, borrow, layout or ordinary traversal failures, exhausted
    /// aggregate rows or unavailable physical backing. The SDK owns its defining
    /// roster and checks creator identity before touching the physical bank.
    pub(crate) fn observe_capture_protocol_data(
        &mut self,
        owner: crucible_node_transport::retained_metadata::RetainedCaptureProtocolData<'_>,
    ) -> Result<(), RuntimeError> {
        let additional = match self.bank.as_deref_mut() {
            Some(bank) => owner.record_retained_metadata_data(bank),
            None => owner.observe_retained_metadata(),
        }
        .map_err(metadata_error)?;
        self.facts
            .capacity_records
            .checked_add(additional.capacity_records)
            .filter(|rows| *rows <= self.maximum_rows)
            .ok_or(RuntimeError::ResourceLimit)?;
        merge_capacity_metadata_data(&mut self.facts, &additional)
    }

    /// Keeps a Copy field in the defining allocation-free roster.
    ///
    /// This compile-time bound prevents a fixed field from silently acquiring an
    /// owned String, Vec, Box, Rc or Weak. It adds no allocation or scalar-work
    /// row; borrowed references and external resources remain separate owners.
    pub(crate) const fn observe_inline_data<T: Copy>(&self, _value: &T) {}

    /// Records the real enclosing allocation of one borrowed strong Rc view.
    ///
    /// Nested payload owners require their own defining walk. Repeated views
    /// keep their independent shared headers without cloning or pointer output.
    ///
    /// # Errors
    /// Refuses invalid geometry, selected-row exhaustion or unready backing.
    pub(crate) fn observe_shared_allocation_data<T>(
        &mut self,
        _owner: &Rc<T>,
    ) -> Result<(), RuntimeError> {
        self.record(MetadataCapacityRecord {
            kind: MetadataRecordKind::Shared,
            extent: size_of::<T>(),
            element_bytes: 1,
            alignment: align_of::<T>(),
        })
    }

    /// Records the actual allocation shell retained by one original weak view.
    ///
    /// Empty Weak values retain no allocation. An expired original Weak still
    /// retains its compiled payload slot and shared header, even after payload
    /// destruction. This capacity-only walk never upgrades or dereferences the
    /// weak view. Nested payload owners remain separate; repeated views receive
    /// no alias discount and no pointer enters the physical rows.
    ///
    /// # Errors
    /// Refuses checked geometry overflow, selected-row exhaustion or unready
    /// physical backing. Earlier rows and the original weak owner stay retained.
    pub(crate) fn observe_weak_allocation_data<T>(
        &mut self,
        owner: &Weak<T>,
    ) -> Result<(), RuntimeError> {
        if Weak::ptr_eq(owner, &Weak::new()) {
            return Ok(());
        }

        self.record(MetadataCapacityRecord {
            kind: MetadataRecordKind::Shared,
            extent: size_of::<T>(),
            element_bytes: 1,
            alignment: align_of::<T>(),
        })
    }

    /// Includes a typed enclosing allocation omitted from its payload's walk.
    ///
    /// # Errors
    /// Refuses invalid or overflowing scalar layout, exhausted row restrictions
    /// or unready physical backing. This numeric DATA authenticates no owner.
    pub(crate) fn record(&mut self, record: MetadataCapacityRecord) -> Result<(), RuntimeError> {
        record.validate_data().map_err(metadata_error)?;
        let next = self
            .facts
            .capacity_records
            .checked_add(1)
            .filter(|rows| *rows <= self.maximum_rows)
            .ok_or(RuntimeError::ResourceLimit)?;
        let bytes = record
            .extent
            .checked_mul(record.element_bytes)
            .ok_or(RuntimeError::ResourceLimit)?;

        match record.kind {
            MetadataRecordKind::String => {
                add(&mut self.facts.string_capacity_bytes, bytes)?;
                add(&mut self.facts.string_banks, 1)?;
            }
            MetadataRecordKind::Vector => {
                add(&mut self.facts.vector_capacity_bytes, bytes)?;
                add(&mut self.facts.vector_banks, 1)?;
            }
            MetadataRecordKind::Tree => {
                add(&mut self.facts.tree_containers, 1)?;
                add(&mut self.facts.tree_entries, record.extent)?;
                self.facts.maximum_tree_key_value_bytes = self
                    .facts
                    .maximum_tree_key_value_bytes
                    .max(record.element_bytes);
                self.facts.maximum_tree_entry_alignment = self
                    .facts
                    .maximum_tree_entry_alignment
                    .max(record.alignment);
            }
            MetadataRecordKind::Shared => {
                add(&mut self.facts.shared_value_bytes, bytes)?;
                add(&mut self.facts.shared_backing_views, 1)?;
                self.facts.maximum_shared_value_alignment = self
                    .facts
                    .maximum_shared_value_alignment
                    .max(record.alignment);
            }
            MetadataRecordKind::Boxed => add(&mut self.facts.boxed_value_bytes, bytes)?,
        }
        self.facts.capacity_records = next;
        if let Some(bank) = self.bank.as_deref_mut() {
            bank.append_capacity_record_data(record)
                .map_err(metadata_error)?;
        }
        Ok(())
    }

    /// Returns capacity geometry without inventing a scalar traversal-work count.
    pub(crate) fn finish(self) -> RetainedProtocolMetadataFacts {
        self.facts
    }

    /// Names actual census, row conversion, checked merge and borrowed controls.
    pub(crate) const fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&mut Self>()
            + size_of::<Rc<()>>()
            + size_of::<&Rc<()>>()
            + size_of::<&Self>()
            + size_of::<Weak<()>>()
            + size_of::<&Weak<()>>()
            + size_of::<OriginalRestoredOwnerCapacityRow>()
            + size_of::<MetadataCapacityRecord>()
            + size_of::<Result<MetadataCapacityRecord, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<&RetainedProtocolMetadataFacts>()
            + size_of::<&mut RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<&mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>>(
            )
            + size_of::<[(&mut usize, usize); 11]>()
            + size_of::<std::array::IntoIter<(&mut usize, usize), 11>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<&usize>()
            + 4 * size_of::<usize>()
    }
}

fn packet_row_data(
    row: OriginalRestoredOwnerCapacityRow,
) -> Result<MetadataCapacityRecord, RuntimeError> {
    let OriginalRestoredOwnerCapacityRow {
        kind,
        length,
        capacity,
        element_bytes,
        alignment,
        shared_group: _,
        identity: _,
    } = row;
    let (kind, extent, element_bytes) = match kind {
        "string" | "vector" => {
            let capacity = capacity
                .filter(|capacity| length <= *capacity)
                .ok_or(RuntimeError::InvalidReceipt)?;
            let kind = if kind == "string" {
                MetadataRecordKind::String
            } else {
                MetadataRecordKind::Vector
            };
            (kind, capacity, element_bytes)
        }
        "tree" if capacity.is_none() => (MetadataRecordKind::Tree, length, element_bytes),
        "shared" | "boxed" if capacity.is_none() && length == 1 => {
            let kind = if kind == "shared" {
                MetadataRecordKind::Shared
            } else {
                MetadataRecordKind::Boxed
            };
            (kind, element_bytes, 1)
        }
        _ => return Err(RuntimeError::InvalidReceipt),
    };
    let record = MetadataCapacityRecord {
        kind,
        extent,
        element_bytes,
        alignment,
    };
    record.validate_data().map_err(metadata_error)?;
    Ok(record)
}

/// Adds independent capacity views without changing their original tree layouts.
///
/// # Errors
/// Refuses checked population or byte overflow. Partial DATA supplies no rights.
pub(crate) fn merge_capacity_metadata_data(
    target: &mut RetainedProtocolMetadataFacts,
    additional: &RetainedProtocolMetadataFacts,
) -> Result<(), RuntimeError> {
    let RetainedProtocolMetadataFacts {
        string_capacity_bytes,
        string_banks,
        vector_capacity_bytes,
        vector_banks,
        boxed_value_bytes,
        shared_value_bytes,
        shared_backing_views,
        tree_containers,
        tree_entries,
        maximum_tree_key_value_bytes,
        maximum_tree_entry_alignment,
        maximum_shared_value_alignment,
        observed_nodes,
        capacity_records,
    } = *additional;
    for (total, value) in [
        (&mut target.string_capacity_bytes, string_capacity_bytes),
        (&mut target.string_banks, string_banks),
        (&mut target.vector_capacity_bytes, vector_capacity_bytes),
        (&mut target.vector_banks, vector_banks),
        (&mut target.boxed_value_bytes, boxed_value_bytes),
        (&mut target.shared_value_bytes, shared_value_bytes),
        (&mut target.shared_backing_views, shared_backing_views),
        (&mut target.tree_containers, tree_containers),
        (&mut target.tree_entries, tree_entries),
        (&mut target.observed_nodes, observed_nodes),
        (&mut target.capacity_records, capacity_records),
    ] {
        add(total, value)?;
    }
    target.maximum_tree_key_value_bytes = target
        .maximum_tree_key_value_bytes
        .max(maximum_tree_key_value_bytes);
    target.maximum_tree_entry_alignment = target
        .maximum_tree_entry_alignment
        .max(maximum_tree_entry_alignment);
    target.maximum_shared_value_alignment = target
        .maximum_shared_value_alignment
        .max(maximum_shared_value_alignment);
    Ok(())
}

fn add(total: &mut usize, bytes: usize) -> Result<(), RuntimeError> {
    *total = total
        .checked_add(bytes)
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok(())
}

fn metadata_error(error: ProviderError) -> RuntimeError {
    match error {
        ProviderError::ResourceExhausted(_) => RuntimeError::ResourceLimit,
        _ => RuntimeError::InvalidReceipt,
    }
}

#[cfg(test)]
mod tests;

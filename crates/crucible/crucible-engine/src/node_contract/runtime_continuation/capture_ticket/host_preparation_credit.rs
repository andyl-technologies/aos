//! Precharges borrowed original host closure before its first owning copy.
//!
//! The geometry is allocation data. Current runtime/source/node custody and
//! complete source-selected capture permission remain separate conjunctions.

use super::*;
use crate::node_contract::{HostSchedulingSelection, NodeRuntime};
use crate::node_scheduling::{InputPayload, SchedulingSnapshot};
use serde::{Serialize, Serializer, ser::SerializeSeq};

#[derive(Serialize)]
#[serde(tag = "kind", content = "record", rename_all = "kebab-case")]
enum BorrowedRuntime<'a> {
    OriginalLineage(&'a OriginalLineageRuntimeRecord),
}

struct BorrowedObjects<'a>(&'a NodeRuntime);

impl Serialize for BorrowedObjects<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = self.0.original_lineage_capture_objects().count();
        let mut objects = serializer.serialize_seq(Some(count))?;
        for object in self.0.original_lineage_capture_objects() {
            objects.serialize_element(object)?;
        }
        objects.end()
    }
}

#[derive(Serialize)]
struct BorrowedHostRecord<'a> {
    schema_version: u16,
    source: &'a HostSchedulingSelection,
    runtime: BorrowedRuntime<'a>,
    scheduling: &'a SchedulingSnapshot,
    objects: BorrowedObjects<'a>,
}

pub(super) fn precharge(
    runtime: &NodeRuntime,
    source: &HostSchedulingSelection,
    original: &OriginalLineageRuntimeRecord,
    scheduling: &SchedulingSnapshot,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let borrowed = BorrowedHostRecord {
        schema_version: 2,
        source,
        runtime: BorrowedRuntime::OriginalLineage(original),
        scheduling,
        objects: BorrowedObjects(runtime),
    };
    // This visitor observes the complete byte-array representation without
    // allocating a Value or encoded bank. Repeated original body occurrences
    // stay charged even when the later producer deduplicates their references.
    let serialization = NodeRuntime::capture_serialization_storage(&borrowed, maximum)?;
    let mut typed = storage::add(
        NodeRuntime::capture_runtime_record_storage(original)?,
        NodeRuntime::capture_scheduling_record_storage(scheduling)?,
    )?;
    typed = storage::add(typed, NodeRuntime::capture_host_selection_storage(source)?)?;
    let mut count = 0usize;
    for object in runtime.original_lineage_capture_objects() {
        count = storage::add(count, 1)?;
        typed = storage::add(typed, storage::payload(object)?)?;
    }
    // The producer reserves its final payload vector exactly. A four-slot
    // floor and doubled count also cover its borrowed temporary reference list.
    let object_slots = count
        .checked_mul(2)
        .map(|count| count.max(4))
        .and_then(|count| count.checked_mul(std::mem::size_of::<InputPayload>()))
        .ok_or(RuntimeError::ResourceLimit)?;
    typed = storage::add(typed, object_slots)?;
    // original_objects builds one borrowed ordered map before its final body
    // copies. Keys/values borrow original storage, but nodes are independent
    // requested allocations even when body references later deduplicate.
    let borrowed_nodes = count
        .max(1)
        .checked_mul(NodeRuntime::capture_map_node_storage::<
            &crucible_node_format::ContentRef,
            &InputPayload,
        >())
        .ok_or(RuntimeError::ResourceLimit)?;
    typed = storage::add(typed, borrowed_nodes)?;

    // The producer retains its canonical byte bank alongside the typed record
    // and transient Value. The borrowed closed shape counts that output before
    // either owning representation is constructed.
    let encoded = NodeRuntime::capture_encoded_output_storage(&borrowed, maximum)?;
    let requested = storage::add(storage::add(typed, serialization)?, encoded)?;
    if requested > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(requested)
}

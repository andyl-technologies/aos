//! Prices reporting with the widest actual enclosing Source and SDK tree layout.
//!
//! Current backing receives no refund. Future child visits bound both new tree
//! populations and capacity records, so a separately selected complete bank can
//! retain successful and refused metadata walks. This constructs no such bank.

use super::{add, multiply, sum};
use crate::{
    ProviderError,
    client::CompactClientOriginal,
    envelope::Envelope,
    retained_metadata::{
        PacketRuntimeMetadataProfileData, RetainedProtocolMetadataFacts,
        records::{MetadataCapacityRecord, MetadataRecordBank},
        requested_storage::tree_storage_data,
    },
};
use crucible_node_format::Id;
use serde_json::Value;
use std::mem::{align_of, size_of};

pub(super) fn storage_data(
    source: &RetainedProtocolMetadataFacts,
    sdk: &RetainedProtocolMetadataFacts,
    suffix: &RetainedProtocolMetadataFacts,
    profile: PacketRuntimeMetadataProfileData,
) -> Result<[usize; 2], ProviderError> {
    let future = profile.maximum_future_rows_data()?;
    let [mut containers, mut entries] = profile.maximum_future_tree_population_data();
    let mut records = future;
    let mut key_value = (size_of::<Id>() + size_of::<Envelope>())
        .max(size_of::<Id>() + size_of::<CompactClientOriginal>())
        .max(size_of::<String>() + size_of::<Value>());
    let mut alignment = align_of::<(Id, Envelope)>()
        .max(align_of::<(Id, CompactClientOriginal)>())
        .max(align_of::<(String, Value)>());
    for facts in [source, sdk, suffix] {
        std::alloc::Layout::from_size_align(0, facts.maximum_tree_entry_alignment.max(1))
            .map_err(|_| super::refused())?;
        containers = add(containers, facts.tree_containers)?;
        entries = add(entries, facts.tree_entries)?;
        records = add(records, facts.capacity_records)?;
        key_value = key_value.max(facts.maximum_tree_key_value_bytes);
        alignment = alignment.max(facts.maximum_tree_entry_alignment);
    }

    // A new wider entry widens every tree in the aggregate report, even an
    // existing empty root. Reprice all current trees instead of spending their
    // previously admitted backing as a discount on this future report.
    let trees = tree_storage_data(containers, entries, key_value, alignment)?;
    let bank = multiply(records, size_of::<MetadataCapacityRecord>())?;
    Ok([
        sum(&[trees, bank, size_of::<MetadataRecordBank>()])?,
        records,
    ])
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<[&RetainedProtocolMetadataFacts; 3]>()
        + size_of::<std::array::IntoIter<&RetainedProtocolMetadataFacts, 3>>()
        + size_of::<&RetainedProtocolMetadataFacts>()
        + size_of::<PacketRuntimeMetadataProfileData>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 2]>()
        + size_of::<Result<[usize; 2], ProviderError>>()
        + size_of::<std::alloc::Layout>()
        + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
        + 4 * size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + 12 * size_of::<usize>()
}

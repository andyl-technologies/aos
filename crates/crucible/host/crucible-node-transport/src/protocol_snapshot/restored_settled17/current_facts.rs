//! Records closed scalar allocation facts without constructing reservations.

use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{Fields, HistoricalType, Ledger, invalid};
use crate::retained_metadata::RetainedProtocolMetadataFacts;
use serde::{Serialize, Serializer, ser::SerializeTuple};

pub(crate) struct BorrowedMetadataFacts17<'a>(pub(crate) &'a RetainedProtocolMetadataFacts);

impl Serialize for BorrowedMetadataFacts17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
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
        } = self.0;
        let mut fields = serializer.serialize_tuple(14)?;
        fields.serialize_element(string_capacity_bytes)?;
        fields.serialize_element(string_banks)?;
        fields.serialize_element(vector_capacity_bytes)?;
        fields.serialize_element(vector_banks)?;
        fields.serialize_element(boxed_value_bytes)?;
        fields.serialize_element(shared_value_bytes)?;
        fields.serialize_element(shared_backing_views)?;
        fields.serialize_element(tree_containers)?;
        fields.serialize_element(tree_entries)?;
        fields.serialize_element(maximum_tree_key_value_bytes)?;
        fields.serialize_element(maximum_tree_entry_alignment)?;
        fields.serialize_element(maximum_shared_value_alignment)?;
        fields.serialize_element(observed_nodes)?;
        fields.serialize_element(capacity_records)?;
        fields.end()
    }
}

/// Retains each original measured scalar independently from parser capacities.
pub(crate) struct HistoricalMetadataFacts17(pub(crate) RetainedProtocolMetadataFacts);

impl HistoricalType for HistoricalMetadataFacts17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let string_capacity_bytes =
            ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let string_banks = ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let vector_capacity_bytes =
            ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let vector_banks = ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let boxed_value_bytes = ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let shared_value_bytes =
            ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let shared_backing_views =
            ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let tree_containers = ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let tree_entries = ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let maximum_tree_key_value_bytes =
            ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let maximum_tree_entry_alignment =
            ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let maximum_shared_value_alignment =
            ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let observed_nodes = ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        let capacity_records = ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self(RetainedProtocolMetadataFacts {
            string_capacity_bytes: string_capacity_bytes.ok_or_else(invalid)?,
            string_banks: string_banks.ok_or_else(invalid)?,
            vector_capacity_bytes: vector_capacity_bytes.ok_or_else(invalid)?,
            vector_banks: vector_banks.ok_or_else(invalid)?,
            boxed_value_bytes: boxed_value_bytes.ok_or_else(invalid)?,
            shared_value_bytes: shared_value_bytes.ok_or_else(invalid)?,
            shared_backing_views: shared_backing_views.ok_or_else(invalid)?,
            tree_containers: tree_containers.ok_or_else(invalid)?,
            tree_entries: tree_entries.ok_or_else(invalid)?,
            maximum_tree_key_value_bytes: maximum_tree_key_value_bytes.ok_or_else(invalid)?,
            maximum_tree_entry_alignment: maximum_tree_entry_alignment.ok_or_else(invalid)?,
            maximum_shared_value_alignment: maximum_shared_value_alignment.ok_or_else(invalid)?,
            observed_nodes: observed_nodes.ok_or_else(invalid)?,
            capacity_records: capacity_records.ok_or_else(invalid)?,
        })))
    }
}

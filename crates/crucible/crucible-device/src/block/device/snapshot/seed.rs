//! Borrowed admission for the concrete BlockWire checkpoint wire.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::*;
use crate::snapshot_codec::seed::{BoundedVecSeed, PairSeed, TableAdmission, ValueSeed};

fn pages_seed<'a, 'callback>(
    admission: &'a TableAdmission<'callback>,
) -> impl for<'de> DeserializeSeed<'de, Value = SnapshotPages> + Clone + 'a {
    BoundedVecSeed::<_, MAX_BLOCK_SNAPSHOT_PAGES>::new(
        PairSeed(
            ValueSeed::<u64>::new(),
            BoundedVecSeed::<_, { PAGE_SIZE as u64 }>::new(ValueSeed::<u8>::new(), admission),
        ),
        admission,
    )
}

#[derive(Clone, Copy)]
pub(crate) struct BlockWireSeed<'a, 'callback> {
    pub(crate) admission: &'a TableAdmission<'callback>,
}

impl<'de> DeserializeSeed<'de> for BlockWireSeed<'_, '_> {
    type Value = BlockSnapshotWire;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_struct("BlockSnapshotWire", FIELDS, self)
    }
}

const FIELDS: &[&str] = &[
    "core",
    "base_hash",
    "device_length",
    "overlay_delta",
    "full_pages",
    "dirty",
    "storage_faults",
    "latency",
];

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum Field {
    Core,
    BaseHash,
    DeviceLength,
    OverlayDelta,
    FullPages,
    Dirty,
    StorageFaults,
    Latency,
}

impl<'de> Visitor<'de> for BlockWireSeed<'_, '_> {
    type Value = BlockSnapshotWire;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the complete BlockWire checkpoint fields")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut core = None;
        let mut base_hash = None;
        let mut device_length = None;
        let mut overlay_delta = None;
        let mut full_pages = None;
        let mut dirty = None;
        let mut storage_faults = None;
        let mut latency = None;

        while let Some(field) = map.next_key::<Field>()? {
            match field {
                Field::Core => {
                    if core.is_some() {
                        return Err(serde::de::Error::duplicate_field("core"));
                    }
                    core = Some(map.next_value_seed(BoundedVecSeed::<
                        _,
                        MAX_BLOCK_SNAPSHOT_BYTES,
                    >::new(
                        ValueSeed::<u8>::new(), self.admission
                    ))?);
                }
                Field::BaseHash => {
                    if base_hash.is_some() {
                        return Err(serde::de::Error::duplicate_field("base_hash"));
                    }
                    base_hash = Some(map.next_value_seed(ValueSeed::<[u8; 32]>::new())?);
                }
                Field::DeviceLength => {
                    if device_length.is_some() {
                        return Err(serde::de::Error::duplicate_field("device_length"));
                    }
                    device_length = Some(map.next_value_seed(ValueSeed::<u64>::new())?);
                }
                Field::OverlayDelta => {
                    if overlay_delta.is_some() {
                        return Err(serde::de::Error::duplicate_field("overlay_delta"));
                    }
                    overlay_delta = Some(map.next_value_seed(pages_seed(self.admission))?);
                }
                Field::FullPages => {
                    if full_pages.is_some() {
                        return Err(serde::de::Error::duplicate_field("full_pages"));
                    }
                    full_pages = Some(map.next_value_seed(pages_seed(self.admission))?);
                }
                Field::Dirty => {
                    if dirty.is_some() {
                        return Err(serde::de::Error::duplicate_field("dirty"));
                    }
                    dirty = Some(map.next_value_seed(BoundedVecSeed::<
                        _,
                        MAX_BLOCK_SNAPSHOT_PAGES,
                    >::new(
                        ValueSeed::<u64>::new(), self.admission
                    ))?);
                }
                Field::StorageFaults => {
                    if storage_faults.is_some() {
                        return Err(serde::de::Error::duplicate_field("storage_faults"));
                    }
                    storage_faults = Some(map.next_value_seed(BoundedVecSeed::<
                        _,
                        MAX_BLOCK_SNAPSHOT_BYTES,
                    >::new(
                        ValueSeed::<u8>::new(),
                        self.admission,
                    ))?);
                }
                Field::Latency => {
                    if latency.is_some() {
                        return Err(serde::de::Error::duplicate_field("latency"));
                    }
                    latency = Some(map.next_value_seed(ValueSeed::<[u64; 5]>::new())?);
                }
            }
        }

        Ok(BlockSnapshotWire {
            core: core.ok_or_else(|| serde::de::Error::missing_field("core"))?,
            base_hash: base_hash.ok_or_else(|| serde::de::Error::missing_field("base_hash"))?,
            device_length: device_length
                .ok_or_else(|| serde::de::Error::missing_field("device_length"))?,
            overlay_delta: overlay_delta
                .ok_or_else(|| serde::de::Error::missing_field("overlay_delta"))?,
            full_pages: full_pages.ok_or_else(|| serde::de::Error::missing_field("full_pages"))?,
            dirty: dirty.ok_or_else(|| serde::de::Error::missing_field("dirty"))?,
            storage_faults: storage_faults
                .ok_or_else(|| serde::de::Error::missing_field("storage_faults"))?,
            latency: latency.ok_or_else(|| serde::de::Error::missing_field("latency"))?,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let core = sequence
            .next_element_seed(BoundedVecSeed::<_, MAX_BLOCK_SNAPSHOT_BYTES>::new(
                ValueSeed::<u8>::new(),
                self.admission,
            ))?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        let base_hash = sequence
            .next_element_seed(ValueSeed::<[u8; 32]>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
        let device_length = sequence
            .next_element_seed(ValueSeed::<u64>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
        let overlay_delta = sequence
            .next_element_seed(pages_seed(self.admission))?
            .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
        let full_pages = sequence
            .next_element_seed(pages_seed(self.admission))?
            .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
        let dirty = sequence
            .next_element_seed(BoundedVecSeed::<_, MAX_BLOCK_SNAPSHOT_PAGES>::new(
                ValueSeed::<u64>::new(),
                self.admission,
            ))?
            .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
        let storage_faults = sequence
            .next_element_seed(BoundedVecSeed::<_, MAX_BLOCK_SNAPSHOT_BYTES>::new(
                ValueSeed::<u8>::new(),
                self.admission,
            ))?
            .ok_or_else(|| serde::de::Error::invalid_length(6, &self))?;
        let latency = sequence
            .next_element_seed(ValueSeed::<[u64; 5]>::new())?
            .ok_or_else(|| serde::de::Error::invalid_length(7, &self))?;
        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::invalid_length(FIELDS.len() + 1, &self));
        }

        Ok(BlockSnapshotWire {
            core,
            base_hash,
            device_length,
            overlay_delta,
            full_pages,
            dirty,
            storage_faults,
            latency,
        })
    }
}

#[cfg(test)]
#[path = "seed/tests.rs"]
mod tests;

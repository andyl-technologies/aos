//! Saved-original parsing and allocation admission for device continuations.
//!
//! The host codec captures its account once before parsing. Tables, retained
//! collections, nested fault validation scratch and counted canonical output
//! receive that same borrowed account through explicit seeds and callbacks.
//! Changing the ambient scope cannot replace these supplied purposes. This
//! component does not certify all parser internals, diagnostics, control tails
//! or an enclosing decoded-owner lifetime.

use serde::de::DeserializeSeed;
use serde::{Deserialize, Deserializer};

use crucible::owned_decode::{DecodeBudget, from_cbor_slice_with_seed};

use super::*;

struct ValueSeed<T>(std::marker::PhantomData<T>);

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for ValueSeed<T> {
    type Value = T;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<T, D::Error> {
        T::deserialize(decoder)
    }
}

pub(super) fn decode_outer(
    payload: &[u8],
    original: Option<&DecodeBudget>,
) -> Result<HostIoWire, ciborium::de::Error<std::io::Error>> {
    match original {
        Some(original) => {
            from_cbor_slice_with_seed(payload, ValueSeed(std::marker::PhantomData), original)
        }
        None => ciborium::de::from_reader(payload),
    }
}

pub(super) fn decode_block_device(
    bytes: &[u8],
    maximum: u64,
    original: Option<&DecodeBudget>,
) -> Result<BlockSnapshot, BlockSnapshotCodecError> {
    let Some(original) = original else {
        return BlockSnapshot::from_canonical_bytes_with_limit(bytes, maximum);
    };
    let mut admit_table = |bytes| {
        original
            .charge_bytes(bytes)
            .map_err(|_| "original device snapshot table refused")
    };

    BlockSnapshot::from_canonical_bytes_with_wire_decoder(
        bytes,
        maximum,
        &mut admit_table,
        &mut |allocation| admit_collection(original, allocation),
        |payload, seed| from_cbor_slice_with_seed(payload, seed, original),
        |bytes, device_length, maximum, _, admit_validation| {
            decode_block_fault(bytes, device_length, maximum, original, admit_validation)
        },
    )
}

fn decode_block_fault(
    bytes: &[u8],
    device_length: u64,
    maximum: u64,
    original: &DecodeBudget,
    admit_validation: &mut dyn FnMut(
        crucible_device::DeviceSnapshotAllocation,
    ) -> Result<(), &'static str>,
) -> Result<
    crucible_device::block::BlockFaultState,
    crucible_device::block::BlockFaultStateCodecError,
> {
    crucible_device::block::BlockFaultState::from_canonical_bytes_with_decoder(
        bytes,
        device_length,
        maximum,
        &mut |bytes| {
            original
                .charge_bytes(bytes)
                .map_err(|_| "original fault validation output refused")
        },
        admit_validation,
        |payload| from_cbor_slice_with_seed(payload, ValueSeed(std::marker::PhantomData), original),
    )
}

pub(super) fn decode_ninep_device(
    bytes: &[u8],
    maximum: u64,
    original: Option<&DecodeBudget>,
) -> Result<NinepSnapshot, NinepSnapshotCodecError> {
    let Some(original) = original else {
        return NinepSnapshot::from_canonical_bytes_with_limit(bytes, maximum);
    };
    let mut admit_table = |bytes| {
        original
            .charge_bytes(bytes)
            .map_err(|_| "original device snapshot table refused")
    };

    NinepSnapshot::from_canonical_bytes_with_wire_decoder(
        bytes,
        maximum,
        &mut admit_table,
        &mut |allocation| admit_collection(original, allocation),
        |payload, seed| from_cbor_slice_with_seed(payload, seed, original),
    )
}

fn admit_collection(
    original: &DecodeBudget,
    allocation: crucible_device::DeviceSnapshotAllocation,
) -> Result<(), &'static str> {
    use crucible_device::DeviceSnapshotAllocation;
    use crucible_device::ninep::server::FidEntry;
    use crucible_device::ninep::{
        NinepRequestIdentity, NinepVirtualFid, ResolvedNinepRequestDirective,
    };

    let result = match allocation {
        DeviceSnapshotAllocation::ValidationFlags { entries } => {
            if entries == 0 {
                original.check()
            } else {
                original.charge_array::<bool>(entries)
            }
        }
        DeviceSnapshotAllocation::ValidationSequences { entries } => {
            original.charge_btree_entries::<u64, ()>(entries)
        }
        DeviceSnapshotAllocation::ValidationJobs { entries } => {
            original.charge_btree_entries::<([u8; 32], u64), ()>(entries)
        }
        DeviceSnapshotAllocation::ValidationJobArray { entries } => {
            if entries == 0 {
                original.check()
            } else {
                original.charge_array::<([u8; 32], u64)>(entries)
            }
        }
        DeviceSnapshotAllocation::ValidationContributor => {
            original.charge_btree_entry::<[u8; 32], ()>()
        }
        DeviceSnapshotAllocation::ValidationOperation => original.charge_btree_entry::<u8, ()>(),
        DeviceSnapshotAllocation::BlockPage => {
            original.charge_btree_entry::<u64, [u8; crucible_device::PAGE_SIZE]>()
        }
        DeviceSnapshotAllocation::BlockDirtyPage => original.charge_btree_entry::<u64, ()>(),
        DeviceSnapshotAllocation::NinepDirective => {
            original.charge_btree_entry::<NinepRequestIdentity, ResolvedNinepRequestDirective>()
        }
        DeviceSnapshotAllocation::NinepVirtualFid => {
            original.charge_btree_entry::<u32, NinepVirtualFid>()
        }
        DeviceSnapshotAllocation::NinepFidTable { entries } => {
            original.charge_array::<(u32, FidEntry)>(entries)
        }
    };
    result.map_err(|_| "original device snapshot collection refused")
}

pub(super) fn verify_final(
    original: Option<&DecodeBudget>,
) -> Result<(), QemuHostIoCheckpointCodecError> {
    if let Some(original) = original
        && let Err(error) = original.verify_live()
    {
        original.record_failure(error);
        return Err(QemuHostIoCheckpointCodecError::Nested);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

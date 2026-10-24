//! Selects independent native metadata banks without granting capture authority.
//!
//! The private source binds these limits before original banks and Child birth.
//! A later current-source quote walks actual retained fields and must fit both
//! physical banks. Source/whole-world admission remains an independent gate.

use crate::ProviderError;
use crucible_node_format::U64;
use serde::{Deserialize, Serialize};

impl crate::retained_metadata::ObserveMetadata for PacketNative5ProtocolMetadataLimits {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            native_before_rows,
            native_after_rows,
        } = self;
        observer.observe(native_before_rows)?;
        observer.observe(native_after_rows)
    }
}

/// Reports the actual independently allocated banks for one native cut.
///
/// These are data facts. The original endpoint must separately authenticate the
/// selected policy and compare them with its same retained physical banks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5ProtocolMetadataBankFacts {
    /// States the source-selected population bound for each bank.
    pub selected_rows: U64,
    /// Reports actual record vector capacity, including spare rows.
    pub record_capacity: U64,
    /// Reports actual record capacity times the typed record layout.
    pub record_bytes: U64,
    /// Reports actual encoded alias vector capacity.
    pub alias_row_capacity: U64,
    /// Reports actual private alias lookup vector capacity.
    pub alias_lookup_capacity: U64,
    /// Reports actual alias row backing bytes.
    pub alias_row_bytes: U64,
    /// Reports actual private alias lookup backing bytes.
    pub alias_lookup_bytes: U64,
}

/// Reports both original native cut reservations before any realization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5ProtocolMetadataBirthFacts {
    /// Reports the independently retained native-before reservation.
    pub before: PacketNative5ProtocolMetadataBankFacts,
    /// Reports the independently retained native-after reservation.
    pub after: PacketNative5ProtocolMetadataBankFacts,
}

impl PacketNative5ProtocolMetadataBirthFacts {
    /// Checks selected rows and all typed backing extent arithmetic.
    ///
    /// # Errors
    /// Refuses invalid selections, insufficient capacities, overflow or a byte
    /// extent inconsistent with the actual compiled record and alias layouts.
    pub fn validate_data(
        &self,
        limits: &PacketNative5ProtocolMetadataLimits,
    ) -> Result<(), ProviderError> {
        limits.validate_data()?;
        self.before.validate_rows(limits.native_before_rows)?;
        self.after.validate_rows(limits.native_after_rows)
    }
}

impl PacketNative5ProtocolMetadataBankFacts {
    fn validate_rows(&self, selected: U64) -> Result<(), ProviderError> {
        use crate::retained_metadata::records::MetadataCapacityRecord;

        let (alias_row_layout, alias_lookup_layout) =
            crate::retained_metadata::aliases::original_metadata_alias_layouts();
        if self.selected_rows != selected {
            return Err(ProviderError::Correlation(
                "native metadata born selection differs",
            ));
        }
        let banks = [
            (
                self.record_capacity,
                self.record_bytes,
                std::mem::size_of::<MetadataCapacityRecord>(),
            ),
            (
                self.alias_row_capacity,
                self.alias_row_bytes,
                alias_row_layout,
            ),
            (
                self.alias_lookup_capacity,
                self.alias_lookup_bytes,
                alias_lookup_layout,
            ),
        ];
        for (capacity, bytes, layout) in banks {
            let layout = u64::try_from(layout)
                .map_err(|_| ProviderError::ResourceExhausted("native metadata bank layout"))?;
            if capacity.get() < selected.get()
                || capacity.get().checked_mul(layout) != Some(bytes.get())
            {
                return Err(ProviderError::Correlation(
                    "native metadata born backing differs",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn from_original_reservation(
        reservation: &crate::protocol_snapshot::ProtocolSnapshotReservation,
    ) -> Result<Self, ProviderError> {
        let record = reservation
            .original_metadata_record_allocation_facts()?
            .ok_or(ProviderError::Correlation(
                "native metadata original record bank absent",
            ))?;
        let alias =
            reservation
                .original_alias_allocation_facts()?
                .ok_or(ProviderError::Correlation(
                    "native metadata original alias bank absent",
                ))?;
        if record.maximum_rows != alias.maximum_rows {
            return Err(ProviderError::Correlation(
                "native metadata original bank selections differ",
            ));
        }
        let convert = |value| {
            u64::try_from(value).map(U64::new).map_err(|_| {
                ProviderError::ResourceExhausted("native metadata original bank extent")
            })
        };
        let facts = Self {
            selected_rows: convert(record.maximum_rows)?,
            record_capacity: convert(record.capacity_rows)?,
            record_bytes: convert(record.allocated_bytes)?,
            alias_row_capacity: convert(alias.row_capacity)?,
            alias_lookup_capacity: convert(alias.lookup_capacity)?,
            alias_row_bytes: convert(alias.row_bytes)?,
            alias_lookup_bytes: convert(alias.lookup_bytes)?,
        };
        facts.validate_rows(facts.selected_rows)?;
        Ok(facts)
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketNative5ProtocolMetadataBankFacts {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            selected_rows,
            record_capacity,
            record_bytes,
            alias_row_capacity,
            alias_lookup_capacity,
            alias_row_bytes,
            alias_lookup_bytes,
        } = self;
        for value in [
            selected_rows,
            record_capacity,
            record_bytes,
            alias_row_capacity,
            alias_lookup_capacity,
            alias_row_bytes,
            alias_lookup_bytes,
        ] {
            observer.observe(value)?;
        }
        Ok(())
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketNative5ProtocolMetadataBirthFacts {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self { before, after } = self;
        observer.observe(before)?;
        observer.observe(after)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual independently allocated bank boundary controls"
)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::ProtocolSnapshotReservation;

    #[test]
    fn actual_independent_birth_banks_reject_crossed_rows_and_one_byte_facts() {
        let limits = PacketNative5ProtocolMetadataLimits {
            native_before_rows: U64::new(2),
            native_after_rows: U64::new(3),
        };
        let before = ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 2).unwrap();
        let after = ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 3).unwrap();
        let before_allocation = before.original_allocation_facts().unwrap();
        let after_allocation = after.original_allocation_facts().unwrap();

        let facts = PacketNative5ProtocolMetadataBirthFacts {
            before: PacketNative5ProtocolMetadataBankFacts::from_original_reservation(&before)
                .unwrap(),
            after: PacketNative5ProtocolMetadataBankFacts::from_original_reservation(&after)
                .unwrap(),
        };
        facts.validate_data(&limits).unwrap();
        let crossed = PacketNative5ProtocolMetadataBirthFacts {
            before: facts.after,
            after: facts.before,
        };
        assert!(crossed.validate_data(&limits).is_err());

        let mut short = facts;
        short.before.record_bytes = U64::new(short.before.record_bytes.get() - 1);
        assert!(short.validate_data(&limits).is_err());
        let mut extra = facts;
        extra.after.alias_lookup_bytes = U64::new(extra.after.alias_lookup_bytes.get() + 1);
        assert!(extra.validate_data(&limits).is_err());

        assert_eq!(
            before.original_allocation_facts().unwrap(),
            before_allocation
        );
        assert_eq!(after.original_allocation_facts().unwrap(), after_allocation);
        let encoded = serde_json::to_value(facts).unwrap();
        let roundtrip: PacketNative5ProtocolMetadataBirthFacts =
            serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(roundtrip, facts);
        let mut unknown = encoded;
        unknown["before"]["permission"] = serde_json::Value::Bool(true);
        assert!(
            serde_json::from_value::<PacketNative5ProtocolMetadataBirthFacts>(unknown).is_err()
        );
    }
}

pub use crucible_source_birth_data::profile::reference_packet::service::PacketNative5ProtocolMetadataLimits;

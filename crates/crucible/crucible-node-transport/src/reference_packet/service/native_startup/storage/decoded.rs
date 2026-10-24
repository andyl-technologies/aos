//! Shares the actual decoded-occurrence producer with the lower data algorithms.
//!
//! Original native callers and their independent controls retain their existing
//! paths. This alias supplies DATA only; Source/native admission remains upper.

use super::*;
use serde_json::Value;

pub(super) use crucible_source_birth_data::decoded_occurrences::{
    DecodedStorage, counter_scratch_data, quote,
};

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn native_value_backing_covers_empty_maps_dense_arrays_and_independent_clones() -> TestResult {
        for input in [
            b"{}".as_slice(),
            b"[]",
            br#"{"a":{},"b":[{},{},"x",1,2],"c":"\uD834\uDD1E"}"#,
        ] {
            let actual: Value = serde_json::from_slice(input)?;
            let independent = actual.clone();
            let mut observer = MetadataObserver::new();
            observer.observe(&actual)?;
            let backing = requested_metadata_backing_storage_data(&observer.finish())?;
            let mut cloned = MetadataObserver::new();
            cloned.observe(&independent)?;
            let clone_backing = requested_metadata_backing_storage_data(&cloned.finish())?;
            let row = quote(input, size_of::<Value>(), size_of::<Value>(), usize::MAX)?;
            assert!(row.value_backing >= backing);
            assert!(row.typed_backing >= clone_backing);
            let exact = row.total(usize::MAX)?;
            assert_eq!(
                quote(input, size_of::<Value>(), size_of::<Value>(), exact)?.total(exact)?,
                exact
            );
            assert!(quote(input, size_of::<Value>(), size_of::<Value>(), exact - 1).is_err());
        }
        Ok(())
    }

    #[test]
    fn actual_coordinator_backing_covers_the_retained_dto_without_validator_work() -> TestResult {
        use crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation;
        let (_, _, local, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let actual =
            PacketNative5CoordinatorInstallation::decode(original.bytes.as_slice(), &local)?;
        let facts = crate::retained_metadata::observe_retained_native_coordinator(&actual)?;
        let observed = requested_metadata_backing_storage_data(&facts)?;
        let backing = coordinator_decode::backing(original.bytes.as_slice(), usize::MAX)?;
        assert!(backing >= observed + size_of::<PacketNative5CoordinatorInstallation>());
        assert!(coordinator_decode::quote(original.bytes.as_slice(), usize::MAX)? > backing);
        assert!(quote(b"{}", usize::MAX, usize::MAX, usize::MAX).is_err());
        Ok(())
    }
}

#[cfg(test)]
#[path = "decoded/projected_tests.rs"]
mod projected_tests;

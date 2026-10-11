//! Cross-binding mode, range and old-canonical compatibility regressions.

use crate::direct_upload::{MAX_DIRECT_PART_BYTES, MIN_DIRECT_PART_BYTES};
use crate::storage_authority::{GuardIncarnation, StorageGuardStamp};

use super::super::{CopySourceObject, ExternalCopyOriginal, original_lookup::CopyOriginalSelector};
use super::*;

fn authority(value: u8) -> PhysicalStorageAuthorityId {
    PhysicalStorageAuthorityId::parse(format!("00000000-0000-4000-8000-{value:012}")).unwrap()
}

fn original(
    source_mode: CopyIncarnationMode,
    destination_mode: CopyIncarnationMode,
) -> ExternalCopyOriginal {
    let mut value = match source_mode {
        CopyIncarnationMode::ProviderVersion => super::super::tests::original(),
        CopyIncarnationMode::GuardedClosure => super::super::tests::protected_original(),
    };
    value.version = 3;
    value.source.binding_id = LeaseInteger::new(2).unwrap();
    value.source.prefix = value.destination.prefix.clone();
    value.transfer = Some(CopyTransferPins {
        source_binding: CopySourceBindingPin {
            binding_id: value.source.binding_id,
            binding_stable_id: "source-binding".into(),
            binding_resource_version: LeaseInteger::new(7).unwrap(),
            snapshot_revision: "e".repeat(64),
            profile_digest: "f".repeat(64),
            binding_read_revision: LeaseInteger::new(9).unwrap(),
            read_generation: value.read_generation,
            physical_authority_id: authority(1),
        },
        source_incarnation: source_mode,
        destination_incarnation: destination_mode,
        destination_physical_authority_id: authority(2),
        maximum_source_range_bytes: LeaseInteger::new(MIN_DIRECT_PART_BYTES as i64).unwrap(),
    });
    value
}

#[test]
fn source_and_destination_modes_are_independent() {
    for source_mode in [
        CopyIncarnationMode::ProviderVersion,
        CopyIncarnationMode::GuardedClosure,
    ] {
        for destination_mode in [
            CopyIncarnationMode::ProviderVersion,
            CopyIncarnationMode::GuardedClosure,
        ] {
            let value = original(source_mode, destination_mode);
            value.validate().unwrap();
            assert_eq!(value.source_incarnation().unwrap(), source_mode);
            assert_eq!(value.destination_incarnation().unwrap(), destination_mode);

            let mut destination = CopySourceObject {
                provider_version: (destination_mode == CopyIncarnationMode::ProviderVersion)
                    .then(|| "actual-destination-version".into()),
                etag: "\"destination-etag\"".into(),
                bytes: value.source_object.bytes,
                guard_stamp: (destination_mode == CopyIncarnationMode::GuardedClosure).then(|| {
                    StorageGuardStamp {
                        physical_authority_id: authority(2),
                        incarnation: GuardIncarnation::parse("12").unwrap(),
                    }
                }),
            };
            value.validate_destination(&destination).unwrap();

            if let Some(stamp) = &mut destination.guard_stamp {
                stamp.physical_authority_id = authority(1);
                assert!(value.validate_destination(&destination).is_err());
            } else {
                destination.provider_version = Some("null".into());
                assert!(value.validate_destination(&destination).is_err());
            }
        }
    }
}

#[test]
fn source_range_bound_is_not_destination_writer_geometry() {
    let value = original(
        CopyIncarnationMode::ProviderVersion,
        CopyIncarnationMode::GuardedClosure,
    );
    value.validate().unwrap();

    let mut insufficient = value.clone();
    insufficient
        .transfer
        .as_mut()
        .unwrap()
        .maximum_source_range_bytes = LeaseInteger::new(MIN_DIRECT_PART_BYTES as i64 - 1).unwrap();
    assert!(insufficient.validate().is_err());

    let mut excessive = value.clone();
    excessive
        .transfer
        .as_mut()
        .unwrap()
        .maximum_source_range_bytes = LeaseInteger::new(MAX_DIRECT_PART_BYTES as i64 + 1).unwrap();
    assert!(excessive.validate().is_err());

    let mut foreign = value.clone();
    foreign.transfer.as_mut().unwrap().source_binding.binding_id = value.binding_id;
    assert!(foreign.validate().is_err());
}

#[test]
fn retained_owner_refuses_changed_source_profile_without_new_copy_id() {
    let value = original(
        CopyIncarnationMode::GuardedClosure,
        CopyIncarnationMode::ProviderVersion,
    );
    let selector = CopyOriginalSelector::from_original(&value).unwrap();
    assert_eq!(selector.copy_id().unwrap(), value.copy_id().unwrap());
    assert_eq!(selector.transfer, value.transfer);

    let mut changed = value.clone();
    changed
        .transfer
        .as_mut()
        .unwrap()
        .source_binding
        .profile_digest = "a".repeat(64);
    assert_eq!(changed.copy_id().unwrap(), value.copy_id().unwrap());
    assert_ne!(changed.fingerprint().unwrap(), value.fingerprint().unwrap());
    assert_ne!(
        CopyOriginalSelector::from_original(&changed).unwrap(),
        selector
    );

    let mut wrong_authority = value.clone();
    wrong_authority
        .source_object
        .guard_stamp
        .as_mut()
        .unwrap()
        .physical_authority_id = authority(2);
    assert!(wrong_authority.validate().is_err());
}

#[test]
fn old_originals_omit_transfer_and_reject_new_pins() {
    for value in [
        super::super::tests::original(),
        super::super::tests::protected_original(),
    ] {
        let encoded = serde_json::to_vec(&value).unwrap();
        let object = serde_json::to_value(&value).unwrap();
        assert!(object.get("transfer").is_none());
        let decoded: ExternalCopyOriginal = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
        assert_eq!(decoded.fingerprint().unwrap(), value.fingerprint().unwrap());

        let mut invalid = value;
        invalid.transfer = original(
            CopyIncarnationMode::ProviderVersion,
            CopyIncarnationMode::ProviderVersion,
        )
        .transfer;
        assert!(invalid.validate().is_err());
    }

    let mut missing = original(
        CopyIncarnationMode::ProviderVersion,
        CopyIncarnationMode::ProviderVersion,
    );
    missing.transfer = None;
    assert!(missing.validate().is_err());
}

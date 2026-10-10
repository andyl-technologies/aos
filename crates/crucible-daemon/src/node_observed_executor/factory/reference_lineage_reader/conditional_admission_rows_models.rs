//! Exercises synthetic admission metadata; no process or source authority exists.

#![cfg(test)]

use crucible_node_contract::Bytes;
use crucible_node_provider::handshake::Limits;
use crucible_node_provider::reference_service::ReferenceServiceBootstrap;

use super::*;

fn fixture() -> Result<(ReferenceProfile, ContentRef, HashRef), InspectionError> {
    let profile = ReferenceProfile::build_public_lineage(
        Id::new("disk").map_err(InspectionError::from_error)?,
        Id::new("disk-owner").map_err(InspectionError::from_error)?,
        canonical::content_ref(b"synthetic provider", "application/octet-stream")
            .map_err(InspectionError::from_error)?,
        canonical::content_ref(b"synthetic device", "application/octet-stream")
            .map_err(InspectionError::from_error)?,
        U64::new(1000),
        U64::new(1_000_000_000),
        false,
    )
    .map_err(InspectionError::from_error)?;
    let qualification = canonical::content_ref(b"synthetic qualification", "text/plain")
        .map_err(InspectionError::from_error)?;
    let world = canonical::json_hash("cnp.world-binding.v1", &"synthetic original world")
        .map_err(InspectionError::from_error)?;
    Ok((profile, qualification, world))
}

#[test]
fn first_transition_matches_original_bootstrap() -> Result<(), InspectionError> {
    let (profile, qualification, world) = fixture()?;
    let expected = reconstruct(&profile, &qualification, &world)?;
    let bootstrap = ReferenceServiceBootstrap::fixture(
        &profile,
        graph::initial_authority(&profile.descriptor.id, &qualification),
        Bytes::new(vec![7; 32]),
        U64::new(0),
        Limits {
            frame_bytes: U64::new(1_048_576),
            nesting: U64::new(64),
            requests: U64::new(32),
            journal_entries: U64::new(4096),
            blob_chunk_bytes: U64::new(16_384),
        },
        expected.first.record.resource_limits.clone(),
        world,
    )
    .map_err(InspectionError::from_error)?;

    assert_eq!(bootstrap.installed_content.len(), 2);
    assert_eq!(
        bootstrap.installed_content[0].bytes.as_slice(),
        bounded_encode(&expected.first.record)?
    );
    assert_eq!(
        bootstrap.installed_content[1].bytes.as_slice(),
        bounded_encode(&expected.first.receipt)?
    );
    assert_eq!(
        bootstrap.authority.host_receipt,
        receipt_ref(&expected.first.receipt)?
    );
    Ok(())
}

#[test]
fn final_binding_cannot_replace_either_original_transition() -> Result<(), InspectionError> {
    let (profile, qualification, world) = fixture()?;
    let expected = reconstruct(&profile, &qualification, &world)?;
    let final_hash = expected
        .final_binding
        .identity()
        .map_err(InspectionError::from_error)?;

    assert!(expected.first.record.qualification_refs.is_empty());
    assert_eq!(
        expected.qualified.record.qualification_refs,
        [qualification]
    );
    assert_ne!(
        expected.first.record.binding_hashes[0],
        expected.qualified.record.binding_hashes[0]
    );
    assert_ne!(expected.first.record.binding_hashes[0], final_hash);
    // Binding identity excludes live host receipts; the full authority still
    // must retain the independently generated second transition receipt.
    assert_eq!(expected.qualified.record.binding_hashes[0], final_hash);
    assert_eq!(
        expected.final_binding.authority.host_receipt,
        receipt_ref(&expected.qualified.receipt)?
    );
    assert_ne!(
        expected.final_binding.authority.host_receipt,
        receipt_ref(&expected.first.receipt)?
    );
    assert_ne!(
        receipt_ref(&expected.first.receipt)?,
        receipt_ref(&expected.qualified.receipt)?
    );
    Ok(())
}

#[test]
fn foreign_world_changes_both_original_record_commitments() -> Result<(), InspectionError> {
    let (profile, qualification, world) = fixture()?;
    let actual = reconstruct(&profile, &qualification, &world)?;
    let foreign = canonical::json_hash("cnp.world-binding.v1", &"foreign world")
        .map_err(InspectionError::from_error)?;
    let changed = reconstruct(&profile, &qualification, &foreign)?;

    assert_ne!(
        actual.first.receipt.record_ref,
        changed.first.receipt.record_ref
    );
    assert_ne!(
        actual.qualified.receipt.record_ref,
        changed.qualified.receipt.record_ref
    );
    assert_ne!(
        actual.final_binding.authority.host_receipt,
        changed.final_binding.authority.host_receipt
    );
    Ok(())
}

#[test]
fn borrowed_metadata_credit_refuses_before_canonical_body_allocation() {
    let excess = "x".repeat(MAXIMUM_RECORD_BYTES);
    assert!(metadata_credit(&excess).is_err());
}

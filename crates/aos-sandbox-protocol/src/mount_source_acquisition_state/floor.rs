//! Canonical SourceProvider verification-floor projections for AOSMSA02.
//!
//! These conversions retain the exact pre-I/O catalog and selection floors.
//! They are pure data transformations and do not grant current trust or
//! provider-request authority.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ProviderCatalogFloorV1, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1, SourceResourceV1,
    SourceSelectionFloorV1,
};

use super::model::{
    AcquireVerificationFloorV2, ProviderCatalogFloorSnapshotV2, SelectionFloorSnapshotV2,
};
use super::{Result, format::state_error};

/// Projects exact protocol floors into their canonical durable representation.
#[must_use]
pub fn acquire_verification_floor_v2(
    catalog: &ProviderCatalogFloorV1,
    selection: Option<&SourceSelectionFloorV1>,
    current_catalog_head_commitment: Option<[u8; 32]>,
) -> AcquireVerificationFloorV2 {
    let selection_snapshot = selection.map(selection_floor_snapshot_v2);
    AcquireVerificationFloorV2 {
        catalog: ProviderCatalogFloorSnapshotV2 {
            provider_authority_id: catalog.provider_authority_id(),
            resource_namespace_digest: *catalog.resource_namespace_digest().as_bytes(),
            minimum_catalog_generation: catalog.minimum_catalog_generation(),
            minimum_catalog_digest: *catalog.minimum_catalog_digest().as_bytes(),
            digest: *catalog.digest().as_bytes(),
        },
        current_catalog_head_commitment,
        selection: selection_snapshot,
        selection_digest: selection.map(|floor| *floor.digest().as_bytes()),
    }
}

/// Reconstructs and self-validates exact protocol floors from durable data.
///
/// # Errors
///
/// Returns an error if any scalar, digest, signer, resource, or optional-field
/// relation is invalid.
pub fn protocol_acquire_verification_floor_v2(
    value: &AcquireVerificationFloorV2,
) -> Result<(ProviderCatalogFloorV1, Option<SourceSelectionFloorV1>)> {
    if value.current_catalog_head_commitment.is_none()
        || value.current_catalog_head_commitment == Some([0; 32])
    {
        return Err(state_error(
            "AOSMSA02 Acquire floor lacks its authenticated current catalog head",
        ));
    }
    let catalog = ProviderCatalogFloorV1::new(
        value.catalog.provider_authority_id,
        ObjectDigest::from_bytes(value.catalog.resource_namespace_digest),
        value.catalog.minimum_catalog_generation,
        ObjectDigest::from_bytes(value.catalog.minimum_catalog_digest),
    )
    .map_err(|_| state_error("AOSMSA02 provider catalog floor is invalid"))?;
    if catalog.digest().as_bytes() != &value.catalog.digest {
        return Err(state_error(
            "AOSMSA02 provider catalog floor digest differs",
        ));
    }

    let selection = match (&value.selection, value.selection_digest) {
        (None, None) => None,
        (Some(snapshot), Some(expected_digest)) => {
            let floor = protocol_selection_floor_v2(snapshot)?;
            if floor.digest().as_bytes() != &expected_digest {
                return Err(state_error("AOSMSA02 selection floor digest differs"));
            }
            Some(floor)
        }
        _ => return Err(state_error("AOSMSA02 selection floor presence is partial")),
    };
    Ok((catalog, selection))
}

/// Projects one exact acquisition selection floor into AOSMSA02.
#[must_use]
pub fn selection_floor_snapshot_v2(value: &SourceSelectionFloorV1) -> SelectionFloorSnapshotV2 {
    let resource = value.resource();
    let signer = value.outcome_signer();
    SelectionFloorSnapshotV2 {
        acquisition_id: *value.acquisition_id().as_bytes(),
        provider_authority_id: value.provider_authority_id(),
        route_id: value.route_id(),
        resource_namespace_digest: *resource.resource_namespace_digest().as_bytes(),
        catalog_generation: resource.catalog_generation(),
        catalog_digest: *resource.catalog_digest().as_bytes(),
        resource_id: resource.resource_id(),
        resource_generation: resource.resource_generation(),
        resource_digest: *resource.resource_digest().as_bytes(),
        selection_generation: resource.selection_generation(),
        selection_digest: *resource.selection_digest().as_bytes(),
        outcome_signer_authority_id: signer.authority_id(),
        outcome_signer_authority_generation: signer.authority_generation(),
        outcome_signer_authority_digest: *signer.authority_digest().as_bytes(),
        outcome_signer_key_id: signer.key_id(),
        outcome_signer_key_generation: signer.key_generation(),
        outcome_signer_public_key_digest: *signer.public_key_digest().as_bytes(),
        lease_id: value.lease_id(),
        signed_lease_digest: *value.signed_lease_digest().as_bytes(),
        proof_class: value.proof_class(),
        proof_digest: *value.proof_digest().as_bytes(),
        resource_commitment: *value.resource_commitment().as_bytes(),
        trust_generation: value.trust_generation(),
        trust_digest: *value.trust_digest().as_bytes(),
        revocation_generation: value.revocation_generation(),
        revocation_digest: *value.revocation_digest().as_bytes(),
    }
}

/// Reconstructs one exact protocol selection floor from AOSMSA02.
///
/// # Errors
///
/// Returns an error for any invalid resource, signer, or floor field.
pub fn protocol_selection_floor_v2(
    value: &SelectionFloorSnapshotV2,
) -> Result<SourceSelectionFloorV1> {
    let resource = SourceResourceV1::new(
        ObjectDigest::from_bytes(value.resource_namespace_digest),
        value.resource_id,
        value.resource_generation,
        ObjectDigest::from_bytes(value.resource_digest),
        value.catalog_generation,
        ObjectDigest::from_bytes(value.catalog_digest),
        value.selection_generation,
        ObjectDigest::from_bytes(value.selection_digest),
    )
    .map_err(|_| state_error("AOSMSA02 selection-floor resource is invalid"))?;
    let signer = SourceProviderSigningKeyV1::new(
        value.outcome_signer_authority_id,
        value.outcome_signer_authority_generation,
        ObjectDigest::from_bytes(value.outcome_signer_authority_digest),
        value.outcome_signer_key_id,
        value.outcome_signer_key_generation,
        ObjectDigest::from_bytes(value.outcome_signer_public_key_digest),
        SourceProviderKeyUsageV1::ProviderOutcome,
    )
    .map_err(|_| state_error("AOSMSA02 selection-floor signer is invalid"))?;
    SourceSelectionFloorV1::new(
        ObjectDigest::from_bytes(value.acquisition_id),
        value.provider_authority_id,
        value.route_id,
        resource,
        signer,
        value.lease_id,
        ObjectDigest::from_bytes(value.signed_lease_digest),
        value.proof_class,
        ObjectDigest::from_bytes(value.proof_digest),
        ObjectDigest::from_bytes(value.resource_commitment),
        value.trust_generation,
        ObjectDigest::from_bytes(value.trust_digest),
        value.revocation_generation,
        ObjectDigest::from_bytes(value.revocation_digest),
    )
    .map_err(|_| state_error("AOSMSA02 selection floor is invalid"))
}

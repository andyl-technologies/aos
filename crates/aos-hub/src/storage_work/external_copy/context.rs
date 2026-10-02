//! Hash projections of the exact Copy state already checked by Native.
//!
//! Private claim tokens and provider coordinates are hashed, never logged.
//! Independent SQL/API observations and installed purpose/provider evidence
//! must still match these source-bound receipts before workload accounting.

use std::collections::BTreeMap;

use super::{CopyClaim, CurrentCopy, SurfaceObjectRecord};
use crate::storage_work::telemetry::context::{fact_digest, ControlObservation};

pub(super) fn after_sql(
    observation: Option<ControlObservation>,
    current: &CurrentCopy,
    claim: Option<&CopyClaim>,
    catalogue: Option<&SurfaceObjectRecord>,
    profile_digest: &str,
    snapshot_revision: &str,
) {
    let Some(observation) = observation else {
        return;
    };
    let Some(commitments) =
        commitments(current, claim, catalogue, profile_digest, snapshot_revision)
    else {
        return;
    };
    observation.after_sql("external_copy_current_sql", commitments);
}

fn commitments(
    current: &CurrentCopy,
    claim: Option<&CopyClaim>,
    catalogue: Option<&SurfaceObjectRecord>,
    profile_digest: &str,
    snapshot_revision: &str,
) -> Option<BTreeMap<&'static str, String>> {
    let binding = &current.binding;
    let revision = &current.revision;
    let grant = &current.grant;
    let binding_fact = serde_json::json!([
        binding.id,
        binding.org_id,
        binding.stable_id,
        binding.owner_scope_key,
        binding.kind,
        binding.is_instance_default,
        binding.local_root_path,
        binding.object_bucket,
        binding.object_prefix,
        binding.endpoint_scheme,
        binding.endpoint_host_kind,
        binding.endpoint_host_bytes,
        binding.endpoint_port,
        binding.signing_region,
        binding.access_mode,
        binding.resource_version,
    ]);
    let revision_fact = (
        revision.binding_id,
        revision.revision,
        &revision.write_credential_purpose,
        revision.write_credential_generation,
        &revision.write_credential_version_ref,
        revision.writes_supported,
        revision.conditional_writes_supported,
        &revision.revision_fingerprint,
        &revision.capability_fingerprint,
        revision.created_at,
    );
    let grant_fact = (
        &grant.resource_kind,
        &grant.resource_stable_id,
        grant.resource_generation,
        &grant.consumer_scope_key,
        grant.grant_generation,
        &grant.grant_kind,
        &grant.state,
        &grant.granted_by,
        grant.granted_at,
        &grant.revoked_by,
        grant.revoked_at,
        grant.resource_version,
    );
    let catalogue_fact = catalogue.map(|object| {
        (
            object.id,
            object.registry_id,
            object.cache_id,
            &object.object_key,
            &object.content_hash,
            object.size,
            &object.object_kind,
            &object.mutable_publication_id,
            &object.lifecycle_state,
            object.tombstoned_at,
            object.created_at,
            object.updated_at,
            object.resource_version,
        )
    });
    Some(BTreeMap::from([
        ("topologySha256", fact_digest(&current.topology)?),
        ("sourcePlacementSha256", fact_digest(&current.source)?),
        (
            "destinationPlacementSha256",
            fact_digest(&current.destination)?,
        ),
        ("bindingStateSha256", fact_digest(&binding_fact)?),
        ("writeRevisionStateSha256", fact_digest(&revision_fact)?),
        ("consumerGrantStateSha256", fact_digest(&grant_fact)?),
        ("claimSha256", fact_digest(&claim)?),
        ("catalogueStateSha256", fact_digest(&catalogue_fact)?),
        ("profileDigest", profile_digest.into()),
        ("snapshotRevision", snapshot_revision.into()),
    ]))
}

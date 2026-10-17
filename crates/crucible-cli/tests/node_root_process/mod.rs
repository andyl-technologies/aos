//! Checks original archived octets separately from genuine fresh target owner scope.
//!
//! These fixture records read actual durable publisher roots. They are data-only
//! oracles and cannot mint activation, readiness or native continuation authority.

use std::{
    fs,
    io::{BufReader, Read},
    path::Path,
};

use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_core::node_contract::{OperationOutcome, OwnerIdentity, SavedRuntimeActivation};
use crucible_node_contract::{Bytes, ContentRef, Id, Position, PreparedOwner, Validate, canonical};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Readiness {
    owners: Vec<OwnerIdentity>,
    boundary: Position,
    state_inventory: ContentRef,
    ready_receipt: ContentRef,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodePreparation {
    node: Id,
    readiness: Readiness,
    prepared_owners: Vec<PreparedOwner>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    format: String,
    version: u16,
    activation: SavedRuntimeActivation,
    node_preparations: Vec<NodePreparation>,
    prepared_owners: Vec<PreparedOwner>,
    coordinator_state_ref: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoredCoordinator {
    schema: String,
    source_activation: SavedRuntimeActivation,
    target_activation: SavedRuntimeActivation,
    source_archive: ContentRef,
    source_coordinator_ref: ContentRef,
    source_coordinator_bytes: Vec<u8>,
    actual_fresh_preparations: Vec<NodePreparation>,
}

/// Retains original published preparation and signed capture coordinator octets.
pub(super) struct PublishedSource {
    publication: Publication,
    coordinator_reference: ContentRef,
    coordinator_bytes: Vec<u8>,
    capture_cut: Position,
}

impl PublishedSource {
    /// Reads actual completed source publication and authenticated archive bodies.
    pub(super) fn read(directory: &Path, execution: &str, archive: &ContentRef) -> Self {
        let publication = read_publication(directory, execution);
        validate_preparations(&publication).unwrap();
        let archive_directory = directory.join("root-operator-archive");
        let manifest_bytes = read_archive_object(&archive_directory, archive);
        let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
        let coordinator_reference: ContentRef =
            serde_json::from_value(manifest["coordinator_state_ref"].clone()).unwrap();
        let coordinator_bytes = read_archive_object(&archive_directory, &coordinator_reference);
        let coordinator: Value = serde_json::from_slice(&coordinator_bytes).unwrap();
        let source_activation: SavedRuntimeActivation =
            serde_json::from_value(coordinator["runtime"]["source_activation"].clone()).unwrap();
        assert_eq!(source_activation, publication.activation);
        let capture_cut: Position = serde_json::from_value(manifest["cut"].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(capture_cut).unwrap(),
            coordinator["runtime"]["capture_cut"]
        );

        Self {
            publication,
            coordinator_reference,
            coordinator_bytes,
            capture_cut,
        }
    }
}

fn durable_bytes(directory: &Path, namespace: &str, execution: &str) -> Vec<u8> {
    let refs = DirectoryRefBackend::new(directory.join("refs"));
    let blobs = DirectoryBlobBackend::new("node-observations", directory.join("blobs"));
    let name = RefName::new(format!("{namespace}/root-operator-{execution}")).unwrap();
    let identity = refs.read_ref(&name).unwrap().unwrap();
    // The backend authenticates the actual immutable ContentId, rather than
    // deriving target scope from the output under comparison.
    blobs
        .read(identity, None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap()
}

fn read_publication(directory: &Path, execution: &str) -> Publication {
    serde_json::from_slice(&durable_bytes(
        directory,
        "node-world-activations",
        execution,
    ))
    .unwrap()
}

fn read_archive_object(directory: &Path, reference: &ContentRef) -> Vec<u8> {
    assert!(reference.length.get() <= 16 * 1024 * 1024);
    let bytes =
        fs::read(directory.join(format!("{}.native-object-v1", reference.hash.digest))).unwrap();
    reference.verify(&bytes).unwrap();
    bytes
}

fn validate_preparations(publication: &Publication) -> Result<(), &'static str> {
    if publication.format != "crucible.node-world-activation"
        || publication.version != 2
        || publication.activation.owners.len() != 2
        || publication.node_preparations.len() != 2
        || publication.prepared_owners.len() != 2
    {
        return Err("incomplete fixed public Root world");
    }
    let mut flattened = Vec::new();
    for (index, (node, owner)) in [("clock", "owner/clock"), ("root", "owner/root")]
        .into_iter()
        .enumerate()
    {
        let preparation = &publication.node_preparations[index];
        let identity = &publication.activation.owners[index];
        if preparation.node.as_str() != node
            || identity.owner.as_str() != owner
            || identity.generation != publication.activation.generation
            || preparation.readiness.owners != [identity.clone()]
            || preparation.readiness.boundary != publication.activation.boundary
            || preparation.prepared_owners.len() != 1
        {
            return Err("partial or swapped actual public owner mapping");
        }
        preparation
            .readiness
            .state_inventory
            .validate()
            .map_err(|_| "invalid state inventory")?;
        let prepared = &preparation.prepared_owners[0];
        prepared
            .validate()
            .map_err(|_| "invalid original PreparedOwner")?;
        if prepared.owner_id != identity.owner
            || prepared.incarnation_id != identity.incarnation
            || prepared.owner_generation != identity.generation
            || prepared.ready_receipt != preparation.readiness.ready_receipt
            || !prepared.extensions.is_empty()
            || prepared.binding_hashes.is_empty()
        {
            return Err("actual readiness and prepared owner disagree");
        }
        flattened.push(prepared.clone());
    }
    if flattened != publication.prepared_owners {
        return Err("complete publisher roster differs from actual node preparations");
    }
    Ok(())
}

fn validated_target_route(
    source: &Publication,
    target: &Publication,
) -> Result<Vec<OwnerIdentity>, &'static str> {
    validate_preparations(source)?;
    validate_preparations(target)?;
    if target.activation.world_binding_hash != source.activation.world_binding_hash
        || target.activation.activation_id == source.activation.activation_id
        || source.activation.generation.checked_add(1.into()).ok()
            != Some(target.activation.generation)
    {
        return Err("foreign target world or generation");
    }
    for index in 0..2 {
        let old = &source.activation.owners[index];
        let fresh = &target.activation.owners[index];
        if old.owner != fresh.owner
            || old.incarnation == fresh.incarnation
            || old.generation.checked_add(1.into()).ok() != Some(fresh.generation)
            || source.prepared_owners[index].binding_hashes
                != target.prepared_owners[index].binding_hashes
        {
            return Err("target is not the same admitted logical owner with fresh native custody");
        }
    }
    Ok(vec![target.activation.owners[1].clone()])
}

/// Checks original history and outcome against independently published fresh authority.
pub(super) fn assert_restored_original(
    directory: &Path,
    execution: &str,
    archive: &ContentRef,
    original: &Bytes,
    restored: &Bytes,
    source: &PublishedSource,
) -> SavedRuntimeActivation {
    let target = read_publication(directory, execution);
    let route = validated_target_route(&source.publication, &target).unwrap();
    assert_eq!(target.activation.boundary, source.capture_cut);
    let coordinator_bytes = durable_bytes(directory, "node-world-coordinators", execution);
    target
        .coordinator_state_ref
        .verify(&coordinator_bytes)
        .unwrap();
    let coordinator: RestoredCoordinator = serde_json::from_slice(&coordinator_bytes).unwrap();
    assert_eq!(
        coordinator.schema,
        "crucible/coordinator-restored-public-arm-root/1"
    );
    assert_eq!(coordinator.source_activation, source.publication.activation);
    assert_eq!(coordinator.target_activation, target.activation);
    assert_eq!(coordinator.source_archive, *archive);
    assert_eq!(
        coordinator.source_coordinator_ref,
        source.coordinator_reference
    );
    assert_eq!(
        coordinator.source_coordinator_bytes,
        source.coordinator_bytes
    );
    assert_eq!(
        serde_json::to_value(coordinator.actual_fresh_preparations).unwrap(),
        serde_json::to_value(&target.node_preparations).unwrap()
    );

    let original: OperationOutcome = serde_json::from_slice(original.as_slice()).unwrap();
    let actual: OperationOutcome = serde_json::from_slice(restored.as_slice()).unwrap();
    let expected = expected_current_outcome(&source.publication, &target, &original).unwrap();
    assert_eq!(actual.owners, route);
    assert_eq!(actual.scheduling.as_ref().unwrap().owners, route);
    assert_eq!(actual, expected);
    assert_eq!(
        restored.as_slice(),
        canonical::canonical_json(&serde_json::to_value(expected).unwrap()).unwrap()
    );
    target.activation
}

fn expected_current_outcome(
    source: &Publication,
    target: &Publication,
    original: &OperationOutcome,
) -> Result<OperationOutcome, &'static str> {
    let route = validated_target_route(source, target)?;
    if original.node.as_str() != "root"
        || original.owners != [source.activation.owners[1].clone()]
        || original
            .scheduling
            .as_ref()
            .is_none_or(|scheduling| scheduling.owners != original.owners)
    {
        return Err("outcome does not retain the original source owner route");
    }

    // Only these two vectors describe the newly authenticated runtime route.
    // Native provenance, event IDs, payloads, history and every other field must
    // remain exactly original; a foreign target never reaches this comparison.
    let mut expected = original.clone();
    expected.owners = route.clone();
    expected
        .scheduling
        .as_mut()
        .ok_or("original scheduling missing")?
        .owners = route;
    Ok(expected)
}

/// Compares the complete original signed file roster and octets with bounded buffers.
pub(super) fn assert_archive_bytes_unchanged(original: &Path, restored: &Path) {
    let mut original_names: Vec<_> = fs::read_dir(original)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let mut restored_names: Vec<_> = fs::read_dir(restored)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    original_names.sort();
    restored_names.sort();
    assert_eq!(original_names, restored_names);

    let mut original_chunk = [0; 64 * 1024];
    let mut restored_chunk = [0; 64 * 1024];
    for name in original_names {
        let original_path = original.join(&name);
        let restored_path = restored.join(&name);
        assert!(fs::symlink_metadata(&original_path).unwrap().is_file());
        assert!(fs::symlink_metadata(&restored_path).unwrap().is_file());
        assert_eq!(
            fs::metadata(&original_path).unwrap().len(),
            fs::metadata(&restored_path).unwrap().len()
        );
        let mut old = BufReader::new(fs::File::open(original_path).unwrap());
        let mut new = BufReader::new(fs::File::open(restored_path).unwrap());
        loop {
            let count = old.read(&mut original_chunk).unwrap();
            new.read_exact(&mut restored_chunk[..count]).unwrap();
            assert_eq!(
                &original_chunk[..count],
                &restored_chunk[..count],
                "original signed archive bytes changed: {name:?}"
            );
            if count == 0 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests;

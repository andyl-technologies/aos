//! Counterexamples for data-only fresh-route oracle validation.

use super::*;
use crucible_node_contract::{Phase, U64};

// This synthetic public preparation exercises the oracle only; no native owner,
// source qualification, activation or continuation authority is constructed.
fn publication(generation: u64) -> Publication {
    let boundary = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
    let owners: Vec<_> = ["clock", "root"]
        .into_iter()
        .map(|name| OwnerIdentity {
            owner: Id::new(format!("owner/{name}")).unwrap(),
            incarnation: Id::new(format!("model/{name}/{generation}")).unwrap(),
            generation: U64::new(generation),
        })
        .collect();
    let node_preparations: Vec<_> = ["clock", "root"]
        .into_iter()
        .zip(&owners)
        .map(|(name, owner)| {
            let ready_receipt = canonical::content_ref(b"ready", "application/json").unwrap();
            NodePreparation {
                node: Id::new(name).unwrap(),
                readiness: Readiness {
                    owners: vec![owner.clone()],
                    boundary,
                    state_inventory: canonical::content_ref(b"state", "application/json").unwrap(),
                    ready_receipt: ready_receipt.clone(),
                },
                prepared_owners: vec![PreparedOwner {
                    owner_id: owner.owner.clone(),
                    incarnation_id: owner.incarnation.clone(),
                    owner_generation: owner.generation,
                    prepared_token: Id::new(format!("model/prepared/{name}/{generation}")).unwrap(),
                    binding_hashes: vec![
                        canonical::hash("cnp.node-binding.v1", name.as_bytes()).unwrap(),
                    ],
                    ready_receipt,
                    extensions: Default::default(),
                }],
            }
        })
        .collect();
    Publication {
        format: "crucible.node-world-activation".to_owned(),
        version: 2,
        activation: SavedRuntimeActivation {
            generation: U64::new(generation),
            activation_id: Id::new(format!("model/activation/{generation}")).unwrap(),
            world_binding_hash: canonical::hash("cnp.world-binding.v1", b"model world").unwrap(),
            owners,
            boundary,
        },
        prepared_owners: node_preparations
            .iter()
            .flat_map(|node| node.prepared_owners.clone())
            .collect(),
        node_preparations,
        coordinator_state_ref: canonical::content_ref(b"coordinator", "application/json").unwrap(),
    }
}

#[test]
fn model_complete_fresh_route_requires_both_original_logical_owners() {
    let source = publication(1);
    let target = publication(2);
    assert_eq!(
        validated_target_route(&source, &target).unwrap(),
        [target.activation.owners[1].clone()]
    );

    let mut partial = target.clone();
    partial.node_preparations.pop();
    assert!(validated_target_route(&source, &partial).is_err());
    let mut swapped = target.clone();
    swapped.activation.owners.swap(0, 1);
    assert!(validated_target_route(&source, &swapped).is_err());
    let mut foreign = target.clone();
    foreign.activation.world_binding_hash =
        canonical::hash("cnp.world-binding.v1", b"foreign").unwrap();
    assert!(validated_target_route(&source, &foreign).is_err());
}

#[test]
fn model_changed_source_or_ready_owner_cannot_authorize_target_rebinding() {
    let source = publication(1);
    let target = publication(2);
    let mut changed_source = source.clone();
    changed_source.prepared_owners[1].binding_hashes =
        vec![canonical::hash("cnp.node-binding.v1", b"changed").unwrap()];
    assert!(validated_target_route(&changed_source, &target).is_err());

    let mut changed_target = target.clone();
    changed_target.node_preparations[1].readiness.owners[0].incarnation =
        Id::new("model/foreign").unwrap();
    assert!(validated_target_route(&source, &changed_target).is_err());
    let mut stale = target.clone();
    stale.activation = source.activation.clone();
    assert!(validated_target_route(&source, &stale).is_err());
    let mut changed_ready = target;
    changed_ready.node_preparations[1].readiness.ready_receipt =
        canonical::content_ref(b"changed ready", "application/json").unwrap();
    assert!(validated_target_route(&source, &changed_ready).is_err());
}

#[test]
fn model_archive_comparison_covers_same_size_octet_mutation_and_extra_file() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("original");
    let target = temporary.path().join("target");
    fs::create_dir_all(&original).unwrap();
    fs::create_dir_all(&target).unwrap();
    fs::write(original.join("native-state"), b"old").unwrap();
    fs::write(target.join("native-state"), b"old").unwrap();
    assert_archive_bytes_unchanged(&original, &target);

    fs::write(target.join("native-state"), b"new").unwrap();
    assert!(
        std::panic::catch_unwind(|| assert_archive_bytes_unchanged(&original, &target)).is_err()
    );
    fs::write(target.join("native-state"), b"old").unwrap();
    fs::write(target.join("extra"), b"old").unwrap();
    assert!(
        std::panic::catch_unwind(|| assert_archive_bytes_unchanged(&original, &target)).is_err()
    );
}

#[test]
fn model_target_rebinding_preserves_every_non_authority_outcome_field() {
    use crucible_core::{
        node_contract::{ProgressEvidence, StopReason},
        node_scheduling::NativeSchedulingObservation,
    };
    let source = publication(1);
    let target = publication(2);
    let node = Id::new("root").unwrap();
    let owners = vec![source.activation.owners[1].clone()];
    let reached = Position::new(1.into(), 1.into(), Phase::BoundaryControl);
    let original = OperationOutcome {
        node: node.clone(),
        operation: Id::new("model/original").unwrap(),
        owners: owners.clone(),
        progress: ProgressEvidence::Exact {
            reached,
            stop: StopReason::HorizonPark,
        },
        retained_outputs: vec![Id::new("model/native-output").unwrap()],
        scheduling: Some(NativeSchedulingObservation {
            node,
            owners,
            reached,
            closed_prefix: reached,
            bounds: Vec::new(),
            publications: Vec::new(),
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: canonical::content_ref(b"original proof", "application/json").unwrap(),
        }),
    };
    let expected = expected_current_outcome(&source, &target, &original).unwrap();
    assert_eq!(expected.owners, [target.activation.owners[1].clone()]);
    assert_eq!(expected.progress, original.progress);
    assert_eq!(expected.retained_outputs, original.retained_outputs);
    assert_eq!(
        expected.scheduling.as_ref().unwrap().proof_ref,
        original.scheduling.as_ref().unwrap().proof_ref
    );

    let mut changed_proof = expected.clone();
    changed_proof.scheduling.as_mut().unwrap().proof_ref =
        canonical::content_ref(b"changed proof", "application/json").unwrap();
    assert_ne!(changed_proof, expected);
    let mut changed_output = expected.clone();
    changed_output.retained_outputs[0] = Id::new("model/foreign-output").unwrap();
    assert_ne!(changed_output, expected);
    let mut foreign_source = original;
    foreign_source.owners[0].incarnation = Id::new("model/foreign-source").unwrap();
    assert!(expected_current_outcome(&source, &target, &foreign_source).is_err());
}

#[test]
fn model_rehashed_archive_source_body_must_match_its_full_original_reference() {
    let directory = tempfile::tempdir().unwrap();
    let reference = canonical::content_ref(b"original", "application/json").unwrap();
    let path = directory
        .path()
        .join(format!("{}.native-object-v1", reference.hash.digest));
    fs::write(&path, b"original").unwrap();
    assert_eq!(
        read_archive_object(directory.path(), &reference),
        b"original"
    );

    fs::write(path, b"tampered").unwrap();
    assert!(
        std::panic::catch_unwind(|| read_archive_object(directory.path(), &reference)).is_err()
    );
}

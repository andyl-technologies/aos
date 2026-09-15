//! Exact-checkpoint canonical relation and resource-bound regressions.

use super::*;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::io::Cursor;

use crucible_cas::content_envelope::ContentChild;

#[test]
fn production_exact_closure_schema_matches_current_magic() {
    assert_eq!(PRODUCTION_EXACT_CLOSURE_SCHEMA_VERSION, 9);
    assert_eq!(MANIFEST_MAGIC, b"crucible.production-exact-closure.v9\0");
}

fn hash(label: &[u8]) -> ContentHash {
    ContentHash::from_bytes(label)
}

struct RepositoryFixture {
    root: ExactCheckpointId,
    envelope: Vec<u8>,
    indexes: Vec<Vec<u8>>,
    observed: Vec<(ContentId, u64)>,
}

fn fixture() -> (
    ExactCheckpointRepositoryBinding,
    ExactCheckpointClosureRecord,
    NodeId,
) {
    let overlay_chunks = vec![hash(b"overlay chunk")];
    let overlay_identity = {
        let extents = vec![ExactCheckpointArtifactExtent {
            start_chunk: 0,
            chunks: overlay_chunks,
        }];
        let mut material = Vec::new();
        ciborium::ser::into_writer(
            &SparseArtifactIdentityMaterial {
                length: 1,
                extents: &extents,
            },
            &mut material,
        )
        .unwrap_or_else(|error| panic!("encode fixture sparse identity: {error:?}"));
        (
            ContentHash::from_canonical_hex_bytes(SPARSE_ARTIFACT_DOMAIN, &material),
            extents,
        )
    };
    let mut target = ExactCheckpointTargetRecord {
        node: String::from("node-a"),
        immutable_backing: hash(b"immutable backing"),
        counter: 17,
        scheduler_time: 23,
        snapshot: hash(b"snapshot"),
        overlay: ExactCheckpointArtifactRecord {
            identity: overlay_identity.0,
            length: 1,
            chunks: Vec::new(),
            sparse: true,
            extents: overlay_identity.1,
        },
        exact_ram: ExactCheckpointRamRecord {
            parent_closure: None,
            device_content_sha256: hash(b"device sha256"),
            device: ExactCheckpointArtifactRecord {
                identity: hash(b"device"),
                length: 1,
                chunks: vec![hash(b"device chunk")],
                sparse: false,
                extents: Vec::new(),
            },
            layers: vec![ExactCheckpointRamLayerRecord {
                kind: ExactCheckpointRamKind::Direct,
                identity: ExactCheckpointIdentity {
                    checkpoint: hash(b"checkpoint"),
                    target: hash(b"target"),
                    frontier: hash(b"frontier"),
                },
                parent: None,
                topology: hash(b"topology"),
                ram_regions: 1,
                ram_records: 1,
                content_sha256: hash(b"ram sha256"),
                artifact: ExactCheckpointArtifactRecord {
                    identity: hash(b"ram"),
                    length: 1,
                    chunks: vec![hash(b"ram chunk")],
                    sparse: false,
                    extents: Vec::new(),
                },
            }],
        },
        manifest_identity: ContentHash::default(),
    };
    let configuration = hash(b"configuration");
    let fault_checkpoint = hash(b"fault checkpoint");
    target.manifest_identity =
        exact_checkpoint_target_manifest_identity(configuration, fault_checkpoint, &target);
    let mut closure = ExactCheckpointClosureRecord {
        scenario: hash(b"scenario"),
        configuration,
        schedule: hash(b"schedule"),
        frontier: 29,
        scheduler: hash(b"scheduler"),
        event_log_segments: Vec::new(),
        signal_artifacts: Vec::new(),
        trigger_state: hash(b"trigger"),
        assertion_state: hash(b"assertion"),
        lifecycle_state: hash(b"lifecycle"),
        fault_checkpoint,
        targets: vec![target],
        failed_host_io: Vec::new(),
        node_generations: vec![(String::from("node-a"), 1)],
        node_service_states: vec![(String::from("node-a"), 1)],
        identity: ContentHash::default(),
        objects: Vec::new(),
    };
    closure.objects = manifest_object_identities(&closure)
        .into_iter()
        .map(|identity| ExactCheckpointObjectRecord {
            identity,
            length: if [
                hash(b"overlay chunk"),
                hash(b"device chunk"),
                hash(b"ram chunk"),
            ]
            .contains(&identity)
            {
                1
            } else {
                32
            },
        })
        .collect();
    assign_exact_checkpoint_closure_identity(&mut closure)
        .unwrap_or_else(|error| panic!("fixture root: {error:?}"));

    let repository_fixture = repository_fixture(&closure);
    let repository = authenticate_exact_checkpoint_repository(
        repository_fixture.root,
        &repository_fixture.envelope,
        &repository_fixture.indexes,
        &repository_fixture.observed,
    )
    .unwrap_or_else(|error| panic!("authenticate fixture repository root: {error:?}"));

    (
        repository,
        closure,
        NodeId {
            name: String::from("node-a"),
        },
    )
}

fn repository_fixture(closure: &ExactCheckpointClosureRecord) -> RepositoryFixture {
    let manifest_bytes = exact_checkpoint_closure_test_bytes(closure)
        .unwrap_or_else(|error| panic!("fixture manifest: {error:?}"));
    let manifest_id = ContentId::for_bytes(
        ObjectKind::DeviceState,
        MANIFEST_SCHEMA_VERSION,
        &manifest_bytes,
    );
    let mut body = Vec::with_capacity(ROOT_BODY_BYTES);
    body.extend_from_slice(&closure.identity.bytes);
    body.extend_from_slice(&closure.scenario.bytes);
    body.extend_from_slice(&closure.configuration.bytes);
    body.extend_from_slice(&(manifest_bytes.len() as u64).to_be_bytes());
    let mut index_body = Vec::new();
    index_body.extend_from_slice(INDEX_MAGIC);
    index_body.extend_from_slice(&(closure.objects.len() as u32).to_be_bytes());
    let mut index_children = BTreeSet::new();
    let mut observed_objects = Vec::new();
    for object in &closure.objects {
        let content = ContentId::for_bytes(
            ObjectKind::DeviceState,
            OBJECT_SCHEMA_VERSION,
            &object.identity.bytes,
        );
        index_body.extend_from_slice(&object.identity.bytes);
        index_body.extend_from_slice(&object.length.to_be_bytes());
        index_children.insert(
            ContentChild::new(object_role(object.identity), content)
                .unwrap_or_else(|error| panic!("fixture object child: {error:?}")),
        );
        observed_objects.push((content, object.length));
    }
    let index = ContentEnvelope::new(
        INDEX_SCHEMA,
        INDEX_SCHEMA_VERSION,
        index_children,
        index_body,
    )
    .unwrap_or_else(|error| panic!("fixture index envelope: {error:?}"));
    let index_id = index.content_id(ObjectKind::ExactManifest);
    body.extend_from_slice(&(closure.objects.len() as u64).to_be_bytes());
    body.extend_from_slice(
        &closure
            .objects
            .iter()
            .map(|object| object.length)
            .sum::<u64>()
            .to_be_bytes(),
    );
    body.extend_from_slice(&1_u32.to_be_bytes());
    let envelope = ContentEnvelope::new(
        ROOT_SCHEMA,
        ROOT_SCHEMA_VERSION,
        BTreeSet::from([
            ContentChild::new(MANIFEST_ROLE, manifest_id)
                .unwrap_or_else(|error| panic!("fixture manifest child: {error:?}")),
            ContentChild::new(
                index_role(0).unwrap_or_else(|| panic!("fixture index role")),
                index_id,
            )
            .unwrap_or_else(|error| panic!("fixture index child: {error:?}")),
        ]),
        body,
    )
    .unwrap_or_else(|error| panic!("fixture root envelope: {error:?}"));
    let root = ExactCheckpointId::try_from(envelope.content_id(ObjectKind::ExactManifest))
        .unwrap_or_else(|error| panic!("fixture exact-checkpoint id: {error:?}"));

    RepositoryFixture {
        root,
        envelope: envelope.canonical_bytes(),
        indexes: vec![index.canonical_bytes()],
        observed: observed_objects,
    }
}

fn authenticate_fixture_target(
    repository: ExactCheckpointRepositoryBinding,
    closure: &ExactCheckpointClosureRecord,
    node: &NodeId,
) -> Result<ExactCheckpointStructuralTargetClaim, ExactCheckpointRelationError> {
    let bytes = exact_checkpoint_closure_test_bytes(closure)?;
    let authenticated = authenticate_exact_checkpoint_closure(
        repository,
        &bytes,
        MAX_EXACT_CHECKPOINT_MANIFEST_BYTES as u64,
    )?;
    let mut traversed = ExactCheckpointTraversedClosureBinding {
        closure: authenticated,
    };
    traversed.take_target(node)
}

#[test]
fn target_binding_authenticates_complete_relation() {
    let (repository, closure, node) = fixture();
    let repository_root = repository.root;
    let binding = authenticate_fixture_target(repository, &closure, &node)
        .unwrap_or_else(|error| panic!("authenticate fixture: {error:?}"));

    assert_eq!(binding.repository_root(), repository_root);
    assert_eq!(binding.root(), closure.identity);
    assert_eq!(
        binding.target_manifest(),
        closure.targets[0].manifest_identity
    );
    assert_eq!(binding.snapshot(), closure.targets[0].snapshot);
    assert_eq!(binding.node(), node.name);
}

#[test]
fn semantic_traversal_reads_a_shared_snapshot_once() {
    let (_, mut closure, _) = fixture();
    let shared_bytes = b"shared semantic object";
    let shared = hash(shared_bytes);
    closure.schedule = shared;
    closure.scheduler = shared;
    closure.trigger_state = shared;
    closure.assertion_state = shared;
    closure.lifecycle_state = shared;
    closure.fault_checkpoint = shared;
    closure.targets[0].snapshot = shared;
    let mut second = closure.targets[0].clone();
    second.node = String::from("node-b");
    closure.targets.push(second);
    closure.node_generations.push((String::from("node-b"), 1));
    closure
        .node_service_states
        .push((String::from("node-b"), 1));
    for target in &mut closure.targets {
        target.manifest_identity = exact_checkpoint_target_manifest_identity(
            closure.configuration,
            closure.fault_checkpoint,
            target,
        );
    }
    closure.objects = manifest_object_identities(&closure)
        .into_iter()
        .map(|identity| ExactCheckpointObjectRecord {
            identity,
            length: if identity == shared {
                shared_bytes.len() as u64
            } else {
                1
            },
        })
        .collect();
    assign_exact_checkpoint_closure_identity(&mut closure)
        .unwrap_or_else(|error| panic!("shared closure root: {error:?}"));

    let fixture = repository_fixture(&closure);
    let repository = authenticate_exact_checkpoint_repository(
        fixture.root,
        &fixture.envelope,
        &fixture.indexes,
        &fixture.observed,
    )
    .unwrap_or_else(|error| panic!("authenticate shared repository: {error:?}"));
    let manifest = exact_checkpoint_closure_test_bytes(&closure)
        .unwrap_or_else(|error| panic!("shared manifest: {error:?}"));
    let binding = authenticate_exact_checkpoint_closure(
        repository,
        &manifest,
        MAX_EXACT_CHECKPOINT_MANIFEST_BYTES as u64,
    )
    .unwrap_or_else(|error| panic!("authenticate shared closure: {error:?}"));
    let opens = Cell::new(0_u64);
    let traversed = binding
        .visit_semantic_objects(
            shared_bytes.len() as u64,
            || Ok(()),
            |identity| {
                assert_eq!(identity, shared);
                opens.set(opens.get() + 1);
                Ok(Box::new(Cursor::new(shared_bytes.to_vec())))
            },
            |_, _| Ok(()),
        )
        .unwrap_or_else(|error| panic!("visit shared semantic object: {error:?}"));

    assert_eq!(opens.get(), 1);
    assert_eq!(traversed.closure.target_index.len(), 2);
}

#[test]
fn execution_binding_rejects_another_immutable_backing() {
    let (repository, closure, node) = fixture();
    let expected = closure.targets[0].immutable_backing;
    let target = authenticate_fixture_target(repository, &closure, &node)
        .unwrap_or_else(|error| panic!("authenticate fixture target: {error:?}"));
    let execution = ExactCheckpointVerifiedNode { target };

    assert_eq!(execution.authenticate_immutable_backing(expected), Ok(()));
    assert_eq!(
        execution.authenticate_immutable_backing(hash(b"other immutable backing")),
        Err(ExactCheckpointRelationError::TargetManifestMismatch)
    );
}

#[test]
fn verified_node_binds_outer_and_embedded_replay_identities() {
    let (repository, closure, node) = fixture();
    let repository_root = repository.root;
    let production_identity = closure.identity;
    let target_manifest = closure.targets[0].manifest_identity;
    let snapshot = closure.targets[0].snapshot;
    let target = authenticate_fixture_target(repository, &closure, &node)
        .unwrap_or_else(|error| panic!("authenticate fixture target: {error:?}"));
    let verified = ExactCheckpointVerifiedNode { target };

    assert_eq!(
        verified.authenticate_replay_source_relation(
            repository_root,
            production_identity,
            target_manifest,
            &node,
            snapshot,
        ),
        Ok(())
    );

    let other_repository = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        b"other repository root",
    ))
    .unwrap_or_else(|error| panic!("other repository root: {error:?}"));
    assert_eq!(
        verified.authenticate_replay_source_relation(
            other_repository,
            production_identity,
            target_manifest,
            &node,
            snapshot,
        ),
        Err(ExactCheckpointRelationError::TargetManifestMismatch)
    );
    assert_eq!(
        verified.authenticate_replay_source_relation(
            repository_root,
            hash(b"other production identity"),
            target_manifest,
            &node,
            snapshot,
        ),
        Err(ExactCheckpointRelationError::TargetManifestMismatch)
    );
}

#[test]
fn target_binding_rejects_root_and_child_transplants() {
    let (repository, mut closure, node) = fixture();
    closure.targets[0].snapshot = hash(b"transplanted snapshot");
    assert_eq!(
        authenticate_fixture_target(repository, &closure, &node),
        Err(ExactCheckpointRelationError::InvalidStructure)
    );
}

#[test]
fn target_binding_rejects_noncontiguous_ram_chain() {
    let (repository, mut closure, node) = fixture();
    let direct = closure.targets[0].exact_ram.layers[0].clone();
    closure.targets[0].exact_ram.parent_closure = Some(hash(b"parent closure"));
    closure.targets[0]
        .exact_ram
        .layers
        .push(ExactCheckpointRamLayerRecord {
            kind: ExactCheckpointRamKind::Delta,
            parent: Some(ExactCheckpointIdentity {
                checkpoint: hash(b"wrong parent"),
                ..direct.identity
            }),
            ..direct
        });
    assign_exact_checkpoint_closure_identity(&mut closure)
        .unwrap_or_else(|error| panic!("mutated root: {error:?}"));

    assert_eq!(
        authenticate_fixture_target(repository, &closure, &node),
        Err(ExactCheckpointRelationError::InvalidStructure)
    );
}

#[test]
fn artifact_lengths_bind_dense_logical_positions() {
    let first = hash(b"dense first");
    let last = hash(b"dense last");
    let artifact = ExactCheckpointArtifactRecord {
        identity: hash(b"dense artifact"),
        length: ARTIFACT_CHUNK_BYTES + 7,
        chunks: vec![first, last],
        sparse: false,
        extents: Vec::new(),
    };
    let mut objects = vec![
        ExactCheckpointObjectRecord {
            identity: first,
            length: ARTIFACT_CHUNK_BYTES,
        },
        ExactCheckpointObjectRecord {
            identity: last,
            length: 7,
        },
    ];
    objects.sort_by_key(|object| object.identity);

    assert_eq!(
        validate_artifact_object_lengths(&artifact, &objects),
        Ok(())
    );

    let first_index = objects
        .binary_search_by_key(&first, |object| object.identity)
        .unwrap_or_else(|error| panic!("first chunk is present: {error:?}"));
    objects[first_index].length -= 1;
    assert_eq!(
        validate_artifact_object_lengths(&artifact, &objects),
        Err(ExactCheckpointRelationError::InvalidStructure)
    );
    objects[first_index].length = ARTIFACT_CHUNK_BYTES;

    let last_index = objects
        .binary_search_by_key(&last, |object| object.identity)
        .unwrap_or_else(|error| panic!("last chunk is present: {error:?}"));
    objects[last_index].length += 1;
    assert_eq!(
        validate_artifact_object_lengths(&artifact, &objects),
        Err(ExactCheckpointRelationError::InvalidStructure)
    );
}

#[test]
fn artifact_lengths_bind_sparse_logical_positions() {
    let last = hash(b"sparse last");
    let artifact = ExactCheckpointArtifactRecord {
        identity: hash(b"sparse artifact"),
        length: ARTIFACT_CHUNK_BYTES + 11,
        chunks: Vec::new(),
        sparse: true,
        extents: vec![ExactCheckpointArtifactExtent {
            start_chunk: 1,
            chunks: vec![last],
        }],
    };
    let valid = [ExactCheckpointObjectRecord {
        identity: last,
        length: 11,
    }];
    let wrong = [ExactCheckpointObjectRecord {
        identity: last,
        length: ARTIFACT_CHUNK_BYTES,
    }];

    assert_eq!(validate_artifact_object_lengths(&artifact, &valid), Ok(()));
    assert_eq!(
        validate_artifact_object_lengths(&artifact, &wrong),
        Err(ExactCheckpointRelationError::InvalidStructure)
    );
}

#[test]
fn artifact_lengths_reject_conflicting_reuse() {
    let reused = hash(b"reused chunk");
    let artifact = ExactCheckpointArtifactRecord {
        identity: hash(b"reused artifact"),
        length: ARTIFACT_CHUNK_BYTES + 1,
        chunks: vec![reused, reused],
        sparse: false,
        extents: Vec::new(),
    };
    let objects = [ExactCheckpointObjectRecord {
        identity: reused,
        length: ARTIFACT_CHUNK_BYTES,
    }];

    assert_eq!(
        validate_artifact_object_lengths(&artifact, &objects),
        Err(ExactCheckpointRelationError::InvalidStructure)
    );
}

#[test]
fn repository_binding_rejects_page_and_object_substitution() {
    let (_, closure, _) = fixture();
    let fixture = repository_fixture(&closure);

    assert_eq!(
        authenticate_exact_checkpoint_repository(
            fixture.root,
            &fixture.envelope,
            &[],
            &fixture.observed,
        ),
        Err(ExactCheckpointRelationError::RepositoryRootMismatch)
    );

    let mut extra_pages = fixture.indexes.clone();
    extra_pages.push(fixture.indexes[0].clone());
    assert_eq!(
        authenticate_exact_checkpoint_repository(
            fixture.root,
            &fixture.envelope,
            &extra_pages,
            &fixture.observed,
        ),
        Err(ExactCheckpointRelationError::RepositoryRootMismatch)
    );

    let mut reordered = fixture.observed.clone();
    reordered.reverse();
    assert_eq!(
        authenticate_exact_checkpoint_repository(
            fixture.root,
            &fixture.envelope,
            &fixture.indexes,
            &reordered,
        ),
        Err(ExactCheckpointRelationError::RepositoryRootMismatch)
    );

    let mut substituted = fixture.observed.clone();
    substituted[0].0 = ContentId::for_bytes(
        ObjectKind::DeviceState,
        OBJECT_SCHEMA_VERSION,
        b"substituted object",
    );
    assert_eq!(
        authenticate_exact_checkpoint_repository(
            fixture.root,
            &fixture.envelope,
            &fixture.indexes,
            &substituted,
        ),
        Err(ExactCheckpointRelationError::RepositoryRootMismatch)
    );

    let mut wrong_length = fixture.observed.clone();
    wrong_length[0].1 += 1;
    assert_eq!(
        authenticate_exact_checkpoint_repository(
            fixture.root,
            &fixture.envelope,
            &fixture.indexes,
            &wrong_length,
        ),
        Err(ExactCheckpointRelationError::RepositoryRootMismatch)
    );
}

#[test]
fn closure_binding_rejects_missing_extra_and_substituted_inventory() {
    let (_, closure, _) = fixture();

    let mut missing = closure.clone();
    missing.objects.remove(0);
    assert_eq!(
        validate_closure_structure(&missing),
        Err(ExactCheckpointRelationError::InvalidStructure)
    );

    let mut extra = closure.clone();
    extra.objects.push(ExactCheckpointObjectRecord {
        identity: hash(b"unreferenced object"),
        length: 1,
    });
    extra.objects.sort_by_key(|object| object.identity);
    assert_eq!(
        validate_closure_structure(&extra),
        Err(ExactCheckpointRelationError::InvalidStructure)
    );

    let mut substituted = closure.clone();
    substituted.objects[0].identity = hash(b"substituted inventory identity");
    substituted.objects.sort_by_key(|object| object.identity);
    assert_eq!(
        validate_closure_structure(&substituted),
        Err(ExactCheckpointRelationError::InvalidStructure)
    );
}

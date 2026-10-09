//! Archive authentication and actual native clock continuation under model-only qualification.
//!
//! These tests execute the real host serializer and clock. Their installed
//! qualification fixture is explicitly synthetic and does not qualify artifacts
//! or profiles for production use.

use std::{
    collections::BTreeMap,
    fs,
    rc::Rc,
    task::{Context, Poll, Waker},
};

use crucible_device::clock::VirtualClock;
use crucible_node_contract::{
    CaptureManifest, CapturedOwner, ContentRef, Id, NodeBinding, NodeDescriptor, Phase, Position,
};

use super::super::*;
use super::*;
use crate::node_adapters::{
    HostModel, HostModelNode, HostModelQualification, HostModelResources, host_clock_initial_bytes,
    validate_host_continuation,
};
use crate::node_contract::*;

#[path = "model_tests.rs"]
mod model_tests;

struct TestDirectory(std::path::PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "crucible-host-archive-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}
fn cut(time: u64) -> Position {
    Position::new(time.into(), 0.into(), Phase::BoundaryControl)
}

struct ModelQualification<'a> {
    source: Option<&'a AuthenticatedHostSource<'a>>,
}

impl HostModelQualification for ModelQualification<'_> {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        _: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        if matches!(model, HostModel::Clock(_)) && descriptor.roles == vec![id("clock")] {
            Ok(())
        } else {
            Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "actual test clock model differs".into(),
            })
        }
    }

    fn authenticate_continuation(
        &self,
        _: &HostModel,
        descriptor: &NodeDescriptor,
        _: &NodeBinding,
        native: &[u8],
        source: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        if self.source.is_some_and(|authenticated| {
            authenticated.node() == &descriptor.id
                && authenticated.native() == native
                && authenticated.runtime() == source
        }) && target.generation > source.source_activation.generation
            && target.boundary == source.capture_cut
        {
            Ok(())
        } else {
            Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "original authenticated test lineage differs".into(),
            })
        }
    }
}

struct ModelFactory;

impl HostWorldFactory for ModelFactory {
    fn authenticate_coordinator(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &crate::node_scheduling::SchedulingSnapshot,
        _: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        assert!(graph.world().connections.is_empty());
        assert_eq!(runtime.capture_cut, scheduler.capture_cut);
        assert_eq!(runtime.capture_ordinal, scheduler.capture_ordinal);
        crate::node_scheduling::validate_saved_source(graph, scheduler)
            .map_err(super::super::schema)
    }

    fn reservation(
        &self,
        _: &crate::node_admission::AdmittedGraph,
        _: &Id,
        native: &[u8],
        _: HostModelResources,
    ) -> Result<RestoreReservations, StateError> {
        Ok(RestoreReservations {
            memory_bytes: (native.len() as u64).saturating_mul(16),
            ..Default::default()
        })
    }

    fn state_schema(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        node: &Id,
    ) -> Result<crucible_node_contract::SchemaRef, StateError> {
        Ok(graph
            .binding(node)
            .unwrap()
            .compatibility
            .implementation
            .formats[0]
            .clone())
    }

    fn authenticate_source(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        node: &Id,
        native: &[u8],
        source: &RuntimeSnapshot,
        _: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        let inventory = validate_host_continuation(
            native,
            source,
            graph.descriptor(node).unwrap(),
            graph.binding(node).unwrap(),
            HostModelResources::default(),
        )
        .map_err(super::native_failure)?;
        if inventory.native_model.bytes.len() != host_clock_initial_bytes(0).len()
            || !inventory
                .native_model
                .bytes
                .starts_with(b"crucible.host-clock.v1\0")
        {
            return Err(super::archive::refusal(
                "selected test native clock codec differs",
            ));
        }
        Ok(())
    }

    fn prepare_node(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        node: &Id,
        source: &AuthenticatedHostSource<'_>,
        target: &ActivationRecord,
        limits: HostModelResources,
    ) -> Result<(HostModelNode, NativeRuntimeContinuationEvidence), StateError> {
        let qualification = ModelQualification {
            source: Some(source),
        };
        let mut actual = HostModelNode::new(
            graph,
            node,
            HostModel::Clock(VirtualClock::new()),
            &qualification,
            limits,
        )
        .map_err(super::native_failure)?;
        let proof = actual
            .prepare_continuation(source.native(), source.runtime(), target, &qualification)
            .map_err(super::native_failure)?;
        Ok((actual, proof))
    }
}

struct Immutable(BTreeMap<String, Vec<u8>>);

impl CaptureEvidence for Immutable {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        let bytes = self
            .0
            .get(&reference.hash.digest)
            .ok_or_else(|| super::archive::refusal("fixture immutable bytes unavailable"))?;
        if bytes.len() > maximum {
            return Err(super::super::closure::limit("fixture fetch"));
        }
        Ok(bytes.clone())
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        _: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        if self.0.get(&reference.hash.digest).map(Vec::as_slice) != Some(bytes) {
            return Err(super::archive::refusal(
                "fixture selected leaf bytes differ",
            ));
        }
        Ok(vec![])
    }

    fn verify_owner_capture(
        &self,
        _: &crate::node_admission::AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(super::archive::refusal(
            "immutable fixture cannot authenticate native owners",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &crate::node_admission::AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(super::archive::refusal(
            "immutable fixture cannot authenticate coordinator state",
        ))
    }
}

struct Publisher;

impl ActivationPublisher for Publisher {
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Committed
    }
    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Committed
    }
}

fn requirements() -> StateRequirements {
    StateRequirements {
        preservation_contract: id("host/preservation-v1"),
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    }
}

fn activation(
    graph: &crate::node_admission::AdmittedGraph,
    generation: u64,
    boundary: Position,
) -> ActivationRecord {
    let owners = graph
        .owners()
        .map(|owner| {
            let binding = graph.binding(&owner.owner.participant_ids[0]).unwrap();
            OwnerIdentity {
                owner: owner.owner.id.clone(),
                incarnation: binding.authority.incarnation_id.clone(),
                generation: binding.authority.owner_generation,
            }
        })
        .collect();
    ActivationRecord {
        generation: generation.into(),
        activation_id: id(&format!("activation/archive-{generation}")),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary,
    }
}

fn advance(
    runtime: &mut NodeRuntime,
    graph: &crate::node_admission::AdmittedGraph,
    world: &WorldActivation,
    node: &Id,
    end: u64,
    acknowledge: bool,
) -> OperationToken {
    let observed = runtime.observe_scheduling(world, node).unwrap();
    runtime
        .scheduler(graph, world)
        .unwrap()
        .accept_boundary_observation(observed)
        .unwrap();
    let grant = runtime
        .scheduler(graph, world)
        .unwrap()
        .admit_exact(node, id(&format!("run/{node}/{end}")), end.into())
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("actual clock rejected admitted operation")
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        runtime.poll(&token, &mut context),
        Poll::Ready(Ok(_))
    ));
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let committed = runtime.commit_scheduling_receipt(receipt).unwrap();
    if acknowledge {
        runtime.acknowledge_scheduled(&token, &committed).unwrap();
    }
    token
}

fn source_world(
    graph: &crate::node_admission::AdmittedGraph,
    queue: &mut RuntimeCustodyQueue,
) -> (NodeRuntime, WorldActivation) {
    let nodes: Vec<Box<dyn SimulationNode>> = graph
        .node_ids()
        .map(|node| {
            Box::new(
                HostModelNode::new(
                    graph,
                    node,
                    HostModel::Clock(VirtualClock::new()),
                    &ModelQualification { source: None },
                    HostModelResources::default(),
                )
                .unwrap(),
            ) as Box<dyn SimulationNode>
        })
        .collect();
    let record = activation(graph, 1, cut(0));
    let slot = queue
        .reserve_world(&record, RuntimeLimits::default())
        .unwrap();
    let mut runtime = NodeRuntime::new(graph, nodes, record, RuntimeLimits::default(), slot)
        .ok()
        .unwrap();
    runtime.arm_all().unwrap();
    let world = runtime.activate(&mut Publisher).unwrap();
    (runtime, world)
}

#[test]
fn durable_archive_restores_actual_clock_and_original_pending_ack_without_reexecution() {
    let directory = TestDirectory::new();
    let path = directory.path().join("private");
    let limits = StateLimits::default();
    let archive = HostArchive::open(&path, limits).unwrap();
    let (graph, blobs) = crate::node_admission::test_fixture_host_clock_execution();
    let mut queue = RuntimeCustodyQueue::new(4).unwrap();
    let (mut runtime, world) = source_world(&graph, &mut queue);
    let original = advance(&mut runtime, &graph, &world, &id("a"), 100, false);
    advance(&mut runtime, &graph, &world, &id("z"), 100, true);
    let record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &world,
            cut(100),
            7.into(),
            id("capture/native-clock"),
            requirements(),
            &Immutable(blobs),
            &ModelFactory,
        )
        .unwrap();
    let artifact = record.artifact().clone();
    drop(runtime);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..8 {
        let _ = queue.poll_reclamation(&mut context);
    }
    assert_eq!(
        queue.reserved_worlds(),
        0,
        "original native owners must actually retire"
    );
    drop(archive);

    let archive = HostArchive::open(&path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let (fresh, _) = crate::node_admission::test_restore_fixture_host_clock_execution();
    let graph = Rc::new(fresh);
    let verified = record
        .admit(&graph, requirements(), &ModelFactory, limits)
        .unwrap();
    let target = activation(&graph, 2, cut(100));
    let mut driver =
        HostWorldRestoreDriver::new(graph.clone(), record, Rc::new(ModelFactory), queue.clone())
            .unwrap();
    let prepared = stage_restore(&graph, verified, target, &mut driver, limits)
        .unwrap_or_else(|error| panic!("{}", error.error));
    let RestorePublication::Committed(mut restored) = prepared.publish(&mut Publisher) else {
        panic!("actual host restore did not publish")
    };
    let resumed = restored.activation().clone();
    let recovered = restored
        .runtime_mut()
        .recover(original.operation())
        .unwrap();
    let commitment = restored
        .runtime_mut()
        .recover_scheduling_commit(&recovered)
        .unwrap();
    restored
        .runtime_mut()
        .acknowledge_scheduled(&recovered, &commitment)
        .unwrap();
    restored
        .runtime_mut()
        .acknowledge_scheduled(&recovered, &commitment)
        .unwrap();
    advance(
        restored.runtime_mut(),
        &graph,
        &resumed,
        &id("a"),
        200,
        true,
    );
    assert_eq!(
        restored.runtime_mut().status(&id("a")).unwrap().boundary,
        Some(cut(200))
    );
    drop(restored);
    for _ in 0..12 {
        let _ = queue.poll_reclamation(&mut context);
    }
    assert_eq!(queue.reserved_worlds(), 0);
}

#[test]
fn authenticated_archive_refuses_changed_bytes_dependency_metadata_and_another_host_key() {
    let directory = TestDirectory::new();
    let archive =
        HostArchive::open(directory.path().join("private"), StateLimits::default()).unwrap();
    let (graph, blobs) = crate::node_admission::test_fixture_host_clock_execution();
    let mut queue = RuntimeCustodyQueue::new(2).unwrap();
    let (mut runtime, world) = source_world(&graph, &mut queue);
    let record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &world,
            cut(0),
            0.into(),
            id("capture/tamper"),
            requirements(),
            &Immutable(blobs),
            &ModelFactory,
        )
        .unwrap();
    let artifact = record.artifact().clone();
    let path = archive
        .directory
        .join(format!("{}.host-world-v1.json", artifact.hash.digest));
    let original = fs::read(&path).unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
    changed["body"]["objects"][0]["bytes"][0] = serde_json::json!(255);
    fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(archive.load(&artifact).is_err());
    let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
    changed["body"]["objects"][0]["dependencies"] = serde_json::json!([artifact]);
    fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(archive.load(&artifact).is_err());
    fs::write(&path, &original).unwrap();
    let other = HostArchive::open(directory.path().join("other"), StateLimits::default()).unwrap();
    fs::write(other.directory.join(path.file_name().unwrap()), original).unwrap();
    assert!(other.load(&artifact).is_err());
}

#[test]
fn private_keys_and_wrong_native_capture_cuts_fail_closed() {
    use std::os::unix::fs::PermissionsExt;
    let directory = TestDirectory::new();
    let path = directory.path().join("private");
    let archive = HostArchive::open(&path, StateLimits::default()).unwrap();
    let (graph, blobs) = crate::node_admission::test_fixture_host_clock_execution();
    let mut queue = RuntimeCustodyQueue::new(2).unwrap();
    let (mut runtime, world) = source_world(&graph, &mut queue);
    assert!(
        archive
            .capture_world(
                &graph,
                &mut runtime,
                &world,
                cut(1),
                0.into(),
                id("capture/false-cut"),
                requirements(),
                &Immutable(blobs),
                &ModelFactory
            )
            .is_err()
    );
    fs::set_permissions(
        path.join("authentication-key-v1"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(HostArchive::open(&path, StateLimits::default()).is_err());
}

#[test]
fn authentication_key_symlinks_and_hard_links_are_refused_on_opened_descriptors() {
    use std::os::unix::fs::symlink;
    let directory = TestDirectory::new();
    let path = directory.path().join("private");
    let archive = HostArchive::open(&path, StateLimits::default()).unwrap();
    let key = path.join("authentication-key-v1");
    let alias = path.join("key-alias");
    fs::hard_link(&key, &alias).unwrap();
    assert!(HostArchive::open(&path, StateLimits::default()).is_err());
    fs::remove_file(&alias).unwrap();
    assert!(HostArchive::open(&path, StateLimits::default()).is_ok());
    fs::rename(&key, &alias).unwrap();
    symlink("key-alias", &key).unwrap();
    assert!(HostArchive::open(&path, StateLimits::default()).is_err());
    drop(archive);
}

#[test]
fn authenticated_import_checks_object_edge_and_byte_ceilings_during_decoding() {
    let directory = TestDirectory::new();
    let path = directory.path().join("private");
    let archive = HostArchive::open(&path, StateLimits::default()).unwrap();
    let (graph, blobs) = crate::node_admission::test_fixture_host_clock_execution();
    let mut queue = RuntimeCustodyQueue::new(2).unwrap();
    let (mut runtime, world) = source_world(&graph, &mut queue);
    let record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &world,
            cut(0),
            0.into(),
            id("capture/import-bounds"),
            requirements(),
            &Immutable(blobs),
            &ModelFactory,
        )
        .unwrap();
    let artifact = record.artifact().clone();
    let actual_objects = record.body.objects.len();
    let actual_edges: usize = record
        .body
        .objects
        .iter()
        .map(|object| object.dependencies.len())
        .sum();
    assert!(actual_edges > actual_objects);
    let shared = record
        .body
        .objects
        .iter()
        .find(|object| {
            record
                .body
                .objects
                .iter()
                .filter(|parent| parent.dependencies.contains(&object.reference))
                .count()
                > 1
        })
        .unwrap();
    assert!(
        record
            .body
            .objects
            .iter()
            .filter(|parent| parent.dependencies.contains(&shared.reference))
            .count()
            > 1
    );
    let exact_roster = HostArchive::open(
        &path,
        StateLimits {
            maximum_content_objects: actual_objects,
            maximum_dependency_edges: actual_edges,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        exact_roster.load(&artifact).is_ok(),
        "shared dependency DAG with more edges than objects remains valid"
    );
    for limits in [
        StateLimits {
            maximum_content_objects: actual_objects - 1,
            ..Default::default()
        },
        StateLimits {
            maximum_dependency_edges: actual_edges - 1,
            ..Default::default()
        },
        StateLimits {
            maximum_content_bytes: 1,
            ..Default::default()
        },
        StateLimits {
            maximum_total_content_bytes: 1,
            ..Default::default()
        },
    ] {
        let bounded = HostArchive::open(&path, limits).unwrap();
        let error = match bounded.load(&artifact) {
            Ok(_) => panic!("signed source exceeded a decoded allocation ceiling"),
            Err(error) => error,
        };
        assert!(error.reason.contains("preallocation ceiling"), "{}", error);
    }
}

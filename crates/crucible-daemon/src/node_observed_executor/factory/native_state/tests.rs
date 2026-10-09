//! Actual installed mixed-world cold witnesses with no constructed native seals.

// Panics report failures of actual original custody and complete native reconstruction.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    os::unix::fs::PermissionsExt,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{
        BeginResult, NodeRuntime, OperationOutcome, OperationToken, SavedRuntimeResult,
    },
    node_state::{
        NativeArchive, NativeArchiveLimits, NativeArchiveRecord, NativeWorldRestoreDriver,
        PublicationKnowledge, RestorePublication, RestoredWorld, StateLimits, StateRequirements,
        StateRestoreMode, stage_restore,
    },
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_node_contract::{Id, U64};

use super::{factory::MixedNativeFactory, installed::InstalledMixedEngine};
use crate::node_observed_executor::StoredWorldActivationPublisher;

#[test]
#[ignore = "requires the compiled source-built complete gem5 closed profile"]
fn pending_native_budget_prefix_survives_source_death_in_two_complete_worlds() {
    cold_world_witness("x86_64", false);
}

#[test]
#[ignore = "requires the compiled source-built complete gem5 closed profile"]
fn held_native_publication_survives_source_death_in_two_complete_worlds() {
    cold_world_witness("aarch64", true);
}

fn cold_world_witness(isa: &str, held_publication: bool) {
    // Failed native callbacks keep their original backing tree until the owning
    // supervisor proves reclamation. A temporary-directory Drop cannot decide
    // when live images and process-private files are safe to unlink.
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = InstalledMixedEngine::new(directory.clone(), 8).unwrap();
    let _supervision = FailedWitnessSupervision { engine: &engine };
    let live = engine.prepare_live(isa).unwrap();
    let factory = Rc::new(MixedNativeFactory::for_live(&live, engine.native.clone()));
    let namespace = live.namespace.clone();
    let graph = live.graph.clone();
    let source_target = live.target.clone();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "mixed-native",
        directory.join("cas"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let mut runtime = live
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "original"))
        .unwrap();
    engine
        .native
        .record_publication(&source_target, PublicationKnowledge::Committed)
        .unwrap();
    for node in graph.node_ids() {
        let observation = runtime.observe_scheduling(&activation, node).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
    }
    let admission = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(
            &id("cpu"),
            id("original/cpu-grant"),
            U64::new(1_000_000_000),
        )
        .unwrap();
    let BeginResult::Accepted(original) = runtime.begin_admitted(admission).unwrap() else {
        panic!("actual native grant was refused");
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(runtime.poll(&original, &mut context).is_pending());
    let held = if held_publication {
        Some(finish_poll(&mut runtime, &original))
    } else {
        None
    };
    if let Some(outcome) = &held {
        assert_eq!(outcome.retained_outputs.len(), 1);
        assert_eq!(
            outcome.scheduling.as_ref().unwrap().publications[0]
                .payload_bytes
                .len(),
            8
        );
    }
    let cut = source_target.boundary;
    let ordinal = U64::new(17);
    let before = runtime
        .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
        .unwrap();
    assert_eq!(before.operations.len(), 1);
    assert_eq!(before.operations[0].operation, *original.operation());
    assert!(before.operations[0].scheduling_commit.is_none());
    if held_publication {
        assert!(matches!(
            before.operations[0].result,
            SavedRuntimeResult::Complete(_)
        ));
    } else {
        assert_eq!(before.operations[0].result, SavedRuntimeResult::Pending);
    }
    let limits = archive_limits();
    let archive_path = directory.join("native-archive");
    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &activation,
            cut,
            ordinal,
            id("mixed/original-capture"),
            requirements(),
            &factory.immutable(),
            factory.as_ref(),
        )
        .unwrap();
    assert_eq!(record.owners().len(), 2);
    assert_eq!(record.manifest().owners.len(), 2);
    assert_eq!(record.runtime_snapshot().unwrap(), before);
    let original_scheduler = record.scheduling_snapshot().unwrap();
    assert_eq!(original_scheduler.reservations.len(), 1);
    assert_eq!(
        original_scheduler.reservations[0].operation,
        *original.operation()
    );
    let native_source = record
        .object_bytes(
            &record
                .owners()
                .iter()
                .find(|owner| owner.owner.as_str() == "owner/cpu")
                .unwrap()
                .state,
            16 * 1024 * 1024,
        )
        .unwrap();
    let configuration = record
        .object_bytes(
            &graph.descriptor(&id("cpu")).unwrap().configuration_ref,
            1024 * 1024,
        )
        .unwrap();
    let configuration: serde_json::Value = serde_json::from_slice(&configuration).unwrap();
    let expected_native_credit = match isa {
        "x86_64" => 65_536,
        "aarch64" => 262_144,
        _ => panic!("unknown native witness architecture"),
    };
    assert_eq!(
        configuration["native_poll"]["maximum_events_per_poll"],
        expected_native_credit.to_string()
    );
    let native_record: serde_json::Value = serde_json::from_slice(&native_source).unwrap();
    let prefix_refs: Vec<crucible_node_contract::ContentRef> =
        serde_json::from_value(native_record["native_prefixes"].clone()).unwrap();
    assert!(!prefix_refs.is_empty());
    for reference in &prefix_refs {
        let bytes = record.object_bytes(reference, 16 * 1024 * 1024).unwrap();
        let prefix: crucible_node_provider::gem5::Gem5Completion =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            prefix.original.maximum_events,
            U64::new(expected_native_credit)
        );
    }
    if !held_publication {
        assert_eq!(prefix_refs.len(), 1);
    }
    let artifact = record.artifact().clone();
    let reserved_before = engine.native.reserved_owners();
    let other_isa = if isa == "x86_64" { "aarch64" } else { "x86_64" };
    assert!(engine.prepare_cold(record.clone(), other_isa).is_err());
    assert_eq!(engine.native.reserved_owners(), reserved_before);
    drop(original);
    drop(runtime);
    drop(activation);
    drop(factory);
    drop(graph);
    reclaim(&engine);
    std::fs::remove_dir_all(&namespace).unwrap();
    assert!(!namespace.exists());
    drop(record);
    drop(archive);

    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    assert_eq!(
        record
            .object_bytes(
                &record
                    .owners()
                    .iter()
                    .find(|owner| owner.owner.as_str() == "owner/cpu")
                    .unwrap()
                    .state,
                16 * 1024 * 1024
            )
            .unwrap(),
        native_source
    );
    let (left_graph, mut left) =
        restore(&engine, record.clone(), isa, &blobs, &refs, "left", limits);
    let (right_graph, mut right) = restore(&engine, record, isa, &blobs, &refs, "right", limits);
    assert_ne!(
        left.activation().record().owners,
        right.activation().record().owners
    );
    assert_eq!(left.activation().record().boundary, cut);
    assert_eq!(right.activation().record().boundary, cut);
    let left_snapshot = left
        .runtime_mut()
        .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
        .unwrap();
    let right_snapshot = right
        .runtime_mut()
        .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
        .unwrap();
    for saved in [&left_snapshot, &right_snapshot] {
        assert_eq!(saved.capture_cut, before.capture_cut);
        assert_eq!(saved.capture_ordinal, before.capture_ordinal);
        assert_eq!(
            saved.operations[0].operation,
            before.operations[0].operation
        );
        assert_eq!(saved.operations[0].request, before.operations[0].request);
        assert_eq!(saved.operations[0].scheduling_commit, None);
    }
    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    let left_original = left
        .runtime_mut()
        .recover(&id("original/cpu-grant"))
        .unwrap();
    let right_original = right
        .runtime_mut()
        .recover(&id("original/cpu-grant"))
        .unwrap();
    let left_outcome = finish_poll(left.runtime_mut(), &left_original);
    let right_outcome = finish_poll(right.runtime_mut(), &right_original);
    let left_publication = &left_outcome.scheduling.as_ref().unwrap().publications[0];
    let right_publication = &right_outcome.scheduling.as_ref().unwrap().publications[0];
    assert_eq!(left_publication, right_publication);
    assert_eq!(left_publication.payload_bytes, expected_checksum());
    if let Some(original) = held {
        assert_eq!(
            &original.scheduling.as_ref().unwrap().publications[0],
            left_publication
        );
    }
    for (runtime, token) in [
        (left.runtime_mut(), &left_original),
        (right.runtime_mut(), &right_original),
    ] {
        let receipt = runtime.scheduling_receipt(token).unwrap();
        let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
        runtime.acknowledge_scheduled(token, &commit).unwrap();
        // The old restored-ready inventory cannot certify genuine later native
        // prefixes, publication custody retirement or changed ACK state.
        assert!(runtime.arm_all().is_err());
    }
    let left_position = left
        .runtime_mut()
        .scheduler(&left_graph, &left_activation)
        .unwrap()
        .position(&id("cpu"))
        .unwrap();
    let right_position = right
        .runtime_mut()
        .scheduler(&right_graph, &right_activation)
        .unwrap()
        .position(&id("cpu"))
        .unwrap();
    assert_eq!(left_position, right_position);
    drop(left_original);
    drop(right_original);
    drop(left);
    drop(right);
    reclaim(&engine);
    std::fs::remove_dir_all(directory).unwrap();
}

fn restore(
    engine: &InstalledMixedEngine,
    record: NativeArchiveRecord,
    isa: &str,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    name: &str,
    limits: NativeArchiveLimits,
) -> (Rc<AdmittedGraph>, Box<RestoredWorld>) {
    let plan = engine.prepare_cold(record.clone(), isa).unwrap();
    let graph = plan.graph.clone();
    let target = plan.target.clone();
    let factory = Rc::new(MixedNativeFactory::for_cold(plan, engine.native.clone()));
    let verified = record
        .admit(&graph, requirements(), factory.as_ref())
        .unwrap();
    let mut driver =
        NativeWorldRestoreDriver::new(graph.clone(), record, factory, engine.runtime.clone())
            .unwrap();
    let prepared = stage_restore(&graph, verified, target.clone(), &mut driver, limits.state)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    let RestorePublication::Committed(restored) =
        prepared.publish(&mut publisher(blobs, refs, name))
    else {
        panic!("actual mixed native world did not commit");
    };
    engine
        .native
        .record_publication(&target, PublicationKnowledge::Committed)
        .unwrap();
    (graph, restored)
}

fn finish_poll(runtime: &mut NodeRuntime, token: &OperationToken) -> OperationOutcome {
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        match runtime.poll(token, &mut context) {
            Poll::Pending => {}
            Poll::Ready(Ok(outcome)) => return outcome,
            Poll::Ready(Err(error)) => panic!("{error}"),
        }
    }
    panic!("actual fixed guest exceeded bounded native prefix budget");
}

/// Computes the fixed installed ELF's integer/memory checksum independently of
/// either ISA's execution, native event journal or reconstructed child.
fn expected_checksum() -> [u8; 8] {
    let mut arena = vec![0_u64; 262_144 / 8];
    let mut state = 3_u32;
    let mut answer = 0_u64;

    for _ in 0..20_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let index = (state & 262_136) as usize / 8;
        arena[index] ^= u64::from(state);
        answer = answer.wrapping_add(arena[index]);
        if state & 1 != 0 {
            answer = answer.wrapping_add(19);
        }
    }

    answer.to_le_bytes()
}

fn reclaim(engine: &InstalledMixedEngine) {
    let mut context = Context::from_waker(Waker::noop());
    let mut retired = Vec::new();
    for _ in 0..6000 {
        if let Poll::Ready(Err(error)) = engine.runtime.poll_reclamation(&mut context) {
            panic!("{error}");
        }
        if engine.runtime.reserved_worlds() == 0 {
            retired.extend(engine.native.take_reclaimed().unwrap());
        }
        if engine.runtime.reserved_worlds() == 0 && engine.native.reserved_owners() == 0 {
            assert!(!retired.is_empty());
            for original in &mut retired {
                assert!(original.custody.child.try_wait().unwrap().is_some());
                original.evidence.verify(&original.bytes).unwrap();
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("original mixed native process and all helpers were not authentically reaped");
}

/// Keeps the installed cleanup actor and original source backing alive through
/// assertion unwind until actual common-world and native-group reclamation.
struct FailedWitnessSupervision<'a> {
    engine: &'a InstalledMixedEngine,
}

impl Drop for FailedWitnessSupervision<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let mut context = Context::from_waker(Waker::noop());
        let mut retired = Vec::new();
        let mut reported_failure = false;
        for _ in 0..6000 {
            let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.engine.runtime.poll_reclamation(&mut context)
            }));
            if !matches!(cleanup, Ok(Poll::Ready(Ok(()))) | Ok(Poll::Pending)) && !reported_failure
            {
                eprintln!("failed mixed witness retains original cleanup obligations");
                reported_failure = true;
            }
            if self.engine.runtime.reserved_worlds() == 0 {
                match self.engine.native.take_reclaimed() {
                    Ok(capsules) => retired.extend(capsules),
                    Err(error) if !reported_failure => {
                        eprintln!("original native retirement remains owned: {error}");
                        reported_failure = true;
                    }
                    Err(_) => {}
                }
            }
            if self.engine.runtime.reserved_worlds() == 0
                && self.engine.native.reserved_owners() == 0
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // A cleanup timeout is never evidence of retirement. The global actor
        // keeps its actual native capsules, and the private tree remains.
        eprintln!("mixed witness original source remains quarantined after cleanup deadline");
    }
}

fn archive_limits() -> NativeArchiveLimits {
    // Native ledgers are small bounded records; checkpoint images use the
    // independently reserved streamed-artifact credits below.
    NativeArchiveLimits {
        state: StateLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_native_processes: 8192,
            ..StateLimits::default()
        },
        native: crucible::node_contract::NativeCaptureLimits {
            maximum_objects: 20_000,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_total_record_bytes: 64 * 1024 * 1024,
            maximum_artifact_bytes: 2 * 1024 * 1024 * 1024,
            maximum_total_artifact_bytes: 8 * 1024 * 1024 * 1024,
        },
    }
}

fn requirements() -> StateRequirements {
    StateRequirements {
        preservation_contract: id("mixed/native-preservation-v1"),
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    }
}
fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}
fn publisher(
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    name: &str,
) -> StoredWorldActivationPublisher {
    StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new(format!("node-world-activations/{name}")).unwrap(),
    )
    .unwrap()
}

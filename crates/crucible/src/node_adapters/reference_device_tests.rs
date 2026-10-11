//! Actual child-process integration and bounded executable authentication tests.

// crucible-lint: allow panic-shortcut -- These reference device tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Waker,
    time::Duration,
};

use super::*;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "crucible-node-adapter-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn actual_executable_bytes_must_match_not_only_identity_syntax() {
    let directory = Directory::new();
    let path = directory.0.join("executable-evidence");
    fs::write(&path, b"bounded actual source-built executable evidence").unwrap();
    let bytes = fs::read(&path).unwrap();
    let mut reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
    verify_executable(&path, &reference).unwrap();
    reference.hash.digest = "0".repeat(64);
    assert!(verify_executable(&path, &reference).is_err());
    reference.length = 1.into();
    assert!(verify_executable(&path, &reference).is_err());
}

struct NativeQualification;
impl ReferenceDeviceQualification for NativeQualification {
    fn authenticate_child(
        &self,
        child: &ReferenceDevice,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        // The test graph deliberately uses synthetic host qualification; these
        // checks additionally inspect the real source-built native child's
        // authenticated identity, inactive state and selected profile. Actual
        // executable bytes are independently measured by the adapter.
        if child.status() == DeviceStatus::Parked
            && child.child_pid() > 0
            && child.owner_id() == &binding.compatibility.execution_owner.id
            && child.incarnation_id() == &binding.authority.incarnation_id
            && child.generation() == binding.authority.owner_generation
            && descriptor.roles[0].as_str() == "external_device"
        {
            Ok(())
        } else {
            Err(no_effect("actual native prepared child identity differs"))
        }
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

/// Runs explicitly with a source-built companion; absence is an error, never a
/// synthetic successful backend. The ordinary library suite does not build a
/// dependency's executable, so the integration harness opts into this case.
#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE source-built companion"]
fn actual_child_runs_two_admitted_quantums_with_original_input_and_publication_custody() {
    let executable = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE")
            .expect("set source-built CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"),
    );
    let metadata = fs::metadata(&executable).unwrap();
    assert!(
        metadata.len() <= 4 * 1024 * 1024,
        "fixture executable exceeds test graph content ceiling"
    );
    let executable_bytes = fs::read(&executable).unwrap();
    let (graph, _) = crate::node_admission::test_fixture_reference_device(executable_bytes);
    let directory = Directory::new();
    let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::new();
    let owners = graph
        .node_ids()
        .map(|node| {
            let binding = graph.binding(node).unwrap();
            OwnerIdentity {
                owner: binding.compatibility.execution_owner.id.clone(),
                incarnation: binding.authority.incarnation_id.clone(),
                generation: binding.authority.owner_generation,
            }
        })
        .collect();
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("activation/actual-device").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: root(0, Phase::BoundaryControl),
    };
    for node in graph.node_ids() {
        let binding = graph.binding(node).unwrap();
        let child = ReferenceDevice::spawn(
            &executable,
            &directory.0,
            binding.compatibility.execution_owner.id.clone(),
            binding.authority.incarnation_id.clone(),
            binding.authority.owner_generation,
            Duration::from_secs(2),
        )
        .unwrap();
        let mut adapter =
            ReferenceDeviceNode::from_prepared(&graph, node, child, &NativeQualification, 16)
                .unwrap();
        adapter.arm(&record).unwrap();
        let bytes = vec![42];
        let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
        let forbidden = RuntimeInputBatch {
            activation: WorldActivation {
                nodes: std::rc::Rc::from([]),
                preparation: None,
                authority: Rc::new(()),
                record: record.clone(),
            },
            node: node.clone(),
            stage_operation: Id::new("stage/forbidden-ingress").unwrap(),
            batch: Id::new("batch/forbidden-ingress").unwrap(),
            owners: adapter.route.owners.clone(),
            cutoff: root(1, Phase::BoundaryControl),
            inventory: reference.clone(),
            deliveries: Vec::new(),
            payloads: vec![InputPayload { reference, bytes }],
        };
        assert!(adapter.stage_inputs(&forbidden).is_err());
        assert!(adapter.staged.is_none());
        assert_eq!(adapter.child.status(), DeviceStatus::Parked);
        nodes.push(Box::new(adapter));
    }
    let mut runtime = NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .ok()
    .unwrap();
    runtime.arm_all().unwrap();
    let activation = runtime.activate(&mut Publisher).unwrap();
    runtime.scheduler(&graph, &activation).unwrap();
    let node = Id::new("a").unwrap();
    let observation = runtime.observe_scheduling(&activation, &node).unwrap();
    runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .accept_boundary_observation(observation)
        .unwrap();

    for quantum in 0..2u64 {
        let stage = Id::new(format!("stage/{quantum}")).unwrap();
        let batch = Id::new(format!("batch/{quantum}")).unwrap();
        let input = runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .prepare_input_batch(
                &node,
                stage.clone(),
                batch.clone(),
                root(quantum * 100 + 1, Phase::BoundaryControl),
            )
            .unwrap();
        let acknowledged = runtime.stage_inputs(input).unwrap();
        let retained = runtime.recover_input_staging(&activation, &stage).unwrap();
        assert_eq!(acknowledged.batch(), retained.batch());
        let input_commit = runtime.commit_input_acknowledgement(retained).unwrap();
        runtime.commit_input_staging(&input_commit).unwrap();
        let grant = runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .admit_quantum(
                &node,
                Id::new(format!("run/{quantum}")).unwrap(),
                Id::new(format!("window/{quantum}")).unwrap(),
                batch,
            )
            .unwrap();
        let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
            panic!("actual child refused admitted window")
        };
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(runtime.poll(&token, &mut context), Poll::Pending));
        assert_eq!(runtime.close_quantum(&token).unwrap(), Submission::Accepted);
        let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut context) else {
            panic!("actual native closure not ready")
        };
        assert!(matches!(
            outcome.progress,
            ProgressEvidence::Quantized {
                physical: PhysicalState::Unknown,
                ..
            }
        ));
        let native = outcome.scheduling.as_ref().unwrap();
        assert_eq!(native.publications.len(), 1);
        assert_eq!(
            native.publications[0].publication,
            root((quantum + 1) * 100, Phase::Publication)
        );
        assert_eq!(native.publications[0].evaluation, None);
        let output: crucible_node_provider::reference_device::DeviceOutput =
            serde_json::from_slice(&native.publications[0].payload_bytes).unwrap();
        assert_eq!(output.bytes_processed.get(), 0);
        assert_eq!(output.checksum.get(), 0);
        let receipt = runtime.scheduling_receipt(&token).unwrap();
        let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
        runtime.acknowledge_scheduled(&token, &commit).unwrap();
        runtime.acknowledge_scheduled(&token, &commit).unwrap();
        let ProgressEvidence::Quantized { closure, .. } = &outcome.progress else {
            unreachable!()
        };
        let references = vec![
            closure.close_receipt.clone(),
            closure.output_inventory.clone(),
            closure.pending_inventory.clone(),
        ];
        let evidence = runtime
            .operation_evidence(&token, &references, (64 * 1024).into())
            .unwrap();
        assert_eq!(evidence.len(), 3);
        let native_receipt: crucible_node_provider::reference_device::DeviceReceipt =
            serde_json::from_slice(&evidence[0].bytes).unwrap();
        assert_eq!(native_receipt.grant.quantum.get(), quantum);
        assert_eq!(
            native_receipt.grant.publication,
            root((quantum + 1) * 100, Phase::Publication)
        );
        let pending: serde_json::Value = serde_json::from_slice(&evidence[2].bytes).unwrap();
        assert_eq!(pending["original_buffer_retained"], true);
        assert!(
            runtime
                .operation_evidence(&token, &references, 1.into())
                .is_err()
        );
    }
    // Actual child guards retain native kill/reap supervision on runtime drop.
    drop(runtime);
}

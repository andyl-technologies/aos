//! Exercises the wrapper's original external staging branch with real child custody.
//!
//! The stage-only fixture deliberately lacks a consumed-commit implementation.
//! Its supplied staging ACK is a regression input, never conformance evidence.

use super::*;
use crucible_node_transport::{ProviderError, reference_device::DeviceGrant};

struct StageOnlyChild {
    native: ReferenceDevice,
    supplies_ack: bool,
}

impl control::sealed::Sealed for StageOnlyChild {}

impl ControlledReference for StageOnlyChild {
    fn status(&self) -> DeviceStatus {
        self.native.status()
    }

    fn child_pid(&self) -> u32 {
        self.native.child_pid()
    }

    fn supervision_id(&self) -> U64 {
        self.native.supervision_id()
    }

    fn owner_id(&self) -> &Id {
        self.native.owner_id()
    }

    fn incarnation_id(&self) -> &Id {
        self.native.incarnation_id()
    }

    fn generation(&self) -> U64 {
        self.native.generation()
    }

    fn stage(&mut self, grant: DeviceGrant, bytes: &[u8]) -> Result<(), ProviderError> {
        self.native.stage(grant, bytes)
    }

    fn activate(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.native.activate(grant)
    }

    fn close(&mut self, grant: &DeviceGrant) -> Result<DeviceReceipt, ProviderError> {
        self.native.close(grant)
    }

    fn validate_receipt(&self, receipt: &DeviceReceipt) -> Result<(), ProviderError> {
        self.native.validate_receipt(receipt)
    }

    fn acknowledge_publication(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.native.acknowledge_publication(grant)
    }

    fn quarantine(&mut self) -> Result<bool, ProviderError> {
        self.native.quarantine()
    }

    fn stage_runtime_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        if !self.supplies_ack {
            return Ok(None);
        }
        Ok(Some(NativeInputAcknowledgement {
            stage_operation: batch.stage_operation().clone(),
            batch: batch.batch().clone(),
            node: batch.node().clone(),
            owners: batch.owners().to_vec(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory().clone(),
            proof_ref: canonical::content_ref(
                b"stage-only-fixture-ack",
                "application/octet-stream",
            )
            .unwrap(),
        }))
    }
}

fn run_stage_only_child(supplies_ack: bool) {
    let executable = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE")
            .expect("set source-built CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"),
    );
    let (graph, _) =
        crate::node_admission::test_fixture_reference_device(fs::read(&executable).unwrap());
    let directory = Directory::new();
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
        activation_id: Id::new("activation/stage-only-child").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: root(0, Phase::BoundaryControl),
    };
    let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::new();
    for node in graph.node_ids() {
        let binding = graph.binding(node).unwrap();
        let native = ReferenceDevice::spawn(
            &executable,
            &directory.0,
            binding.compatibility.execution_owner.id.clone(),
            binding.authority.incarnation_id.clone(),
            binding.authority.owner_generation,
            Duration::from_secs(2),
        )
        .unwrap();
        let child = StageOnlyChild {
            native,
            supplies_ack,
        };
        let mut adapter = ControlledReferenceNode::from_controlled_prepared(
            &graph,
            node,
            child,
            Id::new(REFERENCE_DEVICE_QUANTIZED_PROFILE).unwrap(),
            &|child: &StageOnlyChild, descriptor, binding| {
                NativeQualification.authenticate_child(&child.native, descriptor, binding)
            },
            16,
        )
        .unwrap();
        adapter.arm(&record).unwrap();
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
    let node = Id::new("a").unwrap();
    runtime.scheduler(&graph, &activation).unwrap();
    let observation = runtime.observe_scheduling(&activation, &node).unwrap();
    runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .accept_boundary_observation(observation)
        .unwrap();
    let stage = Id::new("stage/external-ack").unwrap();
    let batch = Id::new("batch/external-ack").unwrap();
    let input = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .prepare_input_batch(
            &node,
            stage.clone(),
            batch.clone(),
            root(1, Phase::BoundaryControl),
        )
        .unwrap();

    if supplies_ack {
        let acknowledged = runtime.stage_inputs(input).unwrap();
        let commit = runtime.commit_input_acknowledgement(acknowledged).unwrap();
        let original = runtime.commit_input_staging(&commit).unwrap_err();
        assert!(
            format!("{original:?}").contains("controlled external input commit is unsupported")
        );
        assert!(runtime.commit_input_staging(&commit).is_err());
        let retained = runtime.recover_input_staging(&activation, &stage).unwrap();
        let recovered = runtime.commit_input_acknowledgement(retained).unwrap();
        assert_eq!(commit.stage_operation(), recovered.stage_operation());
        assert_eq!(commit.batch(), recovered.batch());
        assert_eq!(commit.inventory(), recovered.inventory());
        assert!(runtime.commit_input_staging(&recovered).is_err());
        assert!(
            runtime
                .scheduler(&graph, &activation)
                .unwrap()
                .admit_quantum(
                    &node,
                    Id::new("run/must-stay-closed").unwrap(),
                    Id::new("window/must-stay-closed").unwrap(),
                    batch
                )
                .is_err()
        );
    } else {
        let failure = runtime.stage_inputs(input).unwrap_err();
        assert!(format!("{failure:?}").contains("did not select genuine host-owned input custody"));
        assert!(runtime.recover_input_staging(&activation, &stage).is_err());
    }
    drop(runtime);
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn external_child_staging_ack_cannot_commit_the_original_input_cut() {
    run_stage_only_child(true);
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn absent_child_staging_ack_cannot_select_the_host_owned_fallback() {
    run_stage_only_child(false);
}

//! Adversarial owner-custody and complete-world activation tests.

// crucible-lint: allow panic-shortcut -- These runtime tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{cell::RefCell, task::Waker, time::Duration};

use crucible_node_contract::{
    BindingCompatibility, ContentRef, FacetSelection, HashRef, ImplementationIdentity,
    LiveAuthority, OperatingContract, OperatingMode, OwnerRef, Phase, Position, SchedulingRole,
    U64,
};

use super::*;
use crate::node_contract::{
    ExactBoundaryPolicy, FacetDescription, NativeReclamationReceipt, NodeStatus, PhysicalState,
    ProgressEvidence, PublicationStatus, QuantumClosureEvidence, ReadyAttestation, Refusal,
    StopReason,
};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn position(tick: u64) -> Position {
    Position {
        time_ps: U64::new(tick),
        microstep: U64::new(0),
        phase: Phase::BoundaryControl,
    }
}

fn hash(domain: &str) -> HashRef {
    HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "0".repeat(64),
    }
}

fn blob() -> ContentRef {
    ContentRef {
        hash: hash("cnp.blob.v1"),
        length: U64::new(0),
        media_type: "application/octet-stream".into(),
    }
}

#[derive(Default)]
struct NativeState {
    terminal_failure: Option<EffectKnowledge>,
    terminal_scheduling: Option<crate::node_scheduling::NativeSchedulingObservation>,
    lineage_claim: Option<OriginalPublicationClaim>,
    lineage_required: bool,
    lineage_invalid: bool,
    lineage_reads: usize,
    lineage_validations: usize,
    arm_fail: bool,
    change_declarations_on_arm: bool,
    changed_declarations: bool,
    pending: bool,
    invalid_evidence: bool,
    overshoot: bool,
    refuse: bool,
    uncertain: bool,
    begin_calls: usize,
    poll_calls: usize,
    close_calls: usize,
    ack_calls: usize,
    ack_fail: bool,
    quarantine_calls: usize,
    reclamation_pending: bool,
    invalid_reclamation: bool,
    retained_outputs: Vec<Id>,
    admission: Option<OperationAdmission>,
    scheduling_observation: Option<crate::node_scheduling::NativeSchedulingObservation>,
    evidence_objects: Vec<crate::node_scheduling::InputPayload>,
    evidence_reads: usize,
    evidence_corrupt: bool,
    progress_override: Option<ProgressEvidence>,
    native_capture_calls: usize,
    native_capture_effects: usize,
    native_capture_bytes: Option<Vec<u8>>,
    native_capture_artifacts: Vec<NativeCaptureArtifact>,
    native_capture_limits: Vec<NativeCaptureLimits>,
}

struct TestNode {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    facets: Vec<FacetKind>,
    profile: Id,
    state: Rc<RefCell<NativeState>>,
}

impl FacetDescription for TestNode {
    fn profile(&self) -> &Id {
        &self.profile
    }
}

impl SimulationNode for TestNode {
    fn descriptor(&self) -> &NodeDescriptor {
        &self.descriptor
    }

    fn binding(&self) -> &NodeBinding {
        &self.binding
    }

    fn route(&self) -> &NodeRoute {
        &self.route
    }

    fn thread_affinity(&self) -> crate::node_contract::ThreadAffinity {
        crate::node_contract::ThreadAffinity::OwnerThread(std::thread::current().id())
    }

    fn facets(&self) -> &[FacetKind] {
        if self.state.borrow().changed_declarations {
            &[]
        } else {
            &self.facets
        }
    }

    fn requires_original_input_lineage(
        &self,
        _batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> bool {
        self.state.borrow().lineage_required
    }

    fn original_publication_lineage(
        &self,
        original: &OperationAdmission,
        _outcome: &OperationOutcome,
        _publication: &crate::node_scheduling::NativePublication,
        _limits: OriginalInputLineageLimits,
    ) -> Result<OriginalPublicationClaim, OperationFailure> {
        let mut state = self.state.borrow_mut();
        assert!(
            state
                .admission
                .as_ref()
                .unwrap()
                .token()
                .same_authority(original.token())
        );
        state.lineage_reads += 1;
        state.lineage_claim.clone().ok_or(OperationFailure {
            effects: EffectKnowledge::None,
            reason: "model has no selected lineage".into(),
        })
    }

    fn validate_original_publication_lineage(
        &self,
        original: &OperationAdmission,
        _outcome: &OperationOutcome,
        _publication: &crate::node_scheduling::NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        let mut state = self.state.borrow_mut();
        assert!(
            state
                .admission
                .as_ref()
                .unwrap()
                .token()
                .same_authority(original.token())
        );
        state.lineage_validations += 1;
        if state.lineage_invalid || state.lineage_claim.as_ref() != Some(claim) {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "model rejected original source claim".into(),
            });
        }
        Ok(())
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        Ok(NodeStatus {
            lifecycle: Lifecycle::Stopped,
            physical: PhysicalState::Suspended,
            boundary: Some(position(0)),
        })
    }

    fn arm(&mut self, record: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        if self.state.borrow().arm_fail {
            return Err(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "native ready state unavailable".into(),
            });
        }

        if self.state.borrow().change_declarations_on_arm {
            self.state.borrow_mut().changed_declarations = true;
        }

        Ok(ReadyAttestation {
            owners: self.route.owners.clone(),
            boundary: record.boundary,
            state_inventory: blob(),
            ready_receipt: blob(),
        })
    }

    fn validate_readiness(
        &self,
        _world: &ActivationRecord,
        _readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        Ok(())
    }

    fn observe_terminal(
        &mut self,
        _: &WorldActivation,
        _: usize,
    ) -> Result<crate::node_contract::NativeTerminalInventory, OperationFailure> {
        Err(OperationFailure {
            effects: self
                .state
                .borrow()
                .terminal_failure
                .clone()
                .unwrap_or(EffectKnowledge::None),
            reason: "fixture deliberately refuses native terminal observation".into(),
        })
    }

    fn observe_scheduling(
        &mut self,
        _activation: &WorldActivation,
    ) -> Result<crate::node_scheduling::NativeSchedulingObservation, OperationFailure> {
        self.state
            .borrow()
            .scheduling_observation
            .clone()
            .ok_or(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "model has no retained native observation".into(),
            })
    }

    fn validate_scheduling_observation(
        &self,
        activation: &WorldActivation,
        observation: &crate::node_scheduling::NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        let valid = !self.state.borrow().invalid_evidence
            && self.state.borrow().scheduling_observation.as_ref() == Some(observation)
            && observation.node == self.route.node
            && observation.owners == self.route.owners
            && self
                .route
                .owners
                .iter()
                .all(|owner| activation.record().owners.contains(owner));
        if !valid {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "model retained external FIFO differs from the supplied observation".into(),
            });
        }
        Ok(())
    }

    fn install_restored_custody(
        &mut self,
        activation: &WorldActivation,
        source: &crate::node_contract::RuntimeSnapshot,
        operations: &[OperationAdmission],
        inputs: &[Rc<crate::node_scheduling::RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        // This model-only fixture reattaches coordinator handles after the
        // state tests' separate continuation proof. It never starts work or
        // claims that a QEMU process or native input queue was restored.
        let valid = inputs.is_empty()
            && operations.iter().all(|admission| {
                admission.activation().record() == activation.record()
                    && admission.token().route() == &self.route
                    && source.operations.iter().any(|saved| {
                        &saved.operation == admission.token().operation()
                            && saved.route.node == self.route.node
                            && &saved.request == admission.request()
                    })
            });
        if !valid {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "model fixture has no matching unchanged original continuation".into(),
            });
        }
        self.state.borrow_mut().admission = operations.last().cloned();
        Ok(())
    }

    fn capture_native_continuation(
        &mut self,
        _activation: &WorldActivation,
        source: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        let mut state = self.state.borrow_mut();
        state.native_capture_calls += 1;
        state.native_capture_limits.push(limits);
        let bytes = state
            .native_capture_bytes
            .as_ref()
            .ok_or(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "test model has no native capture codec".into(),
            })?;
        let artifact_bytes: u64 = state
            .native_capture_artifacts
            .iter()
            .map(|artifact| artifact.reference().length.get())
            .sum();
        if bytes.len() > limits.maximum_record_bytes
            || bytes.len() > limits.maximum_total_record_bytes
            || 1 + state.native_capture_artifacts.len() > limits.maximum_objects
            || artifact_bytes > limits.maximum_total_artifact_bytes
            || state
                .native_capture_artifacts
                .iter()
                .any(|artifact| artifact.reference().length.get() > limits.maximum_artifact_bytes)
        {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "model capture refused before its reserved effect".into(),
            });
        }
        let payload = crate::node_scheduling::InputPayload {
            reference: crucible_node_contract::canonical::content_ref(
                bytes,
                "application/octet-stream",
            )
            .unwrap(),
            bytes: bytes.clone(),
        };
        // This counter models the preflight/effect boundary only. Its seal is
        // confined to this custody fixture and never qualifies a native backend.
        state.native_capture_effects += 1;
        Ok(InstalledNativeCapture {
            owner: self.binding.compatibility.capture_owner.id.clone(),
            participants: self
                .binding
                .compatibility
                .capture_owner
                .participant_ids
                .clone(),
            key: NativeStateKey {
                implementation: self
                    .binding
                    .compatibility
                    .implementation
                    .implementation_id
                    .clone(),
                profile: self.profile.clone(),
                schema: self.binding.compatibility.implementation.formats[0].clone(),
            },
            cut: source.capture_cut,
            state: payload,
            evidence: vec![],
            artifacts: state.native_capture_artifacts.clone(),
        })
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        let mut state = self.state.borrow_mut();
        state.begin_calls += 1;
        state.admission = Some(admission.clone());
        if state.refuse {
            return Submission::Refused(Refusal {
                reason: "unsupported native precondition".into(),
            });
        }
        if state.uncertain {
            return Submission::Uncertain(EffectKnowledge::MayHaveProgressed);
        }
        Submission::Accepted
    }

    fn poll_operation(
        &mut self,
        token: &OperationToken,
        _context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        let mut state = self.state.borrow_mut();
        state.poll_calls += 1;
        if state.pending {
            return Poll::Pending;
        }

        let admission = state.admission.as_ref().unwrap();
        let progress = match admission.request() {
            OperationRequest::ExactRun { limit, .. }
            | OperationRequest::BoundarySettle { limit, .. } => ProgressEvidence::Exact {
                reached: if state.overshoot {
                    position(limit.time_ps.get() + 1)
                } else if state.retained_outputs.is_empty() {
                    *limit
                } else {
                    position(limit.time_ps.get() - 1)
                },
                stop: if state.retained_outputs.is_empty() {
                    StopReason::HorizonPark
                } else {
                    StopReason::Output
                },
            },
            OperationRequest::QuantumBegin {
                window,
                end,
                input_batch,
                ..
            } => ProgressEvidence::Quantized {
                window: window.clone(),
                publication: *end,
                physical: PhysicalState::Active,
                closure: Box::new(QuantumClosureEvidence {
                    input_batch: input_batch.clone(),
                    close_receipt: blob(),
                    output_inventory: blob(),
                    pending_inventory: blob(),
                    clock_evidence: blob(),
                }),
            },
            _ => ProgressEvidence::Administrative,
        };
        Poll::Ready(Ok(OperationOutcome {
            operation: token.operation().clone(),
            node: token.route().node.clone(),
            owners: token.route().owners.clone(),
            progress: state.progress_override.clone().unwrap_or(progress),
            retained_outputs: state.retained_outputs.clone(),
            scheduling: state.terminal_scheduling.clone(),
        }))
    }

    fn validate_outcome(
        &self,
        _original: &OperationAdmission,
        _outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        if self.state.borrow().invalid_evidence {
            Err(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "unauthenticated native stop evidence".into(),
            })
        } else {
            Ok(())
        }
    }

    fn read_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure> {
        let mut state = self.state.borrow_mut();
        state.evidence_reads += 1;
        if state
            .admission
            .as_ref()
            .map(OperationAdmission::token)
            .map(OperationToken::operation)
            != Some(original.token().operation())
        {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "model does not own the original evidence operation".into(),
            });
        }
        let mut objects = references
            .iter()
            .map(|reference| {
                state
                    .evidence_objects
                    .iter()
                    .find(|object| &object.reference == reference)
                    .cloned()
                    .ok_or(OperationFailure {
                        effects: EffectKnowledge::None,
                        reason: "model does not retain the requested original object".into(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if state.evidence_corrupt {
            objects[0].bytes.push(0);
        }
        Ok(objects)
    }

    fn validate_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
        objects: &[crate::node_scheduling::InputPayload],
    ) -> Result<(), OperationFailure> {
        let state = self.state.borrow();
        let valid = !state.invalid_evidence
            && state
                .admission
                .as_ref()
                .map(OperationAdmission::token)
                .map(OperationToken::operation)
                == Some(original.token().operation())
            && references.len() == objects.len()
            && objects
                .iter()
                .all(|object| state.evidence_objects.contains(object));
        if !valid {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "model immutable registry has no authentic original custody".into(),
            });
        }
        Ok(())
    }

    fn request_cancel(
        &mut self,
        _token: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure> {
        Ok(CancelStatus::Requested)
    }

    fn close_quantum(&mut self, _original: &OperationAdmission) -> Submission {
        self.state.borrow_mut().close_calls += 1;
        Submission::Accepted
    }

    fn acknowledge_publication(
        &mut self,
        _token: &OperationToken,
        _outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        let mut state = self.state.borrow_mut();
        state.ack_calls += 1;
        if state.ack_fail {
            return Err(OperationFailure {
                effects: EffectKnowledge::CommittedPrefix(state.retained_outputs.clone()),
                reason: "native acknowledgement reply lost".into(),
            });
        }
        Ok(())
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        match kind {
            FacetKind::ExactExecution if self.facets.contains(&kind) => {
                Ok(NodeFacet::ExactExecution(self))
            }
            FacetKind::QuantizedExecution if self.facets.contains(&kind) => {
                Ok(NodeFacet::QuantizedExecution(self))
            }
            _ => Err(Refusal {
                reason: "facet unavailable".into(),
            }),
        }
    }

    fn quarantine_resources(&mut self) {
        self.state.borrow_mut().quarantine_calls += 1;
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        _context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        if self.state.borrow().reclamation_pending {
            return Poll::Pending;
        }
        Poll::Ready(Ok(NativeReclamationReceipt {
            owner: owner.clone(),
            receipt: blob(),
        }))
    }

    fn validate_reclamation(
        &self,
        _receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        if self.state.borrow().invalid_reclamation {
            Err(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "native resource still live".into(),
            })
        } else {
            Ok(())
        }
    }
}

fn test_node(
    name: &str,
    mode: OperatingMode,
) -> (Box<dyn SimulationNode>, Rc<RefCell<NativeState>>) {
    let state = Rc::new(RefCell::new(NativeState::default()));
    let owner = OwnerIdentity {
        owner: id("shared-owner"),
        incarnation: id("native-incarnation"),
        generation: U64::new(1),
    };
    let descriptor = NodeDescriptor {
        schema_version: 1,
        id: id(name),
        roles: vec![id("compute")],
        model_ref: blob(),
        configuration_ref: blob(),
        initialization_ref: blob(),
        ports: vec![],
        extensions: BTreeMap::new(),
    };
    let owner_ref = OwnerRef {
        id: owner.owner.clone(),
        participant_ids: vec![id("a"), id("b")],
        state_domain_ids: vec![id("machine")],
    };
    let binding = NodeBinding {
        compatibility: BindingCompatibility {
            schema_version: 1,
            node_id: id(name),
            descriptor_hash: hash("cnp.node-descriptor.v1"),
            implementation: ImplementationIdentity {
                schema_version: 1,
                implementation_id: id("test-provider"),
                artifacts: vec![],
                model_definitions: vec![],
                formats: vec![],
                extensions: BTreeMap::new(),
            },
            profile_ref: blob(),
            configuration_ref: blob(),
            operating_contract: OperatingContract {
                schema_version: 1,
                mode,
                scheduling_role: SchedulingRole::Active,
                ordering_profile: "superdense-v1".into(),
                policy_ref: blob(),
                resolution_ps: Some(U64::new(1)),
                phase_ps: Some(U64::new(0)),
                facets: vec![FacetSelection {
                    id: id("test-execution"),
                    version: 1,
                    configuration_ref: blob(),
                    guarantees_ref: blob(),
                    extensions: BTreeMap::new(),
                }],
                extensions: BTreeMap::new(),
            },
            execution_owner: owner_ref.clone(),
            capture_owner: owner_ref,
            capabilities_ref: blob(),
            guarantees_ref: blob(),
            qualification_refs: vec![],
            extensions: BTreeMap::new(),
        },
        authority: LiveAuthority {
            schema_version: 1,
            session_id: id("session"),
            incarnation_id: owner.incarnation.clone(),
            realization_id: id("realization"),
            activation_id: None,
            world_generation: U64::new(0),
            owner_generation: owner.generation,
            input_epoch: id("input-epoch"),
            host_receipt: blob(),
            extensions: BTreeMap::new(),
        },
        extensions: BTreeMap::new(),
    };
    let node = TestNode {
        descriptor,
        binding,
        route: NodeRoute {
            node: id(name),
            owners: vec![owner],
        },
        facets: vec![match mode {
            OperatingMode::Exact => FacetKind::ExactExecution,
            OperatingMode::Quantized => FacetKind::QuantizedExecution,
        }],
        profile: id("test-execution"),
        state: Rc::clone(&state),
    };
    (Box::new(node), state)
}

/// Constructs only test-local custody; production construction requires graph admission.
fn runtime(mode: OperatingMode) -> (NodeRuntime, Vec<Rc<RefCell<NativeState>>>) {
    let (a, a_state) = test_node("a", mode);
    let (b, b_state) = test_node("b", mode);
    let nodes = vec![a, b];
    let record = ActivationRecord {
        generation: U64::new(1),
        activation_id: id("activation"),
        world_binding_hash: hash("cnp.world-binding.v1"),
        owners: nodes[0].route().owners.clone(),
        boundary: position(0),
    };
    let owners = record
        .owners
        .iter()
        .cloned()
        .map(|identity| {
            (
                identity.owner.clone(),
                OwnerCustody {
                    identity,
                    lifecycle: Lifecycle::Prepared,
                    operation: None,
                    domains: [id("shared-domain")].into_iter().collect(),
                },
            )
        })
        .collect();
    let snapshots = nodes
        .iter()
        .map(|node| {
            (
                node.route().node.clone(),
                NodeSnapshot {
                    descriptor: node.descriptor().clone(),
                    binding: node.binding().clone(),
                    route: node.route().clone(),
                    facets: node.facets().to_vec(),
                    thread_affinity: node.thread_affinity(),
                },
            )
        })
        .collect();
    let nodes = nodes
        .into_iter()
        .map(|node| (node.route().node.clone(), node))
        .collect();
    let runtime = NodeRuntime {
        authority: Rc::new(()),
        nodes,
        snapshots,
        owners,
        operations: BTreeMap::new(),
        input_batches: BTreeMap::new(),
        barrier: ActivationBarrier::new(record).unwrap(),
        activated: false,
        limits: RuntimeLimits::default(),
        scheduler: None,
        custody_slot: Some(crate::node_contract::test_custody_slot()),
        terminal: None,
        condition_stop: None,
    };
    (runtime, vec![a_state, b_state])
}

struct Publisher {
    disposition: PublicationStatus,
    calls: usize,
}

impl ActivationPublisher for Publisher {
    fn publish(&mut self, _record: &ActivationRecord) -> PublicationStatus {
        self.calls += 1;
        self.disposition
    }

    fn reconcile(&mut self, _record: &ActivationRecord) -> PublicationStatus {
        self.disposition
    }
}

fn activate(runtime: &mut NodeRuntime) -> WorldActivation {
    runtime.arm_all().unwrap();
    runtime
        .activate(&mut Publisher {
            disposition: PublicationStatus::Committed,
            calls: 0,
        })
        .unwrap()
}

fn exact(runtime: &mut NodeRuntime, activation: &WorldActivation, name: &str) -> OperationToken {
    match runtime
        .begin(
            activation,
            &id("a"),
            id(name),
            OperationRequest::ExactRun {
                start: position(0),
                limit: position(10),
                boundary_policy: ExactBoundaryPolicy::HorizonPark,
            },
        )
        .unwrap()
    {
        BeginResult::Accepted(token) => token,
        other => panic!("unexpected submission: {other:?}"),
    }
}

fn poll(
    runtime: &mut NodeRuntime,
    token: &OperationToken,
) -> Poll<Result<OperationOutcome, RuntimePollFailure>> {
    runtime.poll(token, &mut Context::from_waker(Waker::noop()))
}

#[test]
fn incomplete_roster_never_calls_durable_publisher() {
    let (mut runtime, _) = runtime(OperatingMode::Exact);
    let mut publisher = Publisher {
        disposition: PublicationStatus::Committed,
        calls: 0,
    };

    assert!(matches!(
        runtime.activate(&mut publisher),
        Err(RuntimeError::NotActivated)
    ));
    assert_eq!(publisher.calls, 0);
}

#[test]
fn successful_arm_then_failed_rearm_invalidates_activation() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    runtime.arm_all().unwrap();
    state[1].borrow_mut().arm_fail = true;
    assert_eq!(runtime.arm_all(), Err(RuntimeError::InvalidReceipt));

    let mut publisher = Publisher {
        disposition: PublicationStatus::Committed,
        calls: 0,
    };
    assert!(runtime.activate(&mut publisher).is_err());
    assert_eq!(publisher.calls, 0);
    assert_eq!(
        runtime.owner_lifecycle(&id("shared-owner")),
        Some(Lifecycle::Quarantined)
    );
}

#[test]
fn declaration_change_during_arm_never_reaches_publication() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    state[1].borrow_mut().change_declarations_on_arm = true;

    assert_eq!(runtime.arm_all(), Err(RuntimeError::ForeignAuthority));
    let mut publisher = Publisher {
        disposition: PublicationStatus::Committed,
        calls: 0,
    };
    assert!(runtime.activate(&mut publisher).is_err());

    assert_eq!(publisher.calls, 0);
    assert_eq!(state[0].borrow().begin_calls, 0);
    assert_eq!(state[1].borrow().begin_calls, 0);
    assert_eq!(runtime.barrier.retained_nodes().len(), 1);
    assert_eq!(
        runtime.owner_lifecycle(&id("shared-owner")),
        Some(Lifecycle::Quarantined)
    );
}

#[test]
fn declaration_change_after_readiness_never_reaches_publication() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    runtime.arm_all().unwrap();
    state[1].borrow_mut().changed_declarations = true;
    let mut publisher = Publisher {
        disposition: PublicationStatus::Committed,
        calls: 0,
    };

    assert!(matches!(
        runtime.activate(&mut publisher),
        Err(RuntimeError::ForeignAuthority)
    ));

    assert_eq!(publisher.calls, 0);
    assert_eq!(runtime.barrier.retained_nodes().len(), 2);
    assert_eq!(state[0].borrow().begin_calls, 0);
    assert_eq!(state[1].borrow().begin_calls, 0);
}

#[test]
fn uncertain_publication_requires_reconciliation_without_republishing() {
    let (mut runtime, _) = runtime(OperatingMode::Exact);
    runtime.arm_all().unwrap();
    let mut publisher = Publisher {
        disposition: PublicationStatus::Unknown,
        calls: 0,
    };
    assert!(runtime.activate(&mut publisher).is_err());
    publisher.disposition = PublicationStatus::Committed;
    assert!(runtime.activate(&mut publisher).is_err());
    assert_eq!(publisher.calls, 1);

    let activation = runtime.reconcile_activation(&mut publisher).unwrap();
    assert_eq!(activation.record().generation, U64::new(1));
    assert_eq!(publisher.calls, 1);
}

#[test]
fn shared_owner_remains_reserved_after_token_drop_and_cancellation() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    let token = exact(&mut runtime, &activation, "run-1");
    state[0].borrow_mut().pending = true;
    assert_eq!(runtime.cancel(&token).unwrap(), CancelStatus::Requested);
    drop(token);

    let recovered = runtime.recover(&id("run-1")).unwrap();
    assert!(matches!(poll(&mut runtime, &recovered), Poll::Pending));
    assert!(matches!(
        runtime.begin(
            &activation,
            &id("b"),
            id("run-2"),
            OperationRequest::Observe
        ),
        Err(RuntimeError::OwnerBusy)
    ));
    assert_eq!(state[0].borrow().begin_calls, 1);
    assert_eq!(state[1].borrow().begin_calls, 0);
}

#[test]
fn foreign_activation_and_tokens_cannot_reuse_equal_identifiers() {
    let (mut first, _) = runtime(OperatingMode::Exact);
    let (mut second, state) = runtime(OperatingMode::Exact);
    let first_activation = activate(&mut first);
    let second_activation = activate(&mut second);
    assert_eq!(first_activation.record(), second_activation.record());

    assert!(matches!(
        second.begin(
            &first_activation,
            &id("a"),
            id("run"),
            OperationRequest::Observe
        ),
        Err(RuntimeError::ForeignAuthority)
    ));
    let token = exact(&mut first, &first_activation, "run");
    assert!(matches!(
        poll(&mut second, &token),
        Poll::Ready(Err(RuntimePollFailure::Admission(
            RuntimeError::ForeignAuthority
        )))
    ));
    assert_eq!(state[0].borrow().begin_calls, 0);
}

#[test]
fn no_effect_refusal_releases_owner_but_retains_used_operation_identity() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    state[0].borrow_mut().refuse = true;
    assert!(matches!(
        runtime
            .begin(
                &activation,
                &id("a"),
                id("refused"),
                OperationRequest::Observe
            )
            .unwrap(),
        BeginResult::Refused(_)
    ));
    assert_eq!(
        runtime.owner_lifecycle(&id("shared-owner")),
        Some(Lifecycle::Stopped)
    );
    assert!(matches!(
        runtime.begin(
            &activation,
            &id("b"),
            id("refused"),
            OperationRequest::Observe
        ),
        Err(RuntimeError::DuplicateOperation)
    ));
    assert!(matches!(
        runtime
            .begin(&activation, &id("b"), id("next"), OperationRequest::Observe)
            .unwrap(),
        BeginResult::Accepted(_)
    ));
}

#[test]
fn uncertain_submission_retains_original_operation_and_contains_shared_owner() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    state[0].borrow_mut().uncertain = true;
    let token = match runtime
        .begin(
            &activation,
            &id("a"),
            id("uncertain"),
            OperationRequest::Observe,
        )
        .unwrap()
    {
        BeginResult::Uncertain {
            token,
            effects: EffectKnowledge::MayHaveProgressed,
        } => token,
        other => panic!("unexpected submission: {other:?}"),
    };

    assert_eq!(
        runtime.recover(token.operation()).unwrap().operation(),
        token.operation()
    );
    assert_eq!(
        runtime.owner_lifecycle(&id("shared-owner")),
        Some(Lifecycle::Quarantined)
    );
    assert!(matches!(
        runtime.begin(
            &activation,
            &id("b"),
            id("retry"),
            OperationRequest::Observe
        ),
        Err(RuntimeError::OwnerBusy)
    ));
}

#[test]
fn outputs_remain_retained_until_exact_acknowledgement_and_retries_are_idempotent() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    state[0].borrow_mut().retained_outputs = vec![id("output-1")];
    let token = exact(&mut runtime, &activation, "run");
    assert!(matches!(poll(&mut runtime, &token), Poll::Ready(Ok(_))));
    assert!(matches!(poll(&mut runtime, &token), Poll::Ready(Ok(_))));
    assert_eq!(state[0].borrow().poll_calls, 1);
    assert_eq!(runtime.cancel(&token).unwrap(), CancelStatus::Terminal);

    assert!(runtime.acknowledge(&token, &[]).is_err());
    assert_eq!(
        runtime.owner_lifecycle(&id("shared-owner")),
        Some(Lifecycle::Executing)
    );
    runtime.acknowledge(&token, &[id("output-1")]).unwrap();
    runtime.acknowledge(&token, &[id("output-1")]).unwrap();
    assert_eq!(state[0].borrow().ack_calls, 1);
    assert_eq!(
        runtime.owner_lifecycle(&id("shared-owner")),
        Some(Lifecycle::Stopped)
    );
}

#[test]
fn authentic_receipt_rejection_and_overshoot_both_quarantine_without_clamping() {
    for invalid_evidence in [false, true] {
        let (mut runtime, state) = runtime(OperatingMode::Exact);
        let activation = activate(&mut runtime);
        state[0].borrow_mut().overshoot = !invalid_evidence;
        state[0].borrow_mut().invalid_evidence = invalid_evidence;
        let token = exact(&mut runtime, &activation, "run");

        assert!(matches!(
            poll(&mut runtime, &token),
            Poll::Ready(Err(RuntimePollFailure::Admission(
                RuntimeError::InvalidReceipt
            )))
        ));
        assert_eq!(
            runtime.owner_lifecycle(&id("shared-owner")),
            Some(Lifecycle::Quarantined)
        );
        assert!(runtime.acknowledge(&token, &[]).is_err());
        assert_eq!(state[0].borrow().ack_calls, 0);
    }
}

fn quantum(runtime: &mut NodeRuntime, activation: &WorldActivation) -> OperationToken {
    match runtime
        .begin(
            activation,
            &id("a"),
            id("quantum"),
            OperationRequest::QuantumBegin {
                window: id("window"),
                start: position(0),
                end: position(1000),
                input_batch: id("closed-input-batch"),
                host_budget: Duration::from_millis(1),
            },
        )
        .unwrap()
    {
        BeginResult::Accepted(token) => token,
        other => panic!("unexpected submission: {other:?}"),
    }
}

#[test]
fn quantized_completion_before_original_close_is_not_a_valid_receipt() {
    let (mut runtime, _) = runtime(OperatingMode::Quantized);
    let activation = activate(&mut runtime);
    let token = quantum(&mut runtime, &activation);

    assert!(matches!(
        poll(&mut runtime, &token),
        Poll::Ready(Err(RuntimePollFailure::Admission(
            RuntimeError::InvalidReceipt
        )))
    ));
    assert_eq!(
        runtime.owner_lifecycle(&id("shared-owner")),
        Some(Lifecycle::Quarantined)
    );
}

#[test]
fn quantum_closes_original_once_and_does_not_infer_physical_pause() {
    let (mut runtime, state) = runtime(OperatingMode::Quantized);
    let activation = activate(&mut runtime);
    let token = quantum(&mut runtime, &activation);
    assert_eq!(runtime.close_quantum(&token).unwrap(), Submission::Accepted);
    assert_eq!(runtime.close_quantum(&token).unwrap(), Submission::Accepted);
    assert_eq!(state[0].borrow().close_calls, 1);

    let outcome = match poll(&mut runtime, &token) {
        Poll::Ready(Ok(outcome)) => outcome,
        other => panic!("unexpected quantum outcome: {other:?}"),
    };
    assert!(matches!(
        outcome.progress,
        ProgressEvidence::Quantized {
            physical: PhysicalState::Active,
            ..
        }
    ));
    runtime.acknowledge(&token, &[]).unwrap();
    assert_eq!(
        runtime.owner_lifecycle(&id("shared-owner")),
        Some(Lifecycle::Stopped)
    );
}

#[test]
fn unsupported_pause_and_mode_confusion_refuse_before_native_dispatch() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    assert!(matches!(
        runtime.begin(&activation, &id("a"), id("pause"), OperationRequest::Pause),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert!(matches!(
        runtime.begin(
            &activation,
            &id("a"),
            id("close"),
            OperationRequest::QuantumClose {
                window: id("unknown-window")
            }
        ),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert_eq!(state[0].borrow().begin_calls, 0);
}

#[test]
fn quarantine_retains_pending_native_custody_until_authentic_reclamation() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    let _token = exact(&mut runtime, &activation, "outstanding");
    state[0].borrow_mut().reclamation_pending = true;
    let mut quarantine = runtime.into_quarantine();
    assert_eq!(quarantine.remaining_owners(), 1);
    assert!(matches!(
        quarantine.poll_reclamation(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    assert_eq!(quarantine.remaining_owners(), 1);

    state[0].borrow_mut().reclamation_pending = false;
    state[0].borrow_mut().invalid_reclamation = true;
    assert!(matches!(
        quarantine.poll_reclamation(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(_))
    ));
    assert_eq!(quarantine.remaining_owners(), 1);

    state[0].borrow_mut().invalid_reclamation = false;
    assert!(matches!(
        quarantine.poll_reclamation(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(quarantine.remaining_owners(), 0);
}

#[test]
fn abandoning_runtime_invokes_native_supervision_for_every_handle() {
    let (runtime, state) = runtime(OperatingMode::Exact);
    drop(runtime);
    assert_eq!(state[0].borrow().quarantine_calls, 1);
    assert_eq!(state[1].borrow().quarantine_calls, 1);
}

#[test]
fn operation_and_output_resource_limits_preserve_owner_custody() {
    let (mut runtime, state) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    runtime.limits.maximum_operations = 0;
    assert!(matches!(
        runtime.begin(
            &activation,
            &id("a"),
            id("no-capacity"),
            OperationRequest::Observe
        ),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(state[0].borrow().begin_calls, 0);

    runtime.limits.maximum_operations = 1;
    runtime.limits.maximum_retained_outputs = 0;
    state[0].borrow_mut().retained_outputs = vec![id("unreserved-output")];
    let token = exact(&mut runtime, &activation, "bounded");
    assert!(matches!(poll(&mut runtime, &token), Poll::Ready(Err(_))));
    assert_eq!(
        runtime.owner_lifecycle(&id("shared-owner")),
        Some(Lifecycle::Quarantined)
    );
    assert_eq!(state[0].borrow().ack_calls, 0);
}

type AdmittedRuntimeParts = (
    crate::node_admission::AdmittedGraph,
    Vec<Box<dyn SimulationNode>>,
    Vec<Rc<RefCell<NativeState>>>,
    ActivationRecord,
);

fn admitted_parts() -> AdmittedRuntimeParts {
    let (graph, _) = crate::node_admission::test_fixture_with_content();
    admitted_parts_from_graph(graph)
}

fn admitted_parts_from_graph(graph: crate::node_admission::AdmittedGraph) -> AdmittedRuntimeParts {
    let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::new();
    let mut states = Vec::new();
    let mut owners = Vec::new();
    for node_id in graph.node_ids() {
        let binding = graph.binding(node_id).unwrap().clone();
        let owner = OwnerIdentity {
            owner: binding.compatibility.execution_owner.id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        };
        let state = Rc::new(RefCell::new(NativeState::default()));
        let node = TestNode {
            descriptor: graph.descriptor(node_id).unwrap().clone(),
            binding,
            route: NodeRoute {
                node: node_id.clone(),
                owners: vec![owner.clone()],
            },
            facets: if graph
                .binding(node_id)
                .unwrap()
                .compatibility
                .operating_contract
                .facets
                .iter()
                .any(|facet| facet.id == id("test-execution"))
            {
                vec![FacetKind::ExactExecution]
            } else {
                vec![]
            },
            profile: id("test-execution"),
            state: Rc::clone(&state),
        };
        owners.push(owner);
        nodes.push(Box::new(node));
        states.push(state);
    }
    let record = ActivationRecord {
        generation: U64::new(1),
        activation_id: id("actual-admitted-activation"),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: position(0),
    };
    (graph, nodes, states, record)
}

pub(super) fn test_nodes(
    graph: &crate::node_admission::AdmittedGraph,
) -> Vec<Box<dyn SimulationNode>> {
    graph
        .node_ids()
        .map(|node_id| {
            let binding = graph.binding(node_id).unwrap().clone();
            let owner = OwnerIdentity {
                owner: binding.compatibility.execution_owner.id.clone(),
                incarnation: binding.authority.incarnation_id.clone(),
                generation: binding.authority.owner_generation,
            };
            Box::new(TestNode {
                descriptor: graph.descriptor(node_id).unwrap().clone(),
                binding,
                route: NodeRoute {
                    node: node_id.clone(),
                    owners: vec![owner],
                },
                facets: if graph
                    .binding(node_id)
                    .unwrap()
                    .compatibility
                    .operating_contract
                    .facets
                    .iter()
                    .any(|facet| facet.id == id("test-execution"))
                {
                    vec![FacetKind::ExactExecution]
                } else {
                    vec![]
                },
                profile: id("test-execution"),
                state: Rc::new(RefCell::new(NativeState::default())),
            }) as Box<dyn SimulationNode>
        })
        .collect()
}

#[test]
fn graph_mismatch_returns_owned_handles_and_cleanup_remains_supervised() {
    let (graph, nodes, states, mut record) = admitted_parts();
    record.owners[0].incarnation = id("foreign-incarnation");
    let failure = match NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("mismatched owner incarnation must refuse"),
    };
    assert_eq!(failure.error, RuntimeError::InvalidRoute);
    assert_eq!(failure.nodes.len(), 2);
    assert_eq!(states[0].borrow().quarantine_calls, 0);

    drop(failure);
    assert_eq!(states[0].borrow().quarantine_calls, 1);
    assert_eq!(states[1].borrow().quarantine_calls, 1);
}

#[test]
fn complete_graph_activation_retains_one_scheduler_instead_of_resetting_cursors() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let (graph, nodes, _states, record) = admitted_parts_from_graph(graph);
    let mut runtime = match NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    ) {
        Ok(runtime) => runtime,
        Err(failure) => panic!("valid admitted roster refused: {}", failure.error),
    };
    let activation = activate(&mut runtime);
    let admission = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("a"), id("reserved-before-borrow-drop"), U64::new(10))
        .unwrap();

    let scheduler = runtime.scheduler(&graph, &activation).unwrap();
    assert!(
        scheduler
            .admit_exact(&id("a"), id("conflicting-after-borrow-drop"), U64::new(10))
            .is_err()
    );
    scheduler.abandon_undispatched(admission).unwrap();
    assert!(
        scheduler
            .admit_exact(&id("a"), id("new-original-operation"), U64::new(10))
            .is_ok()
    );
}

#[test]
fn admitted_shared_state_domain_blocks_disjoint_owner_routes_before_effects() {
    let (graph, _) = crate::node_admission::test_fixture_with_execution(true);
    let nodes = test_nodes(&graph);
    let owners = nodes
        .iter()
        .flat_map(|node| node.route().owners.iter().cloned())
        .collect();
    let record = ActivationRecord {
        generation: U64::new(1),
        activation_id: id("shared-domain-activation"),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: position(0),
    };
    let mut runtime = match NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    ) {
        Ok(runtime) => runtime,
        Err(failure) => panic!("admitted shared-domain graph refused: {}", failure.error),
    };
    let activation = activate(&mut runtime);
    assert!(matches!(
        runtime.begin(
            &activation,
            &id("a"),
            id("observe-a"),
            OperationRequest::Observe
        ),
        Ok(BeginResult::Accepted(_))
    ));
    assert!(matches!(
        runtime.begin(
            &activation,
            &id("z"),
            id("observe-z"),
            OperationRequest::Observe
        ),
        Err(RuntimeError::OwnerBusy)
    ));
    assert_eq!(
        runtime.owner_lifecycle(&id("owner/z")),
        Some(Lifecycle::Stopped)
    );
}

#[test]
fn dropped_commit_after_native_ack_failure_recovers_without_republication() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let (graph, nodes, states, record) = admitted_parts_from_graph(graph);
    let mut runtime = NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .unwrap_or_else(|failure| panic!("valid graph refused: {}", failure.error));
    let activation = activate(&mut runtime);
    let grant = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("a"), id("run/a"), U64::new(100))
        .unwrap();
    let token = match runtime.begin_admitted(grant).unwrap() {
        BeginResult::Accepted(token) => token,
        _ => panic!("qualified model should accept original grant"),
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        runtime.poll(&token, &mut context),
        Poll::Ready(Ok(_))
    ));
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    states[0].borrow_mut().ack_fail = true;
    assert!(runtime.acknowledge_scheduled(&token, &commit).is_err());
    drop(commit);
    drop(token);

    let recovered_token = runtime.recover(&id("run/a")).unwrap();
    let recovered_commit = runtime.recover_scheduling_commit(&recovered_token).unwrap();
    // Re-reading terminal evidence returns the same original committed inventory.
    let receipt = runtime.scheduling_receipt(&recovered_token).unwrap();
    let duplicate_commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    assert_eq!(recovered_commit.operation(), duplicate_commit.operation());
    states[0].borrow_mut().ack_fail = false;
    runtime
        .acknowledge_scheduled(&recovered_token, &recovered_commit)
        .unwrap();
    runtime
        .acknowledge_scheduled(&recovered_token, &duplicate_commit)
        .unwrap();
    assert_eq!(states[0].borrow().begin_calls, 1);
    assert_eq!(states[0].borrow().poll_calls, 1);
    assert_eq!(states[0].borrow().ack_calls, 2);
    assert_eq!(
        runtime.owner_lifecycle(&id("owner/a")),
        Some(Lifecycle::Stopped)
    );
}

#[path = "../node_dispatch/runtime_tests.rs"]
mod dispatch_tests;

#[path = "runtime_continuation/native_capture_tests.rs"]
mod native_capture_tests;

#[test]
fn declared_external_root_requires_runtime_native_inventory_before_input_closure() {
    use crate::node_scheduling::{
        NativeExternalInput, NativeExternalInputInventory, NativeOutputBound, NativeProducerBound,
        NativeSchedulingObservation,
    };
    use crucible_node_contract::Endpoint;

    let (graph, _) = crate::node_admission::test_fixture_with_content();
    let (graph, nodes, states, record) = admitted_parts_from_graph(graph);
    let owners = nodes[0].route().owners.clone();
    let mut runtime = NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut Publisher {
            disposition: PublicationStatus::Committed,
            calls: 0,
        })
        .unwrap();
    assert!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .admit_exact(&id("a"), id("unknown-input"), 100.into())
            .is_err()
    );
    assert!(runtime.observe_scheduling(&activation, &id("a")).is_err());

    let root = Endpoint {
        node_id: id("a"),
        port_id: id("data"),
        lane_id: id("input"),
    };
    let payload = b"root";
    let evidence = crucible_node_contract::canonical::content_ref(
        b"retained model FIFO",
        "application/octet-stream",
    )
    .unwrap();
    let mut publication = position(10);
    publication.phase = Phase::Publication;
    states[0].borrow_mut().scheduling_observation = Some(NativeSchedulingObservation {
        node: id("a"),
        owners,
        reached: position(0),
        closed_prefix: position(0),
        bounds: vec![NativeProducerBound {
            producer: id("a"),
            bound: NativeOutputBound::Unknown,
            proof_ref: evidence.clone(),
        }],
        publications: Vec::new(),
        input_progress: None,
        external_inputs: vec![NativeExternalInputInventory {
            endpoint: root.clone(),
            closed_before: position(101),
            inputs: vec![NativeExternalInput {
                event_id: id("native-root/1"),
                native_sequence: 0.into(),
                publication,
                payload: crucible_node_contract::canonical::content_ref(
                    payload,
                    "application/octet-stream",
                )
                .unwrap(),
                payload_bytes: payload.to_vec(),
                provenance_ref: evidence.clone(),
            }],
            proof_ref: evidence.clone(),
        }],
        proof_ref: evidence,
    });
    let observation = runtime.observe_scheduling(&activation, &id("a")).unwrap();
    runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .accept_boundary_observation(observation)
        .unwrap();
    let replay = runtime.observe_scheduling(&activation, &id("a")).unwrap();
    runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .accept_boundary_observation(replay)
        .unwrap();
    let snapshot = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .snapshot(position(0), 1.into())
        .unwrap();

    assert_eq!(snapshot.pending_deliveries.len(), 1);
    assert_eq!(snapshot.pending_deliveries[0].external_root, Some(root));
    assert_eq!(snapshot.pending_deliveries[0].connection_id, None);
    assert_eq!(states[0].borrow().begin_calls, 0);
    assert_eq!(
        states[0]
            .borrow()
            .scheduling_observation
            .as_ref()
            .unwrap()
            .external_inputs[0]
            .inputs[0]
            .payload_bytes,
        payload
    );
    states[0].borrow_mut().invalid_evidence = true;
    assert!(runtime.observe_scheduling(&activation, &id("a")).is_err());
    assert_eq!(
        runtime.owner_lifecycle(&id("owner/a")),
        Some(Lifecycle::Quarantined)
    );
}

#[path = "runtime_evidence_tests.rs"]
mod evidence_tests;

#[path = "runtime_terminal_tests.rs"]
mod terminal;

// This fixture injects classified read failure, never qualified native EOF.
pub(super) fn terminal_read_failure_fixture(
    effects: EffectKnowledge,
) -> (NodeRuntime, WorldActivation) {
    let (mut runtime, native) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    native[0].borrow_mut().terminal_failure = Some(effects);
    (runtime, activation)
}

#[path = "runtime_original_input_lineage_models.rs"]
mod original_lineage_models;

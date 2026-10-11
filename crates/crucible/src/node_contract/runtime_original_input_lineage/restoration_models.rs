//! Models context gates using explicitly synthetic native journal validators.
//!
//! Byte-authenticated content here is test-local. These models do not qualify a
//! source package, native capture, restored class or an ordinary Runtime7 codec.

use super::*;
use crate::node_scheduling::{SavedOwner, SchedulingSnapshot};
use crate::node_state::{VerifiedStateContent, synthetic_typed_content};

struct Model {
    runtime: NodeRuntime,
    states: Vec<Rc<RefCell<NativeState>>>,
    record: OriginalLineageRuntimeRecord,
    source: ContentRef,
    content: VerifiedStateContent,
    scheduling: SchedulingSnapshot,
    target: ActivationRecord,
}

#[test]
fn original_lineage_context_refuses_changed_original_scheduler_before_effects()
-> Result<(), RuntimeError> {
    let model = Model::new();
    let mut verifier = Verifier::new(&model);
    let context = model.prepare(&mut verifier)?;
    context.validate_original_scheduler(&model.scheduling)?;

    let mut changed = model.scheduling.clone();
    changed.capture_ordinal = (changed.capture_ordinal.get() + 1).into();
    assert!(matches!(
        context.validate_original_scheduler(&changed),
        Err(RuntimeError::InvalidReceipt)
    ));
    model.no_native_effects();
    Ok(())
}

#[test]
fn original_lineage_context_refuses_other_typed_role_before_original_body_read()
-> Result<(), RuntimeError> {
    let model = Model::new();
    let mut verifier = Verifier::new(&model);
    let mut other_role = model.source.clone();
    other_role.media_type = "application/json".into();

    assert!(matches!(
        model.runtime.prepare_original_lineage_restoration(
            &other_role,
            &model.content,
            &model.scheduling,
            &model.target,
            &mut verifier,
            OriginalLineageRestorationLimits {
                lineage: OriginalInputLineageLimits::default(),
                maximum_record_bytes: 1024 * 1024,
            },
        ),
        Err(RuntimeError::InvalidReceipt)
    ));
    assert_eq!(verifier.calls, 0);
    model.no_native_effects();
    Ok(())
}

impl Model {
    fn new() -> Self {
        let (_, lineage, record) = preservation_record();
        let mut objects = lineage.publications()[0].objects.clone();
        // crucible-lint: allow panic-shortcut -- the finite typed synthetic record must serialize so malformed authority is tested separately.
        let bytes = canonical::canonical_json(&serde_json::to_value(&record).unwrap()).unwrap();
        let source = canonical::content_ref(
            &bytes,
            "application/vnd.crucible.runtime-original-lineage+json;version=7",
        )
        // crucible-lint: allow panic-shortcut -- the preceding closed synthetic fixture conversion must succeed for this control to test restoration authority.
        .unwrap();
        objects.push(InputPayload {
            reference: source.clone(),
            bytes,
        });
        // crucible-lint: allow panic-shortcut -- the explicitly generated typed fixture bodies must authenticate before this authority control.
        let content = synthetic_typed_content(&objects).unwrap();

        let (mut runtime, states) = runtime(OperatingMode::Quantized);
        let mut target = runtime.barrier.record().clone();
        target.generation = 2.into();
        target.activation_id = id("fresh-restoration");
        target.boundary = record.capture_cut;
        for owner in &mut target.owners {
            owner.incarnation = id("fresh-native-incarnation");
            owner.generation = 2.into();
        }
        for (node_id, original) in &mut runtime.nodes {
            let owner = target.owners[0].clone();
            let mut binding = original.binding().clone();
            binding.authority.incarnation_id = owner.incarnation.clone();
            binding.authority.owner_generation = owner.generation;
            let state = if node_id == &id("a") {
                &states[0]
            } else {
                &states[1]
            };
            state.borrow_mut().lineage_restoration_supported = true;
            let fresh = TestNode {
                descriptor: original.descriptor().clone(),
                binding,
                route: NodeRoute {
                    node: node_id.clone(),
                    owners: vec![owner],
                },
                facets: original.facets().to_vec(),
                profile: id("test-execution"),
                state: Rc::clone(state),
            };
            // crucible-lint: allow panic-shortcut -- the closed two-node fixture must retain the original participant and owner roster.
            let snapshot = runtime.snapshots.get_mut(node_id).unwrap();
            snapshot.binding = fresh.binding.clone();
            snapshot.route = fresh.route.clone();
            *original = Box::new(fresh);
        }
        // crucible-lint: allow panic-shortcut -- the closed two-node fixture must retain the original participant and owner roster.
        runtime.owners.values_mut().next().unwrap().identity = target.owners[0].clone();
        // crucible-lint: allow panic-shortcut -- the synthetic target barrier must validate before the separately mutated scope is tested.
        runtime.barrier = ActivationBarrier::new(target.clone()).unwrap();
        let scheduling = SchedulingSnapshot {
            schema_version: 1,
            original_epochs: None,
            ordering_profile: "superdense-v1".into(),
            world_binding_hash: record.source_activation.world_binding_hash.clone(),
            source_activation_id: record.source_activation.activation_id.clone(),
            source_generation: record.source_activation.generation,
            source_boundary: record.source_activation.boundary,
            capture_cut: record.capture_cut,
            capture_ordinal: record.capture_ordinal,
            source_owners: record
                .owners
                .iter()
                .map(|owner| SavedOwner {
                    owner: owner.identity.owner.clone(),
                    incarnation: owner.identity.incarnation.clone(),
                    generation: owner.identity.generation,
                })
                .collect(),
            maximum_microsteps: 1000.into(),
            positions: vec![],
            producers: vec![],
            native_sequences: vec![],
            external_closed_prefixes: vec![],
            payload_objects: vec![],
            pending_deliveries: vec![],
            used_operations: vec![],
            reservations: vec![],
            input_batches: vec![],
            used_input_batches: vec![],
        };
        Self {
            runtime,
            states,
            record,
            source,
            content,
            scheduling,
            target,
        }
    }

    fn reauthenticate_record(&mut self) {
        let mut objects = Vec::new();
        // crucible-lint: allow panic-shortcut -- the preservation fixture must include the original lineage being mutated by this control.
        for publication in &self.record.inputs[0].lineage.as_ref().unwrap().publications {
            for reference in &publication.objects {
                objects.push(InputPayload {
                    reference: reference.clone(),
                    // crucible-lint: allow panic-shortcut -- the synthetic source body must exist before reconstructing its changed signed-data control.
                    bytes: self.content.get(reference).unwrap().to_vec(),
                });
            }
        }
        let bytes =
            // crucible-lint: allow panic-shortcut -- the finite typed synthetic record must serialize so malformed authority is tested separately.
            canonical::canonical_json(&serde_json::to_value(&self.record).unwrap()).unwrap();
        self.source = canonical::content_ref(
            &bytes,
            "application/vnd.crucible.runtime-original-lineage+json;version=7",
        )
        // crucible-lint: allow panic-shortcut -- the preceding closed synthetic fixture conversion must succeed for this control to test restoration authority.
        .unwrap();
        objects.push(InputPayload {
            reference: self.source.clone(),
            bytes,
        });
        // crucible-lint: allow panic-shortcut -- the explicitly generated typed fixture bodies must authenticate before this authority control.
        self.content = synthetic_typed_content(&objects).unwrap();
    }

    fn advance_capture_and_target(&mut self) {
        // Only host-side historical metadata is rebound in this synthetic model.
        // Original Event/native evidence bodies and first-sealed scope stay exact.
        self.record.source_activation = (&self.target).into();
        for saved in &mut self.record.owners {
            saved.identity = self.target.owners[0].clone();
        }
        for operation in &mut self.record.operations {
            operation.route.owners = self.target.owners.clone();
            if let SavedRuntimeResult::Complete(outcome)
            | SavedRuntimeResult::Acknowledged(outcome) = &mut operation.result
            {
                outcome.owners = self.target.owners.clone();
                if let Some(observation) = &mut outcome.scheduling {
                    observation.owners = self.target.owners.clone();
                }
            }
        }
        for input in &mut self.record.inputs {
            input.owners = self.target.owners.clone();
        }
        self.scheduling.source_activation_id = self.target.activation_id.clone();
        self.scheduling.source_generation = self.target.generation;
        self.scheduling.source_boundary = self.target.boundary;
        for owner in &mut self.scheduling.source_owners {
            owner.incarnation = self.target.owners[0].incarnation.clone();
            owner.generation = self.target.owners[0].generation;
        }
        self.target.activation_id = id("third-activation");
        self.target.generation = 3.into();
        self.target.owners[0].incarnation = id("third-native-incarnation");
        self.target.owners[0].generation = 3.into();
        for (node_id, native) in &mut self.runtime.nodes {
            let state = if node_id == &id("a") {
                &self.states[0]
            } else {
                &self.states[1]
            };
            let mut binding = native.binding().clone();
            binding.authority.incarnation_id = self.target.owners[0].incarnation.clone();
            binding.authority.owner_generation = self.target.owners[0].generation;
            let fresh = TestNode {
                descriptor: native.descriptor().clone(),
                binding,
                route: NodeRoute {
                    node: node_id.clone(),
                    owners: self.target.owners.clone(),
                },
                facets: native.facets().to_vec(),
                profile: id("test-execution"),
                state: Rc::clone(state),
            };
            // crucible-lint: allow panic-shortcut -- the closed two-node fixture must retain the original participant and owner roster.
            let snapshot = self.runtime.snapshots.get_mut(node_id).unwrap();
            snapshot.binding = fresh.binding.clone();
            snapshot.route = fresh.route.clone();
            *native = Box::new(fresh);
        }
        // crucible-lint: allow panic-shortcut -- the closed two-node fixture must retain the original participant and owner roster.
        self.runtime.owners.values_mut().next().unwrap().identity = self.target.owners[0].clone();
        // crucible-lint: allow panic-shortcut -- the synthetic target barrier must validate before the separately mutated scope is tested.
        self.runtime.barrier = ActivationBarrier::new(self.target.clone()).unwrap();
        self.reauthenticate_record();
    }

    fn scope(&self) -> OriginalLineageNativeScope {
        OriginalLineageNativeScope {
            input_acknowledgements: Vec::new(),
            coordinator_schema: 7,
            source_record: self.source.clone(),
            source_capture: self.record.source_activation.clone(),
            target: self.target.clone(),
            owners: self
                .record
                .owners
                .iter()
                .zip(&self.target.owners)
                .map(|(source, target)| OriginalLineageOwnerMapping {
                    source: source.identity.clone(),
                    target: target.clone(),
                })
                .collect(),
            first_scopes: self
                .record
                .inputs
                .iter()
                .filter_map(|input| input.lineage.as_ref().map(|lineage| lineage.source.clone()))
                .collect(),
            journals: self
                .runtime
                .snapshots
                .keys()
                .map(|node| OriginalLineageJournal {
                    node: node.clone(),
                    operations: self
                        .record
                        .operations
                        .iter()
                        .filter(|entry| &entry.route.node == node)
                        .map(|entry| entry.operation.clone())
                        .collect(),
                    pending_operations: self
                        .record
                        .operations
                        .iter()
                        .filter(|entry| {
                            &entry.route.node == node
                                && matches!(entry.result, SavedRuntimeResult::Pending)
                        })
                        .map(|entry| entry.operation.clone())
                        .collect(),
                    acknowledged_operations: self
                        .record
                        .operations
                        .iter()
                        .filter(|entry| {
                            &entry.route.node == node
                                && matches!(entry.result, SavedRuntimeResult::Acknowledged(_))
                        })
                        .map(|entry| entry.operation.clone())
                        .collect(),
                    input_stages: self
                        .record
                        .inputs
                        .iter()
                        .filter(|input| &input.node == node)
                        .map(|input| input.stage_operation.clone())
                        .collect(),
                })
                .collect(),
            proof: self.source.clone(),
        }
    }

    fn prepare<'a>(
        &'a self,
        verifier: &mut Verifier,
    ) -> Result<OriginalLineageRestoration<'a>, RuntimeError> {
        self.runtime.prepare_original_lineage_restoration(
            &self.source,
            &self.content,
            &self.scheduling,
            &self.target,
            verifier,
            OriginalLineageRestorationLimits {
                lineage: OriginalInputLineageLimits::default(),
                maximum_record_bytes: 1024 * 1024,
            },
        )
    }

    fn no_native_effects(&self) {
        for state in &self.states {
            let state = state.borrow();
            assert_eq!(
                (
                    state.begin_calls,
                    state.poll_calls,
                    state.close_calls,
                    state.ack_calls
                ),
                (0, 0, 0, 0)
            );
        }
        assert!(!self.runtime.activated);
        assert!(self.runtime.operations.is_empty());
        assert!(self.runtime.input_batches.is_empty());
    }
}

struct Verifier {
    scope: OriginalLineageNativeScope,
    calls: usize,
    supported: bool,
}

impl Verifier {
    fn new(model: &Model) -> Self {
        Self {
            scope: model.scope(),
            calls: 0,
            supported: true,
        }
    }
}

impl NativeRuntimeContinuationVerifier for Verifier {
    fn verify_original_lineage_scope(
        &mut self,
        _: &ContentRef,
        _: &OriginalLineageRuntimeRecord,
        _: &SchedulingSnapshot,
        _: &ActivationRecord,
        _: RuntimeLimits,
    ) -> Result<OriginalLineageNativeScope, RuntimeError> {
        self.calls += 1;
        if self.supported {
            Ok(self.scope.clone())
        } else {
            Err(RuntimeError::UnsupportedFacet)
        }
    }

    fn verify_runtime_continuation(
        &mut self,
        _: &RuntimeSnapshot,
        _: &SchedulingSnapshot,
        _: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError> {
        panic!("Runtime7 must never project into a legacy runtime native verifier")
    }
}

#[test]
fn restoration_context_keeps_first_capture_and_target_scopes_separate() {
    let model = Model::new();
    let mut verifier = Verifier::new(&model);

    // crucible-lint: allow panic-shortcut -- the unchanged synthetic context must pass so the adjacent refusal isolates the mutated authority.
    let context = model.prepare(&mut verifier).unwrap();

    assert_eq!(context.record(), &model.record);
    assert_eq!(context.target(), &model.target);
    assert_eq!(context.source_record(), &model.source);
    assert_ne!(
        context.record().source_activation.activation_id,
        context.target().activation_id
    );
    assert_eq!(
        context.record().inputs[0]
            .lineage
            .as_ref()
            // crucible-lint: allow panic-shortcut -- the preceding closed synthetic fixture conversion must succeed for this control to test restoration authority.
            .unwrap()
            .source
            .source_activation
            .generation,
        1.into()
    );
    // crucible-lint: allow panic-shortcut -- the unchanged synthetic context must pass so the adjacent refusal isolates the mutated authority.
    context.validate_current(&model.runtime).unwrap();
    let (foreign, _) = runtime(OperatingMode::Quantized);
    assert!(matches!(
        context.validate_current(&foreign),
        Err(RuntimeError::ForeignAuthority)
    ));
    model.no_native_effects();
}

#[test]
fn foreign_target_and_extent_refuse_before_native_callbacks() {
    let model = Model::new();
    let mut verifier = Verifier::new(&model);
    let mut foreign = model.target.clone();
    foreign.activation_id = id("other-target");

    assert!(matches!(
        model.runtime.prepare_original_lineage_restoration(
            &model.source,
            &model.content,
            &model.scheduling,
            &foreign,
            &mut verifier,
            OriginalLineageRestorationLimits {
                lineage: OriginalInputLineageLimits::default(),
                maximum_record_bytes: 1024 * 1024,
            },
        ),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert!(matches!(
        model.runtime.prepare_original_lineage_restoration(
            &model.source,
            &model.content,
            &model.scheduling,
            &model.target,
            &mut verifier,
            OriginalLineageRestorationLimits {
                lineage: OriginalInputLineageLimits::default(),
                maximum_record_bytes: 1,
            },
        ),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(verifier.calls, 0);
    assert!(
        model
            .states
            .iter()
            .all(|state| state.borrow().lineage_restoration_calls == 0)
    );
    model.no_native_effects();
}

#[test]
fn foreign_first_scope_and_source_or_missing_journal_refuse_before_nodes() {
    let model = Model::new();
    for mutation in 0..4 {
        let mut verifier = Verifier::new(&model);
        match mutation {
            0 => {
                verifier.scope.first_scopes[0]
                    .source_activation
                    .activation_id = id("foreign-first")
            }
            1 => verifier.scope.source_capture.activation_id = id("foreign-capture"),
            2 => verifier.scope.journals[0].operations.clear(),
            _ => verifier.scope.journals[1].input_stages.clear(),
        }
        assert!(matches!(
            model.prepare(&mut verifier),
            Err(RuntimeError::InvalidReceipt)
        ));
    }
    assert!(
        model
            .states
            .iter()
            .all(|state| state.borrow().lineage_restoration_calls == 0)
    );
    model.no_native_effects();
}

#[test]
fn missing_producer_or_consumer_native_journals_never_forms_context() {
    for missing in 0..2 {
        let model = Model::new();
        model.states[missing]
            .borrow_mut()
            .lineage_restoration_refuse = true;
        let mut verifier = Verifier::new(&model);

        assert!(matches!(
            model.prepare(&mut verifier),
            Err(RuntimeError::InvalidReceipt)
        ));
        model.no_native_effects();
    }
    let model = Model::new();
    let mut verifier = Verifier::new(&model);
    verifier.supported = false;
    assert!(matches!(
        model.prepare(&mut verifier),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert!(
        model
            .states
            .iter()
            .all(|state| state.borrow().lineage_restoration_calls == 0)
    );
    model.no_native_effects();
}

#[test]
fn recapture_context_keeps_three_distinct_generations_without_relabeling_first() {
    let mut model = Model::new();
    let original = model.record.inputs[0].lineage.clone();
    model.advance_capture_and_target();
    let mut verifier = Verifier::new(&model);

    // crucible-lint: allow panic-shortcut -- the unchanged synthetic context must pass so the adjacent refusal isolates the mutated authority.
    let context = model.prepare(&mut verifier).unwrap();

    assert_eq!(context.record().inputs[0].lineage, original);
    assert_eq!(
        context.record().inputs[0]
            .lineage
            .as_ref()
            // crucible-lint: allow panic-shortcut -- the preceding closed synthetic fixture conversion must succeed for this control to test restoration authority.
            .unwrap()
            .source
            .source_activation
            .generation,
        1.into()
    );
    assert_eq!(context.record().source_activation.generation, 2.into());
    assert_eq!(context.target().generation, 3.into());
    // crucible-lint: allow panic-shortcut -- the unchanged synthetic context must pass so the adjacent refusal isolates the mutated authority.
    context.validate_current(&model.runtime).unwrap();
    model.no_native_effects();
}

#[test]
fn pending_original_journal_is_required_before_endpoint_callbacks() {
    let mut model = Model::new();
    model.record.operations[0].result = SavedRuntimeResult::Pending;
    model.reauthenticate_record();
    let mut verifier = Verifier::new(&model);
    assert_eq!(
        verifier.scope.journals[0].pending_operations,
        vec![model.record.operations[0].operation.clone()]
    );
    verifier.scope.journals[0].pending_operations.clear();

    assert!(matches!(
        model.prepare(&mut verifier),
        Err(RuntimeError::InvalidReceipt)
    ));

    assert!(
        model
            .states
            .iter()
            .all(|state| state.borrow().lineage_restoration_calls == 0)
    );
    model.no_native_effects();
}

#[test]
fn foreign_actual_target_world_refuses_before_original_journal_callbacks()
-> Result<(), RuntimeError> {
    let mut model = Model::new();
    model.target.world_binding_hash = crucible_node_contract::canonical::content_ref(
        b"different-whole-world",
        "application/json",
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?
    .hash;
    model.runtime.barrier = ActivationBarrier::new(model.target.clone())?;
    let mut verifier = Verifier::new(&model);

    assert!(matches!(
        model.prepare(&mut verifier),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert_eq!(verifier.calls, 0);
    assert!(
        model
            .states
            .iter()
            .all(|state| state.borrow().lineage_restoration_calls == 0)
    );
    model.no_native_effects();
    Ok(())
}

#[test]
fn validated_context_does_not_silently_enable_unqualified_readiness() -> Result<(), RuntimeError> {
    let mut model = Model::new();
    let mut verifier = Verifier {
        scope: model.scope(),
        calls: 0,
        supported: true,
    };
    let context = model.runtime.prepare_original_lineage_restoration(
        &model.source,
        &model.content,
        &model.scheduling,
        &model.target,
        &mut verifier,
        OriginalLineageRestorationLimits {
            lineage: OriginalInputLineageLimits::default(),
            maximum_record_bytes: 1024 * 1024,
        },
    )?;
    assert!(
        model
            .runtime
            .arm_original_lineage_restoration(&context)
            .is_err()
    );
    assert!(model.runtime.prepared_node_records().is_err());
    assert!(!model.runtime.activated);
    assert!(model.runtime.operations.is_empty());
    assert!(model.runtime.input_batches.is_empty());
    model.no_native_effects();
    Ok(())
}

#[test]
fn post_publication_install_refusal_retains_original_pending_permission_and_input()
-> Result<(), RuntimeError> {
    let mut model = Model::new();
    model.record.operations[0].result = SavedRuntimeResult::Pending;
    model.reauthenticate_record();
    let mut verifier = Verifier::new(&model);
    let Model {
        mut runtime,
        states,
        record,
        source,
        content,
        scheduling,
        target,
    } = model;
    for state in &states {
        state.borrow_mut().lineage_restoration_admit = true;
    }
    let context = runtime.prepare_original_lineage_restoration(
        &source,
        &content,
        &scheduling,
        &target,
        &mut verifier,
        OriginalLineageRestorationLimits {
            lineage: OriginalInputLineageLimits::default(),
            maximum_record_bytes: 1024 * 1024,
        },
    )?;
    runtime.arm_original_lineage_restoration(&context)?;
    let activation = runtime.activate(&mut Publisher {
        disposition: PublicationStatus::Committed,
        calls: 0,
    })?;

    assert!(matches!(
        runtime.install_original_lineage_restoration(&context, &activation),
        Err(RuntimeError::InvalidReceipt)
    ));

    let operation = runtime
        .operations
        .get(&record.operations[0].operation)
        .ok_or(RuntimeError::InvalidReceipt)?;
    assert!(matches!(operation.result, RetainedResult::Pending));
    assert_eq!(operation.admission.request(), &record.operations[0].request);
    assert_eq!(runtime.input_batches.len(), record.inputs.len());
    let saved = &record.inputs[0];
    let input = runtime
        .input_batches
        .get(&saved.stage_operation)
        .ok_or(RuntimeError::InvalidReceipt)?;
    assert_eq!(input.batch.deliveries(), saved.deliveries);
    assert_eq!(input.batch.inventory(), &saved.inventory);
    assert_eq!(
        input
            .lineage
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)?
            .source_scope(),
        &saved
            .lineage
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)?
            .source
    );
    for payload in input.batch.payloads() {
        assert_eq!(
            Some(payload.bytes.as_slice()),
            content.get(&payload.reference)
        );
    }
    assert!(
        runtime
            .owners
            .values()
            .all(|owner| owner.lifecycle == Lifecycle::Quarantined)
    );
    assert_eq!(
        states
            .iter()
            .map(|state| state.borrow().lineage_install_calls)
            .sum::<usize>(),
        1
    );
    for state in states {
        let state = state.borrow();
        assert_eq!(
            (
                state.begin_calls,
                state.poll_calls,
                state.close_calls,
                state.ack_calls
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(state.quarantine_calls, 1);
    }
    Ok(())
}

#[test]
fn post_publication_copy_credit_refuses_before_journal_install_or_native_callbacks()
-> Result<(), RuntimeError> {
    let model = Model::new();
    let mut verifier = Verifier::new(&model);
    let Model {
        mut runtime,
        states,
        record,
        source,
        content,
        scheduling,
        target,
    } = model;
    let maximum_bytes = record
        .inputs
        .iter()
        .flat_map(|input| {
            input
                .payloads
                .iter()
                .chain(input.provenance.iter().flat_map(|proof| &proof.objects))
                .chain(
                    input
                        .lineage
                        .iter()
                        .flat_map(|lineage| &lineage.publications)
                        .flat_map(|publication| &publication.objects),
                )
        })
        .try_fold(0usize, |total, reference| {
            total
                .checked_add(
                    usize::try_from(reference.length.get())
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)
        })?;
    let limits = OriginalInputLineageLimits {
        maximum_bytes,
        ..OriginalInputLineageLimits::default()
    };
    record.validate_metadata(limits, 1024 * 1024)?;
    for state in &states {
        state.borrow_mut().lineage_restoration_admit = true;
    }
    let context = runtime.prepare_original_lineage_restoration(
        &source,
        &content,
        &scheduling,
        &target,
        &mut verifier,
        OriginalLineageRestorationLimits {
            lineage: limits,
            maximum_record_bytes: 1024 * 1024,
        },
    )?;
    runtime.arm_original_lineage_restoration(&context)?;
    let activation = runtime.activate(&mut Publisher {
        disposition: PublicationStatus::Committed,
        calls: 0,
    })?;

    assert!(matches!(
        runtime.install_original_lineage_restoration(&context, &activation),
        Err(RuntimeError::ResourceLimit)
    ));

    assert!(runtime.operations.is_empty());
    assert!(runtime.input_batches.is_empty());
    for state in states {
        let state = state.borrow();
        assert_eq!(state.lineage_install_calls, 0);
        assert_eq!(
            (
                state.begin_calls,
                state.poll_calls,
                state.close_calls,
                state.ack_calls
            ),
            (0, 0, 0, 0)
        );
    }
    assert_eq!(context.record(), &record);
    assert!(
        context
            .original_body(&record.inputs[0].payloads[0])
            .is_some()
    );
    Ok(())
}

#[test]
fn foreign_fresh_input_ack_roster_refuses_before_endpoint_validation() -> Result<(), RuntimeError> {
    let model = Model::new();
    let mut verifier = Verifier::new(&model);
    let saved = &model.record.inputs[0];
    verifier.scope.input_acknowledgements.push(
        crate::node_scheduling::NativeInputAcknowledgement {
            stage_operation: saved.stage_operation.clone(),
            batch: saved.batch.clone(),
            node: saved.node.clone(),
            owners: model.target.owners.clone(),
            cutoff: saved.cutoff,
            inventory: saved.inventory.clone(),
            proof_ref: model.source.clone(),
        },
    );

    assert!(matches!(
        model.prepare(&mut verifier),
        Err(RuntimeError::InvalidReceipt)
    ));

    assert!(
        model
            .states
            .iter()
            .all(|state| state.borrow().lineage_restoration_calls == 0)
    );
    model.no_native_effects();
    Ok(())
}

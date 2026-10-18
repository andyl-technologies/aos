//! Validates restored completions through retained authority and Source evidence.
//!
//! Common installation replaces only outcome owners and scheduling owners with
//! the actual fresh route. Every other field remains the authenticated historical
//! outcome. This adapter never creates a generic Begin/Poll ledger or treats a
//! matching DTO as proof: its comparisons run inside the real association fence.

use super::*;
use crate::node_contract::{
    OperationOutcome, OwnerIdentity, ProgressEvidence, SavedRuntimeOperation, SavedRuntimeResult,
};
use crate::node_scheduling::{
    NativeExternalInputInventory, NativeInputProgress, NativeProducerBound, NativePublication,
    NativeSchedulingObservation,
};
use crucible_node_contract::{ContentRef, Id, Position};

#[path = "outcome/history17.rs"]
mod history17;
pub(in crate::node_adapters::cnp::semantic::node) use history17::{
    historical_outcome_correspondence17_counter_scratch_data,
    historical_outcome_correspondence17_data,
};

impl super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn validate_installed_restoration_outcome(
        &self,
        original: &OperationAdmission,
        actual: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        if self.requires_installed_producer_claim_data(original.token()) {
            return self.validate_installed_producer_outcome_data(original, actual);
        }
        let native = self
            .preparation
            .guard
            .custody()
            .map_err(super::super::super::unknown)?;
        let source = native
            .source
            .as_ref()
            .ok_or_else(|| super::super::super::refused("installed Source absent"))?;
        let controller = native
            .controller()
            .ok_or_else(|| super::super::super::refused("installed Controller absent"))?;
        let selected = native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or_else(|| super::super::super::refused("installed association absent"))?;
        let activation = selected
            .activation
            .as_ref()
            .ok_or_else(|| super::super::super::refused("installed activation absent"))?;
        if !selected.installed {
            return Err(super::super::super::refused(
                "installed custody adoption incomplete",
            ));
        }
        authenticate_retained_admission(
            &selected.operations,
            &selected.inputs,
            &self.route,
            activation,
            original,
        )
        .map_err(super::super::super::refused_display)?;

        selected
            .association
            .with_original_node_custody_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                |record, scope, content| {
                    if activation.record() != &scope.target {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    correspondence::operation(&self.route, activation, original, record)?;
                    if let Some(batch) = original.inputs() {
                        // Recheck the complete real shared input against immutable
                        // saved payloads inside this same archived/native fence.
                        correspondence::input(
                            &self.route,
                            activation,
                            batch,
                            record,
                            scope,
                            content,
                        )?;
                    }
                    let saved =
                        unique_saved_operation(&record.operations, original.token().operation())?;
                    let saved = completed_outcome(&saved.result)?;
                    outcome_correspondence(saved, &self.route.owners, actual)
                },
            )
            .map_err(super::super::super::refused_display)?;
        self.current()
    }
}

fn authenticate_retained_admission(
    operations: &[OperationAdmission],
    inputs: &[Rc<RuntimeInputBatch>],
    route: &NodeRoute,
    activation: &WorldActivation,
    original: &OperationAdmission,
) -> Result<(), RuntimeError> {
    if original.token().route() != route || !original.activation().same_authority(activation) {
        return Err(RuntimeError::ForeignAuthority);
    }
    let mut matched = false;
    for retained in operations {
        if retained.token().operation() != original.token().operation() {
            continue;
        }
        if matched
            || !retained.token().same_authority(original.token())
            || retained.request() != original.request()
            || !retained.activation().same_authority(activation)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        match (retained.inputs(), original.inputs()) {
            (None, None) => {}
            (Some(saved), Some(actual)) if std::ptr::eq(saved, actual) => {
                let mut found = false;
                for batch in inputs {
                    if std::ptr::eq(batch.as_ref(), actual) {
                        if found {
                            return Err(RuntimeError::InvalidReceipt);
                        }
                        found = true;
                    }
                }
                if !found {
                    return Err(RuntimeError::ForeignAuthority);
                }
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        matched = true;
    }
    if !matched {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

fn unique_saved_operation<'a>(
    operations: &'a [SavedRuntimeOperation],
    operation: &Id,
) -> Result<&'a SavedRuntimeOperation, RuntimeError> {
    let mut matched = None;
    for saved in operations {
        if &saved.operation == operation && matched.replace(saved).is_some() {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    matched.ok_or(RuntimeError::InvalidReceipt)
}

fn completed_outcome(saved: &SavedRuntimeResult) -> Result<&OperationOutcome, RuntimeError> {
    match saved {
        SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
            Ok(outcome)
        }
        SavedRuntimeResult::Pending | SavedRuntimeResult::Failed(_) => {
            Err(RuntimeError::InvalidReceipt)
        }
    }
}

// Exhaustive borrowed field views make any future contract field an explicit
// review obligation. No cloned outcome or temporary serialization is needed.
type OutcomeFields<'a> = (&'a Id, &'a Id, &'a ProgressEvidence, &'a Vec<Id>);
type SchedulingFields<'a> = (
    &'a Id,
    &'a Position,
    &'a Position,
    &'a Vec<NativeProducerBound>,
    &'a Vec<NativePublication>,
    &'a Option<NativeInputProgress>,
    &'a Vec<NativeExternalInputInventory>,
    &'a ContentRef,
);

fn outcome_correspondence(
    saved: &OperationOutcome,
    target_owners: &[OwnerIdentity],
    actual: &OperationOutcome,
) -> Result<(), RuntimeError> {
    let OperationOutcome {
        operation,
        node,
        owners: _,
        progress,
        retained_outputs,
        scheduling,
    } = saved;
    let saved_fields: OutcomeFields<'_> = (operation, node, progress, retained_outputs);
    let OperationOutcome {
        operation,
        node,
        owners,
        progress,
        retained_outputs,
        scheduling: actual_scheduling,
    } = actual;
    let actual_fields: OutcomeFields<'_> = (operation, node, progress, retained_outputs);
    if saved_fields != actual_fields || owners != target_owners {
        return Err(RuntimeError::InvalidReceipt);
    }
    match (scheduling.as_ref(), actual_scheduling.as_ref()) {
        (None, None) => Ok(()),
        (Some(saved), Some(actual)) => scheduling_correspondence(saved, target_owners, actual),
        _ => Err(RuntimeError::InvalidReceipt),
    }
}

fn scheduling_correspondence(
    saved: &NativeSchedulingObservation,
    target_owners: &[OwnerIdentity],
    actual: &NativeSchedulingObservation,
) -> Result<(), RuntimeError> {
    let NativeSchedulingObservation {
        node,
        owners: _,
        reached,
        closed_prefix,
        bounds,
        publications,
        input_progress,
        external_inputs,
        proof_ref,
    } = saved;
    let saved_fields: SchedulingFields<'_> = (
        node,
        reached,
        closed_prefix,
        bounds,
        publications,
        input_progress,
        external_inputs,
        proof_ref,
    );
    let NativeSchedulingObservation {
        node,
        owners,
        reached,
        closed_prefix,
        bounds,
        publications,
        input_progress,
        external_inputs,
        proof_ref,
    } = actual;
    let actual_fields: SchedulingFields<'_> = (
        node,
        reached,
        closed_prefix,
        bounds,
        publications,
        input_progress,
        external_inputs,
        proof_ref,
    );
    if saved_fields != actual_fields || owners != target_owners {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    use crate::node_adapters::cnp::{
        CnpSemanticSource,
        semantic::{process::CnpSemanticProcessCustody, state::SemanticRuntimeCustody},
    };
    use crucible_node_provider::{ProviderError, client::CnpController};
    2 * size_of::<OutcomeFields<'static>>()
        + 2 * size_of::<SchedulingFields<'static>>()
        + size_of::<&OutcomeFields<'static>>()
        + size_of::<&SchedulingFields<'static>>()
        + size_of::<&OperationOutcome>()
        + size_of::<&SavedRuntimeResult>()
        + size_of::<Result<&OperationOutcome, RuntimeError>>()
        + size_of::<Option<&SavedRuntimeOperation>>()
        + size_of::<&mut Option<&SavedRuntimeOperation>>()
        + size_of::<Result<&SavedRuntimeOperation, RuntimeError>>()
        + size_of::<&[SavedRuntimeOperation]>()
        + size_of::<&Vec<SavedRuntimeOperation>>()
        + size_of::<std::slice::Iter<'static, SavedRuntimeOperation>>()
        + size_of::<std::slice::Iter<'static, OperationAdmission>>()
        + size_of::<std::slice::Iter<'static, Rc<RuntimeInputBatch>>>()
        + size_of::<&[OperationAdmission]>()
        + size_of::<&[Rc<RuntimeInputBatch>]>()
        + size_of::<&OperationAdmission>()
        + size_of::<&crate::node_contract::OperationToken>()
        + size_of::<&crate::node_contract::OperationRequest>()
        + size_of::<&Id>()
        + size_of::<&NodeRoute>()
        + size_of::<&InstalledRestorationCustody>()
        + size_of::<&WorldActivation>()
        + size_of::<Option<&WorldActivation>>()
        + size_of::<Result<&WorldActivation, OperationFailure>>()
        + size_of::<&Rc<dyn CnpSemanticSource>>()
        + size_of::<&dyn CnpSemanticSource>()
        + size_of::<Option<&Rc<dyn CnpSemanticSource>>>()
        + size_of::<Result<&Rc<dyn CnpSemanticSource>, OperationFailure>>()
        + size_of::<&CnpController>()
        + size_of::<Option<&CnpController>>()
        + size_of::<Result<&CnpController, OperationFailure>>()
        + size_of::<&CnpSemanticProcessCustody>()
        + size_of::<Result<&CnpSemanticProcessCustody, ProviderError>>()
        + size_of::<Result<&CnpSemanticProcessCustody, OperationFailure>>()
        + size_of::<Option<&SemanticRuntimeCustody>>()
        + size_of::<&SemanticRuntimeCustody>()
        + size_of::<Option<&InstalledRestorationCustody>>()
        + size_of::<Result<&InstalledRestorationCustody, OperationFailure>>()
        + size_of::<&[OwnerIdentity]>()
        + size_of::<&Vec<OwnerIdentity>>()
        + size_of::<Option<&RuntimeInputBatch>>()
        + size_of::<(Option<&RuntimeInputBatch>, Option<&RuntimeInputBatch>)>()
        + size_of::<Option<&NativeSchedulingObservation>>()
        + size_of::<(
            Option<&NativeSchedulingObservation>,
            Option<&NativeSchedulingObservation>,
        )>()
        + size_of::<&OriginalLineageRuntimeRecord>()
        + size_of::<&crate::node_contract::OriginalLineageNativeScope>()
        + size_of::<&crate::node_state::VerifiedStateContent>()
        + size_of::<Result<&crate::node_contract::OriginalLineageInputRecord, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), OperationFailure>>()
        + size_of::<*const ()>()
        + 2 * size_of::<bool>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::{EffectKnowledge, StopReason};
    use crucible_node_contract::{Endpoint, Phase, U64, canonical};

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn owners(incarnation: &str) -> Vec<OwnerIdentity> {
        vec![OwnerIdentity {
            owner: id("actual-owner"),
            incarnation: id(incarnation),
            generation: U64::new(1),
        }]
    }

    fn outcome() -> OperationOutcome {
        let at = Position::new(U64::new(3), U64::new(1), Phase::Publication);
        let proof =
            canonical::content_ref(b"unchanged complete evidence", "application/json").unwrap();
        let payload =
            canonical::content_ref(b"retained output", "application/octet-stream").unwrap();
        OperationOutcome {
            operation: id("original-operation"),
            node: id("original-node"),
            owners: owners("source-incarnation"),
            progress: ProgressEvidence::Exact {
                reached: at,
                stop: StopReason::Output,
            },
            retained_outputs: vec![id("first-output"), id("second-output")],
            scheduling: Some(NativeSchedulingObservation {
                node: id("original-node"),
                owners: owners("source-incarnation"),
                reached: at,
                closed_prefix: at,
                bounds: vec![NativeProducerBound {
                    producer: id("original-node"),
                    bound: crate::node_scheduling::NativeOutputBound::AfterInstant(U64::new(3)),
                    proof_ref: proof.clone(),
                }],
                publications: vec![NativePublication {
                    publication_id: id("first-output"),
                    endpoint: Endpoint {
                        node_id: id("original-node"),
                        port_id: id("actual-port"),
                        lane_id: id("actual-lane"),
                    },
                    native_sequence: U64::new(2),
                    publication: at,
                    evaluation: Some(at),
                    causal_parents: vec![at],
                    payload,
                    payload_bytes: b"retained output".to_vec(),
                }],
                input_progress: None,
                external_inputs: Vec::new(),
                proof_ref: proof,
            }),
        }
    }

    fn remap(saved: &OperationOutcome, target: &[OwnerIdentity]) -> OperationOutcome {
        let mut actual = saved.clone();
        actual.owners = target.to_vec();
        actual.scheduling.as_mut().unwrap().owners = target.to_vec();
        actual
    }

    #[test]
    fn complete_and_acknowledged_outcomes_allow_only_the_two_real_owner_substitutions() {
        let saved = outcome();
        let target = owners("fresh-target-incarnation");
        let actual = remap(&saved, &target);

        for phase in [
            SavedRuntimeResult::Complete(saved.clone()),
            SavedRuntimeResult::Acknowledged(saved.clone()),
        ] {
            outcome_correspondence(completed_outcome(&phase).unwrap(), &target, &actual).unwrap();
        }
        assert_eq!(saved.owners, owners("source-incarnation"));
        assert_eq!(saved.scheduling.as_ref().unwrap().owners, saved.owners);
        assert!(outcome_correspondence(&saved, &target, &saved).is_err());
        assert!(completed_outcome(&SavedRuntimeResult::Pending).is_err());
        assert!(
            completed_outcome(&SavedRuntimeResult::Failed(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "retained failure".into()
            }))
            .is_err()
        );
    }

    #[test]
    fn full_outcome_and_scheduling_correspondence_rejects_changed_evidence() {
        let saved = outcome();
        let target = owners("fresh-target-incarnation");
        let original = remap(&saved, &target);

        for field in 0..17 {
            let mut actual = original.clone();
            match field {
                0 => actual.operation = id("changed-operation"),
                1 => actual.node = id("changed-node"),
                2 => actual.owners.clear(),
                3 => actual.progress = ProgressEvidence::Administrative,
                4 => actual.retained_outputs.reverse(),
                5 => actual.scheduling = None,
                _ => {
                    let view = actual.scheduling.as_mut().unwrap();
                    match field {
                        6 => view.node = id("changed-node"),
                        7 => view.owners.clear(),
                        8 => view.reached.time_ps = U64::new(4),
                        9 => view.closed_prefix.microstep = U64::new(2),
                        10 => view.bounds.clear(),
                        11 => view.publications[0].payload_bytes.push(0),
                        12 => view.publications[0].causal_parents.clear(),
                        13 => view.publications[0].native_sequence = U64::new(3),
                        14 => {
                            view.input_progress = Some(NativeInputProgress {
                                batch: id("foreign-input-batch"),
                                consumed: Vec::new(),
                                proof_ref: view.proof_ref.clone(),
                            })
                        }
                        15 => view.external_inputs.push(NativeExternalInputInventory {
                            endpoint: view.publications[0].endpoint.clone(),
                            closed_before: view.closed_prefix,
                            inputs: Vec::new(),
                            proof_ref: view.proof_ref.clone(),
                        }),
                        _ => {
                            view.proof_ref =
                                canonical::content_ref(b"foreign proof", "application/json")
                                    .unwrap()
                        }
                    }
                }
            }
            assert!(
                outcome_correspondence(&saved, &target, &actual).is_err(),
                "field {field}"
            );
        }
    }

    #[test]
    fn saved_completion_lookup_refuses_missing_and_duplicate_operation_rows() {
        let outcome = outcome();
        let saved = SavedRuntimeOperation {
            operation: outcome.operation.clone(),
            route: NodeRoute {
                node: outcome.node.clone(),
                owners: outcome.owners.clone(),
            },
            request: crate::node_contract::OperationRequest::Observe,
            input_batch: None,
            result: SavedRuntimeResult::Complete(outcome),
            close_submission: None,
            submission_effects: None,
            scheduling_commit: None,
        };
        let rows = vec![saved.clone()];
        assert!(std::ptr::eq(
            unique_saved_operation(&rows, &saved.operation).unwrap(),
            &rows[0]
        ));
        assert!(unique_saved_operation(&[], &saved.operation).is_err());
        assert!(unique_saved_operation(&rows, &id("foreign-operation")).is_err());
        assert!(unique_saved_operation(&[saved.clone(), saved.clone()], &saved.operation).is_err());
    }

    #[test]
    fn retained_core_admission_requires_actual_token_world_request_and_shared_input_identity() {
        let original = crate::node_contract::test_original_admission("restored-completion");
        let retained = original.clone();
        let route = original.token().route();
        let activation = original.activation();
        authenticate_retained_admission(&[retained.clone()], &[], route, activation, &original)
            .unwrap();

        let mut foreign = crate::node_contract::test_original_admission("restored-completion");
        assert_eq!(foreign.token().operation(), original.token().operation());
        assert!(!foreign.token().same_authority(original.token()));
        let foreign_world = foreign.activation().clone();
        foreign.activation = activation.clone();
        assert!(foreign.activation().same_authority(activation));
        assert!(
            authenticate_retained_admission(&[retained.clone()], &[], route, activation, &foreign)
                .is_err()
        );
        let mut changed_world = original.clone();
        changed_world.activation = foreign_world;
        assert!(changed_world.token().same_authority(original.token()));
        assert!(
            authenticate_retained_admission(
                &[retained.clone()],
                &[],
                route,
                activation,
                &changed_world,
            )
            .is_err()
        );
        assert!(
            authenticate_retained_admission(
                &[retained.clone(), retained.clone()],
                &[],
                route,
                activation,
                &original
            )
            .is_err()
        );
        assert!(authenticate_retained_admission(&[], &[], route, activation, &original).is_err());
        let mut changed = original.clone();
        changed.request = crate::node_contract::OperationRequest::Observe;
        assert!(
            authenticate_retained_admission(&[retained.clone()], &[], route, activation, &changed)
                .is_err()
        );

        // These inert batch bodies test local shared-owner identity only. The
        // production Source fence still authenticates the complete real batch.
        let make_batch = || RuntimeInputBatch {
            activation: activation.clone(),
            node: route.node.clone(),
            stage_operation: id("original-stage"),
            batch: id("original-batch"),
            owners: route.owners.clone(),
            cutoff: activation.record().boundary,
            inventory: canonical::content_ref(b"inert batch identity", "application/json").unwrap(),
            deliveries: Vec::new(),
            payloads: Vec::new(),
        };
        let batch = Rc::new(make_batch());
        let mut original = original.clone();
        original.inputs = Some(Rc::clone(&batch));
        let retained = original.clone();
        authenticate_retained_admission(
            &[retained.clone()],
            &[Rc::clone(&batch)],
            route,
            activation,
            &original,
        )
        .unwrap();
        let mut changed = original.clone();
        changed.inputs = Some(Rc::new(make_batch()));
        assert!(
            authenticate_retained_admission(
                &[retained.clone()],
                &[Rc::clone(&batch)],
                route,
                activation,
                &changed
            )
            .is_err()
        );
        assert!(
            authenticate_retained_admission(&[retained], &[], route, activation, &original)
                .is_err()
        );
    }
}

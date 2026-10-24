//! Retains actual same-runtime operation/activation identity after native checks.

use super::*;
use crate::node_qualification::OriginalCompletionObservation;
use crucible_engine::node_contract::{OperationToken, OriginalCompletedOperation, WorldActivation};
use crucible_node_format::canonical;

pub(super) struct OriginalBindings {
    entries: RefCell<Vec<Option<Binding>>>,
}

struct Binding {
    token: OperationToken,
    activation: WorldActivation,
    reference: ContentRef,
}

impl OriginalBindings {
    pub(super) fn reserve(cases: usize) -> Result<Self, QualificationError> {
        if cases == 0 || cases > 128 {
            return Err(refused());
        }
        let mut entries = Vec::new();
        entries.try_reserve_exact(cases).map_err(|_| refused())?;
        entries.resize_with(cases, || None);
        Ok(Self {
            entries: RefCell::new(entries),
        })
    }

    fn retain(
        &self,
        index: usize,
        original: &OriginalCompletedOperation<'_>,
        reference: &ContentRef,
    ) -> Result<(), QualificationError> {
        let mut entries = self.entries.try_borrow_mut().map_err(|_| refused())?;
        let admission = original.admission();
        if index >= entries.len() {
            return Err(refused());
        }
        if let Some(binding) = &entries[index] {
            return binding.authenticate(original, reference);
        }
        for binding in entries.iter().flatten() {
            if binding.token.operation() == admission.token().operation()
                && (!binding.token.same_authority(admission.token())
                    || !binding.activation.same_authority(admission.activation()))
            {
                return Err(refused());
            }
        }
        // Every future slot was reserved before Child. Count full route and
        // activation before cloning the actual original opaque handles.
        super::super::super::scope::encoded_size(
            &(
                admission.token().operation(),
                admission.token().route(),
                super::super::super::scope::activation_view(admission.activation().record()),
                reference,
            ),
            4096,
        )?;
        entries[index] = Some(Binding {
            token: admission.token().clone(),
            activation: admission.activation().clone(),
            reference: reference.clone(),
        });
        Ok(())
    }
}

impl Binding {
    fn authenticate(
        &self,
        original: &OriginalCompletedOperation<'_>,
        reference: &ContentRef,
    ) -> Result<(), QualificationError> {
        if !self.token.same_authority(original.admission().token())
            || !self
                .activation
                .same_authority(original.admission().activation())
            || self.reference != *reference
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl PacketConnectedNativeOracle {
    /// Rechecks a retained original report before durable native publication.
    ///
    /// # Errors
    /// Refuses a substituted runtime/token/activation/report, changed original
    /// request/outcome/ACK disposition or revoked original native source custody.
    pub fn authenticate_original_result(
        &self,
        case: &str,
        original: &OriginalCompletedOperation<'_>,
        reference: &ContentRef,
    ) -> Result<(), QualificationError> {
        let expected = self.expected_completion(case)?;
        if original.admission().request() != &expected.request
            || original.outcome() != &expected.outcome
            || original.acknowledged() != expected.acknowledged
        {
            return Err(refused());
        }
        let index = self
            .schedule
            .cases
            .iter()
            .position(|row| row.id == case)
            .ok_or_else(refused)?;
        let entries = self.originals.entries.try_borrow().map_err(|_| refused())?;
        entries
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(refused)?
            .authenticate(original, reference)?;
        self.roster.current_native().map_err(native_failure)
    }

    /// Authenticates a fresh opaque completion against the independent native oracle.
    ///
    /// # Errors
    /// Refuses a foreign token/activation, changed full input/ACK/commit custody,
    /// altered outcome, substituted report or missing actual producer lineage.
    pub fn authenticate_original_runtime(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        original: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<(), QualificationError> {
        let planned = plan
            .cases
            .iter()
            .find(|row| row.id == case && row.oracle == *oracle)
            .ok_or_else(refused)?;
        if self.authenticate_original(plan, planned, original)? != CaseVerdict::Passed {
            return Err(refused());
        }
        let index = self
            .schedule
            .cases
            .iter()
            .position(|row| row.id == case)
            .ok_or_else(refused)?;
        self.originals
            .retain(index, original.original(), original.reference())
    }
}

impl InstalledRuntimeWitnessOracle for PacketConnectedNativeOracle {
    fn authenticate_original(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        original: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<CaseVerdict, QualificationError> {
        if plan != &self.plan
            || !matches!(
                original.observation(),
                OriginalCompletionObservation::Exact(_)
            )
        {
            return Err(refused());
        }
        let expected = self.expected_completion(&case.id)?;
        let completed = original.original();
        let admission = completed.admission();
        let (selected, scheduled, member) = self.template(&case.id)?;
        let activation: &crucible_engine::node_contract::SavedRuntimeActivation =
            &serde_json::from_value(self.roster.coordinator.template["activation"].clone())
                .map_err(crucible_node_format::ContractError::from)?;
        let actual = admission.activation().record();
        if expected.oracle != case.oracle
            || actual.generation != activation.generation
            || actual.activation_id != activation.activation_id
            || actual.world_binding_hash != activation.world_binding_hash
            || actual.owners != activation.owners
            || actual.boundary != activation.boundary
            || admission.token().route().node != selected.node
            || admission.token().operation() != &scheduled.operation
            || admission.request() != &expected.request
            || completed.outcome() != &expected.outcome
            || completed.acknowledged() != expected.acknowledged
        {
            return Err(refused());
        }
        let observed = self.observed.try_borrow().map_err(|_| refused())?;
        match &self.roster.sources[member] {
            PacketConnectedParticipant::Producer(_) => {
                if admission.inputs().is_some()
                    || completed
                        .staged_inputs()
                        .map_err(runtime_failure)?
                        .is_some()
                    || original.native_input().is_some()
                {
                    return Err(refused());
                }
            }
            PacketConnectedParticipant::Reactive(_) => {
                let staged = completed
                    .staged_inputs()
                    .map_err(runtime_failure)?
                    .ok_or_else(refused)?;
                let batch = staged.batch();
                let commit = observed
                    .seals
                    .iter()
                    .filter(|seal| seal.member == member)
                    .find_map(|seal| match &seal.body {
                        NativeBody::Commit(record)
                            if record.cut.batch_id == *batch.batch()
                                && record.cut.stage_operation_id == *batch.stage_operation() =>
                        {
                            Some(record)
                        }
                        _ => None,
                    })
                    .ok_or_else(refused)?;
                let stage = observed
                    .seals
                    .iter()
                    .find_map(|seal| match &seal.body {
                        NativeBody::Stage(record)
                            if seal.member == member && seal.reference == commit.staged_record =>
                        {
                            Some(record)
                        }
                        _ => None,
                    })
                    .ok_or_else(refused)?;
                if !staged.committed()
                    || staged.coordinator_commit().is_none()
                    || batch.node() != &stage.cut.node_id
                    || batch.stage_operation() != &stage.cut.stage_operation_id
                    || batch.batch() != &stage.cut.batch_id
                    || batch.cutoff() != stage.cut.cutoff
                    || batch.inventory() != &stage.cut.delivery_inventory
                    || staged.acknowledgement().proof_ref != commit.staged_record
                    || serde_json::to_value(batch.deliveries())
                        .map_err(crucible_node_format::ContractError::from)?
                        != serde_json::to_value(&stage.deliveries)
                            .map_err(crucible_node_format::ContractError::from)?
                {
                    return Err(refused());
                }
                if !batch.deliveries().is_empty()
                    && (staged.lineage().is_none() || staged.provenance().is_none())
                {
                    return Err(refused());
                }
                let native = original.native_input().ok_or_else(refused)?;
                if native.root != commit.staged_record
                    || !native
                        .objects
                        .iter()
                        .any(|body| body.reference == commit.staged_record)
                {
                    return Err(refused());
                }
                for body in &native.objects {
                    body.reference.verify(&body.bytes)?;
                }
                // This full native Stage closure is read under the same runtime;
                // matching bytes alone never supplied the source validation.
                let stage_body = native
                    .objects
                    .iter()
                    .find(|body| body.reference == commit.staged_record)
                    .ok_or_else(refused)?;
                let stage_bytes = canonical::canonical_json(
                    &serde_json::to_value(stage)
                        .map_err(crucible_node_format::ContractError::from)?,
                )?;
                if stage_body.bytes != stage_bytes {
                    return Err(refused());
                }
            }
        }
        original.reference().verify(original.bytes())?;
        self.roster.current_native().map_err(native_failure)?;
        Ok(CaseVerdict::Passed)
    }
}

fn runtime_failure(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(format!("original connected input custody: {error}"))
}

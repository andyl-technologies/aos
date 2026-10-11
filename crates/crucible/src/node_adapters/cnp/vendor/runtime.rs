//! Common lifecycle dispatch over retained original vendor CNP custody.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{
    ContentRef, Id, NodeBinding, NodeDescriptor, PreparedOwner, Validate,
};

use crate::{
    node_contract::{
        ActivationRecord, CancelStatus, EffectKnowledge, FacetDescription, FacetKind,
        NativeReclamationReceipt, NodeFacet, NodeRoute, NodeStatus, OperationAdmission,
        OperationFailure, OperationOutcome, OperationRequest, OperationToken, OwnerIdentity,
        ReadyAttestation, Refusal, SimulationNode, Submission, ThreadAffinity, WorldActivation,
    },
    node_scheduling::{
        InputPayload, NativeInputAcknowledgement, NativeSchedulingObservation, RuntimeInputBatch,
    },
};

use super::{
    OriginalInput, OriginalOperation, VendorCnpAction, VendorCnpEvidence, VendorCnpFacet,
    VendorCnpFailure, VendorCnpIdentity, VendorCnpLaunchGuard, activation_credit, encoded_size,
    refused, unknown,
};

/// Dispatches independently qualified vendor semantics through the common node contract.
///
/// This adapter is not restricted to the reference checksum profile. Its exact
/// descriptors, typed lanes, modes and state codecs come from source installation
/// and ordinary graph admission. Unsupported callbacks preserve explicit refusal.
pub struct VendorCnpNode {
    guard: VendorCnpLaunchGuard,
    identity: VendorCnpIdentity,
    facets: Vec<FacetKind>,
    affinity: ThreadAffinity,
}

impl VendorCnpNode {
    /// Constructs an inactive node under exact installed native/source inspection.
    ///
    /// No constructor argument supplies readiness or execution authority. The
    /// registry authenticates ordinary behavioral acceptance before preparation
    /// and seals the complete graph afterwards; every common mutation still
    /// requires the runtime's original opaque admission.
    ///
    /// # Errors
    /// Returns the same complete guard on unsupported source, changed identity,
    /// invalid facets or exhausted descriptor/compatibility metadata credit.
    ///
    /// # Panics
    /// An installed inspector may unwind. The complete original guard transfers
    /// to its preowned supervisor; unwinding never establishes native release.
    pub fn from_original_preparation(
        identity: VendorCnpIdentity,
        mut guard: VendorCnpLaunchGuard,
        codec: Rc<dyn super::InstalledVendorCnpCodec>,
    ) -> Result<Self, VendorCnpFailure> {
        let result = (|| {
            let state = guard
                .custody
                .as_mut()
                .ok_or_else(|| refused("vendor original custody absent"))?;
            identity.descriptor.validate().map_err(super::contract)?;
            identity.binding.validate().map_err(super::contract)?;
            if identity.descriptor.id != identity.binding.compatibility.node_id
                || identity.route.node != identity.descriptor.id
                || identity.binding.compatibility.descriptor_hash
                    != identity.descriptor.identity().map_err(super::contract)?
                || identity.route.owners.is_empty()
                || identity
                    .route
                    .owners
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || !identity.route.owners.iter().any(|owner| {
                    owner.owner == identity.binding.compatibility.execution_owner.id
                        && owner.incarnation == identity.binding.authority.incarnation_id
                        && owner.generation == identity.binding.authority.owner_generation
                })
                || identity.binding.authority.session_id
                    != *state.peer.session.authority().session_id()
                || identity.binding.authority.incarnation_id
                    != *state.peer.session.authority().incarnation_id()
            {
                return Err(refused(
                    "vendor metadata differs from original native owner/session scope",
                ));
            }
            let bytes = encoded_size(&identity.descriptor, state.limits.metadata_bytes)?
                .checked_add(encoded_size(
                    &identity.binding,
                    state.limits.metadata_bytes,
                )?)
                .and_then(|bytes| {
                    bytes.checked_add(
                        encoded_size(&identity.route, state.limits.metadata_bytes).ok()?,
                    )
                })
                .filter(|bytes| *bytes <= state.limits.metadata_bytes)
                .ok_or_else(|| refused("vendor original metadata exceeds aggregate credit"))?;
            // Store the installed identity/codec below owning custody before any
            // external semantic inspector callback can fail or unwind.
            state.reclamation.reserve_exact(identity.route.owners.len());
            state.identity = Some(identity.clone());
            state.codec = Some(Rc::clone(&codec));
            state.metadata_used = bytes;
            state.current()?;
            let mut facets = codec.facets(&identity)?;
            super::facets::validate_mapping(
                &identity.binding.compatibility.operating_contract,
                &facets,
            )?;
            state.current()?;
            facets.sort_by_key(|facet| facet.kind);
            let kinds = facets.iter().map(|facet| facet.kind).collect();
            state.facets = facets;
            state.adopted = true;
            Ok(kinds)
        })();
        match result {
            Ok(facets) => Ok(Self {
                guard,
                identity,
                facets,
                affinity: ThreadAffinity::OwnerThread(std::thread::current().id()),
            }),
            Err(error) => Err(VendorCnpFailure {
                error: unknown(&error.reason),
                guard,
            }),
        }
    }

    pub(super) fn state(&self) -> Result<&super::VendorCnpCustody, OperationFailure> {
        self.guard
            .custody
            .as_deref()
            .ok_or_else(|| unknown("vendor original custody transferred"))
    }

    pub(super) fn state_mut(&mut self) -> Result<&mut super::VendorCnpCustody, OperationFailure> {
        if !self.affinity.permits_current_thread() {
            return Err(refused("vendor callback is on another owner thread"));
        }
        self.guard
            .custody
            .as_deref_mut()
            .ok_or_else(|| unknown("vendor original custody transferred"))
    }

    fn original(&self, token: &OperationToken) -> Result<Rc<OperationAdmission>, OperationFailure> {
        let state = self.state()?;
        let original = state
            .operations
            .get(token.operation())
            .ok_or_else(|| refused("vendor original operation is absent"))?;
        if !original.original.token().same_authority(token)
            || original.original.token().route() != token.route()
        {
            return Err(refused(
                "vendor operation is not the original opaque admission",
            ));
        }
        Ok(Rc::clone(&original.original))
    }

    fn activate(&mut self, world: &WorldActivation) -> Result<(), OperationFailure> {
        let state = self.state_mut()?;
        if let Some(active) = &state.active {
            return if active.same_authority(world) {
                state.current()
            } else {
                Err(refused("vendor original activation changed"))
            };
        }
        if state
            .prepared
            .as_ref()
            .is_none_or(|(record, _, _)| record != world.record())
            || world.prepared_owners().is_none()
            || world.coordinator_snapshot().is_none()
        {
            return Err(refused(
                "vendor lacks the actual complete durable world publication",
            ));
        }
        match state.exchange(VendorCnpAction::Activate(world))? {
            VendorCnpEvidence::Acknowledged => {
                state.active = Some(world.clone());
                Ok(())
            }
            _ => Err(unknown(
                "vendor world activation lacks authentic native acknowledgement",
            )),
        }
    }

    fn cache_evidence(
        &mut self,
        token: &OperationToken,
        evidence: VendorCnpEvidence,
    ) -> Result<(), OperationFailure> {
        let original = self.original(token)?;
        match evidence {
            VendorCnpEvidence::Pending => Ok(()),
            VendorCnpEvidence::Outcome(outcome) => {
                let outcome = *outcome;
                self.state_mut()?.uncertain = true;
                let state = self.state_mut()?;
                if outcome.retained_outputs.len() > state.limits.outputs {
                    return Err(unknown(
                        "vendor outcome exceeds original publication count credit",
                    ));
                }
                let bytes = encoded_size(&outcome, state.limits.metadata_bytes)?;
                let entry = state
                    .operations
                    .get_mut(token.operation())
                    .ok_or_else(|| unknown("vendor original outcome custody disappeared"))?;
                if let Some(retained) = &entry.outcome {
                    return if entry.outcome_validated && retained == &outcome {
                        state.current()?;
                        state.uncertain = false;
                        Ok(())
                    } else {
                        Err(unknown("vendor changed its original terminal outcome"))
                    };
                }
                state.metadata_used = state
                    .metadata_used
                    .checked_add(bytes)
                    .filter(|used| *used <= state.limits.metadata_bytes)
                    .ok_or_else(|| unknown("vendor terminal outcome aggregate credit exhausted"))?;
                entry.outcome = Some(outcome);
                let original_outcome = self
                    .state()?
                    .operations
                    .get(token.operation())
                    .and_then(|entry| entry.outcome.as_ref())
                    .ok_or_else(|| unknown("original vendor outcome disappeared"))?;
                self.validate_outcome(&original, original_outcome)?;
                let state = self.state_mut()?;
                state
                    .operations
                    .get_mut(token.operation())
                    .ok_or_else(|| unknown("original vendor outcome disappeared"))?
                    .outcome_validated = true;
                state.uncertain = false;
                Ok(())
            }
            _ => Err(unknown("vendor operation returned another semantic role")),
        }
    }

    fn contain_failure(&mut self, operation: &Id, error: OperationFailure) {
        if let Ok(state) = self.state_mut() {
            if let Some(original) = state.operations.get_mut(operation) {
                original.failure = Some(OperationFailure {
                    effects: EffectKnowledge::Unknown,
                    reason: error.reason,
                });
            }
            state.uncertain = true;
        }
    }
}

impl SimulationNode for VendorCnpNode {
    fn descriptor(&self) -> &NodeDescriptor {
        &self.identity.descriptor
    }

    fn binding(&self) -> &NodeBinding {
        &self.identity.binding
    }

    fn route(&self) -> &NodeRoute {
        &self.identity.route
    }

    fn thread_affinity(&self) -> ThreadAffinity {
        self.affinity
    }

    fn facets(&self) -> &[FacetKind] {
        &self.facets
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        match self.state_mut()?.exchange(VendorCnpAction::Status)? {
            VendorCnpEvidence::Status(status) => Ok(status),
            _ => Err(unknown("vendor status has another native evidence role")),
        }
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        if let Some((record, ready, _)) = &self.state()?.prepared {
            if record != world {
                return Err(refused("vendor original readiness world changed"));
            }
            self.validate_readiness(world, ready)?;
            return Ok(ready.clone());
        }
        let evidence = self.state_mut()?.exchange(VendorCnpAction::Arm(world))?;
        let VendorCnpEvidence::Readiness(ready, owners) = evidence else {
            return Err(unknown(
                "vendor readiness lacks original closed-gate evidence",
            ));
        };
        let state = self.state_mut()?;
        state.uncertain = true;
        let bytes = activation_credit(world, state.limits.metadata_bytes)?
            .checked_add(encoded_size(&ready, state.limits.metadata_bytes)?)
            .and_then(|bytes| {
                bytes.checked_add(encoded_size(&owners, state.limits.metadata_bytes).ok()?)
            })
            .ok_or_else(|| unknown("vendor readiness metadata count overflow"))?;
        state.metadata_used = state
            .metadata_used
            .checked_add(bytes)
            .filter(|used| *used <= state.limits.metadata_bytes)
            .ok_or_else(|| unknown("vendor readiness aggregate credit exhausted"))?;
        state.prepared = Some((world.clone(), ready, owners));
        let (record, ready, _) = self
            .state()?
            .prepared
            .as_ref()
            .ok_or_else(|| unknown("vendor original readiness custody absent"))?;
        self.validate_readiness(record, ready)
            .map_err(|error| unknown(&error.reason))?;
        let ready = ready.clone();
        self.state_mut()?.uncertain = false;
        Ok(ready)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        let state = self.state()?;
        state.current()?;
        let (identity, codec) = state.identity_and_codec()?;
        let (record, original, owners) = state
            .prepared
            .as_ref()
            .ok_or_else(|| refused("vendor original readiness absent"))?;
        if record != world
            || original != ready
            || ready.owners != identity.route.owners
            || ready.boundary != world.boundary
        {
            return Err(refused(
                "vendor readiness is not the unchanged original owner/cut",
            ));
        }
        codec.validate_readiness(identity, world, ready, owners, &state.peer)?;
        state.current()
    }

    fn prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        self.validate_readiness(world, ready)?;
        Ok(self
            .state()?
            .prepared
            .as_ref()
            .map(|(_, _, owners)| owners.clone()))
    }

    fn validate_prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[PreparedOwner],
    ) -> Result<(), OperationFailure> {
        self.validate_readiness(world, ready)?;
        if self
            .state()?
            .prepared
            .as_ref()
            .is_none_or(|(_, _, original)| original != owners)
        {
            return Err(refused(
                "vendor public preparation changed original tokens/bindings",
            ));
        }
        Ok(())
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.validate_readiness(world, ready)?;
        let state = self.state()?;
        let (identity, codec) = state.identity_and_codec()?;
        codec.validate_initial(identity, world, ready, &state.peer)?;
        state.current()
    }

    fn capture_native_continuation(
        &mut self,
        activation: &WorldActivation,
        runtime: &crate::node_contract::RuntimeSnapshot,
        limits: crate::node_contract::NativeCaptureLimits,
    ) -> Result<crate::node_contract::InstalledNativeCapture, OperationFailure> {
        self.capture_original(activation, runtime, limits)
    }

    fn stage_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        if batch.node() != &self.identity.descriptor.id {
            return Err(refused("vendor input belongs to another node"));
        }
        self.activate(batch.activation())?;
        let state = self.state_mut()?;
        state.current()?;
        if let Some(retained) = state.inputs.get(batch.batch()) {
            if state.uncertain || state.quarantined {
                return Err(unknown("vendor original input remains uncertain"));
            }
            if retained.batch.stage_operation() != batch.stage_operation()
                || !retained
                    .batch
                    .activation()
                    .same_authority(batch.activation())
                || retained.batch.inventory() != batch.inventory()
                || retained.batch.deliveries() != batch.deliveries()
                || retained.batch.payloads() != batch.payloads()
                || retained.batch.owners() != batch.owners()
                || retained.batch.cutoff() != batch.cutoff()
            {
                return Err(refused("vendor input changed its original frozen batch"));
            }
            return retained
                .acknowledgement
                .clone()
                .ok_or_else(|| unknown("vendor original input acknowledgement remains uncertain"));
        }
        if state.inputs.len() >= state.limits.operations {
            return Err(refused("vendor original input count credit exhausted"));
        }
        let bytes = input_credit(batch, state.limits.metadata_bytes)?;
        state.metadata_used = state
            .metadata_used
            .checked_add(bytes)
            .filter(|used| *used <= state.limits.metadata_bytes)
            .ok_or_else(|| refused("vendor original input aggregate credit exhausted"))?;
        let original = Rc::new(batch.retained_copy());
        state.inputs.insert(
            batch.batch().clone(),
            OriginalInput {
                batch: Rc::clone(&original),
                acknowledgement: None,
            },
        );
        let evidence = state.exchange(VendorCnpAction::Input(&original))?;
        let VendorCnpEvidence::Input(ack) = evidence else {
            return Err(unknown(
                "vendor input has another original acknowledgement role",
            ));
        };
        self.state_mut()?.uncertain = true;
        // Keep the returned original receipt before the inspector can unwind.
        self.state_mut()?
            .inputs
            .get_mut(batch.batch())
            .ok_or_else(|| unknown("original vendor input custody disappeared"))?
            .acknowledgement = Some(ack.clone());
        self.validate_input_acknowledgement(&original, &ack)
            .map_err(|error| unknown(&error.reason))?;
        self.state_mut()?.uncertain = false;
        Ok(ack)
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &RuntimeInputBatch,
        ack: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        let state = self.state()?;
        state.current()?;
        let (identity, codec) = state.identity_and_codec()?;
        codec.validate_input(identity, batch, ack, &state.peer)?;
        state.current()
    }

    fn observe_scheduling(
        &mut self,
        world: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.activate(world)?;
        match self
            .state_mut()?
            .exchange(VendorCnpAction::Scheduling(world))?
        {
            VendorCnpEvidence::Scheduling(observation) => {
                let observation = *observation;
                self.state_mut()?.uncertain = true;
                self.validate_scheduling_observation(world, &observation)
                    .map_err(|error| unknown(&error.reason))?;
                self.state_mut()?.uncertain = false;
                Ok(observation)
            }
            _ => Err(unknown(
                "vendor scheduling has another native evidence role",
            )),
        }
    }

    fn validate_scheduling_observation(
        &self,
        world: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        let state = self.state()?;
        state.current()?;
        if state
            .active
            .as_ref()
            .is_none_or(|active| !active.same_authority(world))
            || observation.node != self.identity.descriptor.id
            || observation.owners != self.identity.route.owners
        {
            return Err(refused(
                "vendor scheduling changed original activation/owners",
            ));
        }
        let (identity, codec) = state.identity_and_codec()?;
        codec.validate_scheduling(identity, world, observation, &state.peer)?;
        state.current()
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        let operation = admission.token().operation().clone();
        if let Ok(state) = self.state()
            && let Some(entry) = state.operations.get(&operation)
        {
            if let Some(error) = &entry.failure {
                if error.effects == EffectKnowledge::None && !state.uncertain && !state.quarantined
                {
                    return Submission::Refused(Refusal {
                        reason: error.reason.clone(),
                    });
                }
                return Submission::Uncertain(EffectKnowledge::Unknown);
            }
            if state.uncertain || state.quarantined {
                return Submission::Uncertain(EffectKnowledge::Unknown);
            }
            return if self
                .original(admission.token())
                .is_ok_and(|old| old.request() == admission.request())
            {
                Submission::Accepted
            } else {
                Submission::Refused(Refusal {
                    reason: "vendor original operation was changed".into(),
                })
            };
        }
        let prepared = (|| {
            if admission.token().route() != &self.identity.route {
                return Err(refused("vendor operation has foreign original owners"));
            }
            self.activate(admission.activation())?;
            let state = self.state_mut()?;
            if state.operations.len() >= state.limits.operations {
                return Err(refused("vendor original operation credit exhausted"));
            }
            let bytes = encoded_size(admission.request(), state.limits.metadata_bytes)?
                .checked_add(activation_credit(
                    admission.activation().record(),
                    state.limits.metadata_bytes,
                )?)
                .and_then(|bytes| {
                    bytes.checked_add(
                        encoded_size(admission.token().route(), state.limits.metadata_bytes)
                            .ok()?,
                    )
                })
                .filter(|bytes| *bytes <= state.limits.metadata_bytes)
                .ok_or_else(|| {
                    refused("vendor original operation clone exceeds metadata credit")
                })?;
            state.metadata_used = state
                .metadata_used
                .checked_add(bytes)
                .filter(|used| *used <= state.limits.metadata_bytes)
                .ok_or_else(|| refused("vendor original operation metadata credit exhausted"))?;
            let original = Rc::new(admission.clone());
            state.operations.insert(
                operation.clone(),
                OriginalOperation {
                    original: Rc::clone(&original),
                    outcome: None,
                    outcome_validated: false,
                    failure: None,
                    close_attempted: false,
                    acknowledged: false,
                    cancellation: None,
                },
            );
            Ok(original)
        })();
        let original = match prepared {
            Ok(original) => original,
            Err(error) => {
                let no_effect = error.effects == EffectKnowledge::None
                    && self
                        .state()
                        .is_ok_and(|state| !state.uncertain && !state.quarantined);
                return if no_effect {
                    Submission::Refused(Refusal {
                        reason: error.reason,
                    })
                } else {
                    Submission::Uncertain(EffectKnowledge::Unknown)
                };
            }
        };
        let result = self
            .state_mut()
            .and_then(|state| state.exchange(VendorCnpAction::Begin(&original)))
            .and_then(|evidence| self.cache_evidence(admission.token(), evidence));
        match result {
            Ok(()) => Submission::Accepted,
            Err(error) => {
                let no_effect = error.effects == EffectKnowledge::None
                    && self
                        .state()
                        .is_ok_and(|state| !state.uncertain && !state.quarantined);
                if no_effect {
                    let reason = error.reason.clone();
                    if let Ok(state) = self.state_mut()
                        && let Some(entry) = state.operations.get_mut(&operation)
                    {
                        entry.failure = Some(error);
                    }
                    Submission::Refused(Refusal { reason })
                } else {
                    self.contain_failure(&operation, error);
                    Submission::Uncertain(EffectKnowledge::Unknown)
                }
            }
        }
    }

    fn poll_operation(
        &mut self,
        token: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        let original = match self.original(token) {
            Ok(original) => original,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if let Ok(state) = self.state()
            && let Some(entry) = state.operations.get(token.operation())
        {
            if let Some(error) = &entry.failure {
                return Poll::Ready(Err(unknown(&error.reason)));
            }
            if let Some(outcome) = &entry.outcome {
                if !entry.outcome_validated {
                    return Poll::Ready(Err(unknown(
                        "original vendor outcome remains unvalidated",
                    )));
                }
                return Poll::Ready(Ok(outcome.clone()));
            }
        }
        let result = self
            .state_mut()
            .and_then(|state| state.exchange(VendorCnpAction::Poll(&original)))
            .and_then(|evidence| self.cache_evidence(token, evidence));
        if let Err(error) = result {
            self.contain_failure(token.operation(), error);
            return Poll::Ready(Err(unknown("vendor original poll remains contained")));
        }
        match self
            .state()
            .ok()
            .and_then(|state| state.operations.get(token.operation()))
        {
            Some(entry) if entry.outcome.is_some() => Poll::Ready(
                entry
                    .outcome
                    .clone()
                    .ok_or_else(|| unknown("vendor outcome absent")),
            ),
            _ => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.original(original.token())?;
        let state = self.state()?;
        state.current()?;
        if outcome.operation != *original.token().operation()
            || outcome.node != self.identity.descriptor.id
            || outcome.owners != self.identity.route.owners
        {
            return Err(refused(
                "vendor terminal outcome changed its original operation/owner roster",
            ));
        }
        let (identity, codec) = state.identity_and_codec()?;
        codec.validate_outcome(identity, original, outcome, &state.peer)?;
        state.current()
    }

    fn request_cancel(&mut self, token: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        let original = self.original(token)?;
        let state = self.state_mut()?;
        if let Some(disposition) = state
            .operations
            .get(token.operation())
            .and_then(|entry| entry.cancellation)
        {
            return Ok(disposition);
        }
        match state.exchange(VendorCnpAction::Cancel(&original))? {
            VendorCnpEvidence::Cancellation(disposition) => {
                state
                    .operations
                    .get_mut(token.operation())
                    .ok_or_else(|| unknown("vendor original cancellation custody absent"))?
                    .cancellation = Some(disposition);
                Ok(disposition)
            }
            _ => Err(unknown(
                "vendor cancellation lacks original native disposition",
            )),
        }
    }

    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        let retained = match self.original(original.token()) {
            Ok(retained)
                if retained.request() == original.request()
                    && matches!(retained.request(), OperationRequest::QuantumBegin { .. }) =>
            {
                retained
            }
            _ => {
                return Submission::Refused(Refusal {
                    reason: "vendor closure is not its original Begin".into(),
                });
            }
        };
        if let Ok(state) = self.state_mut()
            && let Some(entry) = state.operations.get_mut(original.token().operation())
        {
            if entry.outcome_validated && entry.outcome.is_some() {
                return Submission::Accepted;
            }
            if entry.close_attempted {
                return Submission::Uncertain(EffectKnowledge::Unknown);
            }
            entry.close_attempted = true;
        }
        let result = self
            .state_mut()
            .and_then(|state| state.exchange(VendorCnpAction::Close(&retained)))
            .and_then(|evidence| self.cache_evidence(original.token(), evidence));
        match result {
            Ok(()) => Submission::Accepted,
            Err(error) => {
                self.contain_failure(original.token().operation(), error);
                Submission::Uncertain(EffectKnowledge::Unknown)
            }
        }
    }

    fn acknowledge_publication(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        let original = self.original(token)?;
        let state = self.state()?;
        let entry = state
            .operations
            .get(token.operation())
            .ok_or_else(|| refused("vendor original publication absent"))?;
        if !entry.outcome_validated {
            return Err(unknown("vendor publication outcome is not authenticated"));
        }
        if entry
            .outcome
            .as_ref()
            .is_none_or(|outcome| outcome.retained_outputs != outputs)
        {
            return Err(refused(
                "vendor acknowledgement changes the complete original publication roster",
            ));
        }
        if entry.acknowledged {
            return Ok(());
        }
        match self
            .state_mut()?
            .exchange(VendorCnpAction::Acknowledge(&original, outputs))?
        {
            VendorCnpEvidence::Acknowledged => {
                let state = self.state_mut()?;
                let entry = state
                    .operations
                    .get_mut(token.operation())
                    .ok_or_else(|| unknown("vendor original publication custody absent"))?;
                entry.acknowledged = true;
                Ok(())
            }
            _ => Err(unknown(
                "vendor consumption lacks authentic original publication acknowledgement",
            )),
        }
    }

    fn read_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.original(original.token())?;
        let state = self.state()?;
        state.current()?;
        if references.len() > state.limits.outputs {
            return Err(refused("vendor original evidence object credit exhausted"));
        }
        let mut total = 0usize;
        for reference in references {
            let bytes = state
                .peer
                .journal
                .content()
                .get(reference)
                .map_err(super::protocol::native)?;
            total = total
                .checked_add(bytes.len())
                .filter(|total| *total <= state.limits.metadata_bytes)
                .ok_or_else(|| refused("vendor original evidence byte credit exhausted"))?;
            reference.verify(bytes).map_err(super::contract)?;
        }
        let objects = references
            .iter()
            .map(|reference| {
                let bytes = state
                    .peer
                    .journal
                    .content()
                    .get(reference)
                    .map_err(super::protocol::native)?;
                Ok(InputPayload {
                    reference: reference.clone(),
                    bytes: bytes.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?;
        self.validate_operation_evidence(original, references, &objects)?;
        Ok(objects)
    }

    fn validate_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        self.original(original.token())?;
        let state = self.state()?;
        state.current()?;
        if references.len() != objects.len()
            || references.iter().zip(objects).any(|(reference, object)| {
                reference != &object.reference
                    || state.peer.journal.content().get(reference).ok()
                        != Some(object.bytes.as_slice())
            })
        {
            return Err(refused(
                "vendor evidence is not the original complete raw byte roster",
            ));
        }
        let (identity, codec) = state.identity_and_codec()?;
        codec.validate_evidence(identity, original, references, objects, &state.peer)?;
        state.current()
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        let state = self.state().map_err(|error| Refusal {
            reason: error.reason,
        })?;
        state.current().map_err(|error| Refusal {
            reason: error.reason,
        })?;
        let facet = state
            .facets
            .iter()
            .find(|facet| facet.kind == kind)
            .ok_or_else(|| Refusal {
                reason: "vendor selected facet is unsupported".into(),
            })?;
        Ok(match kind {
            FacetKind::ExactExecution => NodeFacet::ExactExecution(facet),
            FacetKind::QuantizedExecution => NodeFacet::QuantizedExecution(facet),
            FacetKind::PhysicalPause => NodeFacet::PhysicalPause(facet),
            FacetKind::Preservation => NodeFacet::Preservation(facet),
            FacetKind::Replay => NodeFacet::Replay(facet),
            FacetKind::FaultInjection => NodeFacet::FaultInjection(facet),
            FacetKind::Coverage => NodeFacet::Coverage(facet),
            FacetKind::Introspection => NodeFacet::Introspection(facet),
            FacetKind::Debugging => NodeFacet::Debugging(facet),
            FacetKind::TerminalAssertions => NodeFacet::TerminalAssertions(facet),
        })
    }

    fn quarantine_resources(&mut self) {
        if let Ok(state) = self.state_mut() {
            if state.quarantined {
                return;
            }
            state.quarantined = true;
            state.uncertain = true;
            state.peer.session.close();
            if let Err(error) = state.cleanup.request_containment(&mut state.peer) {
                state.containment_error = Some(error);
            }
            if let (Some(identity), Some(codec)) = (&state.identity, &state.codec) {
                // Ownership and the once-only marker precede external cleanup.
                if let Err(error) = codec.request_containment(identity, &mut state.peer) {
                    state.containment_error = Some(error);
                }
            }
        }
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        let state = match self.state_mut() {
            Ok(state) => state,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if !state.quarantined {
            return Poll::Ready(Err(refused("vendor reclamation was not contained")));
        }
        if state.peer.reaped.is_none() {
            match state.peer.child.try_wait() {
                Ok(Some(wait)) => state.peer.reaped = Some(wait),
                Ok(None) => {
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => return Poll::Ready(Err(unknown(&error.to_string()))),
            }
        }
        let (identity, codec) = match state.identity_and_codec() {
            Ok(pair) => pair,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if !identity.route.owners.contains(owner) {
            return Poll::Ready(Err(refused(
                "vendor reclamation belongs to another original owner",
            )));
        }
        codec.poll_reclamation(identity, owner, &state.peer, context)
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        let state = self.state()?;
        if !state.quarantined
            || state.peer.reaped.is_none()
            || !self.identity.route.owners.contains(&receipt.owner)
        {
            return Err(refused(
                "vendor lacks original kernel wait and complete native owner scope",
            ));
        }
        let (identity, codec) = state.identity_and_codec()?;
        codec.validate_reclamation(identity, &state.peer, receipt)
    }
}

impl FacetDescription for VendorCnpFacet {
    fn profile(&self) -> &Id {
        &self.profile
    }
}

fn input_credit(batch: &RuntimeInputBatch, maximum: usize) -> Result<usize, OperationFailure> {
    let mut bytes = activation_credit(batch.activation().record(), maximum)?;
    for size in [
        encoded_size(batch.deliveries(), maximum)?,
        encoded_size(batch.payloads(), maximum)?,
        encoded_size(batch.owners(), maximum)?,
        encoded_size(batch.inventory(), maximum)?,
    ] {
        bytes = bytes
            .checked_add(size)
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(|| refused("vendor frozen input metadata exceeds original credit"))?;
    }
    Ok(bytes)
}

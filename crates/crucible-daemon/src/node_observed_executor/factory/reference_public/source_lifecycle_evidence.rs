//! Reads the fixed source profile's original typed lifecycle evidence closure.
//!
//! Each edge has a codec role selected by its containing typed record. Opaque
//! event payloads, native measurements and coordinator bodies are never searched
//! for JSON-shaped references. The finite work and result slots are reserved
//! before process creation; successful verification confers no native authority.

use crucible::node_adapters::cnp::{CnpCompletedLifecyclePhase, CnpCompletedLifecycleScope};
use crucible_node_contract::{
    ActivationManifest, ActivationReadyRecord, ClosedGateRecord, ClosureKind, ContentRef,
    ControlReceipt, ControlReceiptKind, Event, EventStage, Extensions, InputBatch,
    InputCustodyRecord, NodeBinding, ObservationBatch, OperatingMode, OwnerBinding,
    PendingInventory, PendingKind, PhysicalStop, ReceiptIssuer, StopReceipt, U64, Validate,
    Visibility, canonical,
};
use crucible_node_provider::{
    ProviderError,
    bodies::{BeginArguments, MethodResult, RequestBody},
    client::RecordedReferenceObservation,
    reference_device::{DeviceGrant, DeviceReceipt},
    reference_service::PublicationConsumption,
};
use serde::{Serialize, de::DeserializeOwned};

use super::source_lifecycle_world::SourceLifecycleWorld;

const MAXIMUM_OBJECTS: usize = 1024;
const MAXIMUM_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_JSON_BYTES: usize = 256 * 1024;
const MAXIMUM_METADATA_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Control(ControlReceiptKind, usize),
    Ready(usize),
    Gate(usize),
    PhysicalStatus(usize),
    InputCustody(usize),
    InputBatch(usize),
    Pending(usize),
    Stop(usize),
    Observation(usize),
    CommittedObservation(usize),
    Native(usize),
    Consumption(usize),
    Manifest,
    Coordinator,
    Payload,
}

struct RoleReference {
    reference: ContentRef,
    role: Role,
}

/// Borrows independently authenticated original archives and fixed source axes.
/// These read-only bodies grant no source, execution or publication authority.
pub(super) struct SourceLifecycleEvidenceContext<'a> {
    pub(super) original: &'a RecordedReferenceObservation,
    pub(super) peer_originals: &'a [RecordedReferenceObservation],
    pub(super) bindings: &'a [(NodeBinding, OwnerBinding)],
    pub(super) grants: &'a [DeviceGrant],
    pub(super) original_companion_pids: &'a [u32],
    pub(super) world: &'a SourceLifecycleWorld,
}

struct ReadContext<'a> {
    scope: &'a CnpCompletedLifecycleScope,
    bindings: &'a [(NodeBinding, OwnerBinding)],
    grants: &'a [DeviceGrant],
    original_companion_pids: &'a [u32],
    originals: &'a [&'a RecordedReferenceObservation],
    world: &'a SourceLifecycleWorld,
}

pub(super) struct SourceLifecycleEvidence {
    queue: Vec<RoleReference>,
    verified: Vec<ContentRef>,
    metadata_bytes: usize,
    body_bytes: usize,
    #[cfg(test)]
    refusal_site: Option<&'static str>,
}

impl SourceLifecycleEvidence {
    /// Reserves the installed finite role queue and verified-reference slots.
    ///
    /// # Errors
    /// Refuses inability to reserve the complete pre-effect metadata population.
    pub(super) fn reserve() -> Result<Self, ProviderError> {
        let mut queue = Vec::new();
        let mut verified = Vec::new();
        queue
            .try_reserve_exact(MAXIMUM_OBJECTS)
            .map_err(|_| credits())?;
        verified
            .try_reserve_exact(MAXIMUM_OBJECTS)
            .map_err(|_| credits())?;
        Ok(Self {
            queue,
            verified,
            metadata_bytes: 0,
            body_bytes: 0,
            #[cfg(test)]
            refusal_site: None,
        })
    }

    /// Authenticates the retained source codec closure without constructing proof.
    ///
    /// # Errors
    /// Refuses missing bodies, role aliases, unsupported edges, scope drift or
    /// exhausted read credits. Returned references borrow pre-reserved slots and
    /// are valid only until the next verification on this reader.
    pub(super) fn verify(
        &mut self,
        scope: &CnpCompletedLifecycleScope,
        body: &RequestBody,
        context: SourceLifecycleEvidenceContext<'_>,
    ) -> Result<&[ContentRef], ProviderError> {
        let SourceLifecycleEvidenceContext {
            original,
            peer_originals,
            bindings,
            grants,
            original_companion_pids,
            world,
        } = context;
        self.queue.clear();
        self.verified.clear();
        self.metadata_bytes = 0;
        self.body_bytes = 0;
        #[cfg(test)]
        {
            self.refusal_site = None;
        }
        if !original.recording_complete
            || original.observed_unknown
            || original.recording_failure.0.is_some()
            || peer_originals.len() != 2
            || bindings.len() != 2
            || grants.len() != 6
            || original_companion_pids.len() != 2
            || original_companion_pids.contains(&0)
            || original.evidence.objects.len() > MAXIMUM_OBJECTS
        {
            return Err(changed());
        }
        let peer = bindings
            .iter()
            .position(|(binding, owner)| {
                binding.identity().ok().as_ref() == Some(&scope.binding_hash)
                    && owner.identity().ok().as_ref() == Some(&scope.owner_binding_hash)
            })
            .ok_or_else(changed)?;
        for (binding, owner) in bindings {
            binding.validate()?;
            owner.validate()?;
            if binding.compatibility.execution_owner != owner.owner {
                return Err(changed());
            }
        }
        if original.evidence.scope.session_id != bindings[peer].0.authority.session_id
            || original.evidence.scope.incarnation_id != bindings[peer].0.authority.incarnation_id
            || original.evidence.scope.compatibility != bindings[peer].0.compatibility
        {
            return Err(changed());
        }
        for (snapshot, (binding, _)) in peer_originals.iter().zip(bindings) {
            if !snapshot.recording_complete
                || snapshot.observed_unknown
                || snapshot.recording_failure.0.is_some()
                || snapshot.evidence.objects.len() > MAXIMUM_OBJECTS
                || snapshot.evidence.scope.session_id != binding.authority.session_id
                || snapshot.evidence.scope.incarnation_id != binding.authority.incarnation_id
                || snapshot.evidence.scope.compatibility != binding.compatibility
            {
                return Err(changed());
            }
        }
        let sources = [original, &peer_originals[0], &peer_originals[1]];
        self.roots(scope, body, peer, bindings, &sources)?;
        let context = ReadContext {
            scope,
            bindings,
            grants,
            original_companion_pids,
            originals: &sources,
            world,
        };
        let mut cursor = 0;
        while cursor < self.queue.len() {
            let reference = self.queue[cursor].reference.clone();
            let role = self.queue[cursor].role;
            #[cfg(test)]
            {
                self.refusal_site = Some("missing-body");
            }
            let bytes = observed(&sources, &reference)?;
            reference.verify(bytes)?;
            #[cfg(test)]
            {
                self.refusal_site = Some("typed-media");
            }
            if !matches!(role, Role::Coordinator | Role::Payload)
                && reference.media_type != "application/json"
            {
                return Err(changed());
            }
            self.body_bytes = self
                .body_bytes
                .checked_add(bytes.len())
                .ok_or_else(credits)?;
            if self.body_bytes > MAXIMUM_BYTES {
                return Err(credits());
            }
            #[cfg(test)]
            {
                self.refusal_site = Some(match role {
                    Role::Stop(_) => "stop",
                    Role::Observation(_) | Role::CommittedObservation(_) => "observation",
                    _ => "other",
                });
            }
            self.read(role, bytes, &context)?;
            self.verified.push(reference);
            cursor += 1;
        }
        Ok(&self.verified)
    }

    /// Identifies the last rejection stage for inert counterfactual tests only.
    #[cfg(test)]
    pub(super) fn refusal_site(&self) -> Option<&'static str> {
        self.refusal_site
    }

    fn enqueue(&mut self, reference: &ContentRef, role: Role) -> Result<(), ProviderError> {
        reference.validate()?;
        if let Some(existing) = self.queue.iter().find(|row| row.reference == *reference) {
            return if existing.role == role {
                Ok(())
            } else {
                #[cfg(test)]
                {
                    self.refusal_site = Some("role-alias");
                }
                Err(changed())
            };
        }
        if self.queue.len() == MAXIMUM_OBJECTS {
            return Err(credits());
        }
        let cost = canonical_bytes(reference)?.len();
        self.metadata_bytes = self.metadata_bytes.checked_add(cost).ok_or_else(credits)?;
        if self.metadata_bytes > MAXIMUM_METADATA_BYTES {
            return Err(credits());
        }
        self.queue.push(RoleReference {
            reference: reference.clone(),
            role,
        });
        Ok(())
    }

    fn roots(
        &mut self,
        scope: &CnpCompletedLifecycleScope,
        body: &RequestBody,
        peer: usize,
        bindings: &[(NodeBinding, OwnerBinding)],
        original: &[&RecordedReferenceObservation],
    ) -> Result<(), ProviderError> {
        use CnpCompletedLifecyclePhase as Phase;
        match (scope.phase, body, &scope.original_result) {
            (Phase::Prepared, RequestBody::Activate(_), MethodResult::Activate(result)) => {
                exact_roots(scope, &[&result.activation_receipt])?;
                self.enqueue(
                    &result.activation_receipt,
                    Role::Control(ControlReceiptKind::ActivationReady, peer),
                )?;
            }
            (
                Phase::WorldActivated,
                RequestBody::WorldActivate(request),
                MethodResult::WorldActivate(result),
            ) => {
                exact_roots(scope, &[&result.activation_receipt])?;
                self.enqueue(
                    &result.activation_receipt,
                    Role::Control(ControlReceiptKind::ActivationReady, peer),
                )?;
                let manifest: ActivationManifest =
                    typed(observed(original, &request.activation_manifest)?)?;
                if manifest.transaction_id != request.transaction_id
                    || manifest.gate_id != request.gate_id
                    || manifest.activation_id != request.activation_id
                    || manifest.world_generation != request.world_generation
                    || manifest.world_binding_hash != request.world_binding_hash
                    || !manifest.extensions.is_empty()
                {
                    return Err(changed());
                }
                self.enqueue(&request.activation_manifest, Role::Manifest)?;
            }
            (Phase::InputAccepted, RequestBody::Input(request), MethodResult::Input(result)) => {
                exact_roots(scope, &[&result.custody_receipt])?;
                self.enqueue(
                    &result.custody_receipt,
                    Role::Control(ControlReceiptKind::InputCustody, peer),
                )?;
                let batch = InputBatch {
                    schema_version: 1,
                    execution_owner_id: bindings[peer].1.owner.id.clone(),
                    input_epoch: request.input_epoch.clone(),
                    batch_id: request.batch_id.clone(),
                    batch_sequence: request.batch_sequence,
                    events: request.events.clone(),
                    extensions: Extensions::new(),
                };
                batch.validate()?;
                if batch.identity()? != request.batch_hash {
                    return Err(changed());
                }
                let bytes = canonical_bytes(&batch)?;
                let reference = ContentRef {
                    hash: canonical::hash("cnp.blob.v1", &bytes)?,
                    length: U64::new(u64::try_from(bytes.len()).map_err(|_| credits())?),
                    media_type: "application/json".to_owned(),
                };
                if observed(original, &reference)? != bytes {
                    return Err(changed());
                }
                self.enqueue(&reference, Role::InputBatch(peer))?;
            }
            (
                Phase::WindowCompleted,
                RequestBody::Begin(request),
                MethodResult::QuantumBegin(result),
            ) => {
                exact_roots(
                    scope,
                    &[
                        &result.stop_receipt,
                        &result.observation_batch,
                        &result.pending_inventory,
                        &result.physical_measurement_ref,
                    ],
                )?;
                self.enqueue(&result.stop_receipt, Role::Stop(peer))?;
                self.enqueue(&result.observation_batch, Role::Observation(peer))?;
                self.enqueue(&result.pending_inventory, Role::Pending(peer))?;
                self.enqueue(&result.physical_measurement_ref, Role::Native(peer))?;
                let BeginArguments::QuantumBegin(arguments) = request.decoded_arguments()? else {
                    return Err(changed());
                };
                self.enqueue(&arguments.input_batch, Role::InputBatch(peer))?;
            }
            (
                Phase::PublicationClosed,
                RequestBody::QuantumClose(_),
                MethodResult::QuantumClose(result),
            ) => {
                exact_roots(
                    scope,
                    &[
                        &result.committed_batch,
                        &result.stop_receipt,
                        &result.pending_inventory,
                    ],
                )?;
                self.enqueue(&result.committed_batch, Role::CommittedObservation(peer))?;
                self.enqueue(&result.stop_receipt, Role::Stop(peer))?;
                self.enqueue(&result.pending_inventory, Role::Pending(peer))?;
            }
            (Phase::PublicationConsumed, RequestBody::Retire(request), MethodResult::Retire(_)) => {
                let receipt = request.custody_receipt.0.as_ref().ok_or_else(changed)?;
                if scope.evidence_roots.len() != 3 || scope.evidence_roots[0] != *receipt {
                    return Err(changed());
                }
                self.enqueue(receipt, Role::Consumption(peer))?;
                self.enqueue(&scope.evidence_roots[1], Role::Stop(peer))?;
                self.enqueue(&scope.evidence_roots[2], Role::Observation(peer))?;
            }
            _ => return Err(changed()),
        }
        Ok(())
    }

    fn read(
        &mut self,
        role: Role,
        bytes: &[u8],
        context: &ReadContext<'_>,
    ) -> Result<(), ProviderError> {
        let ReadContext {
            scope,
            bindings,
            grants,
            original_companion_pids,
            originals: original,
            world,
        } = *context;
        match role {
            Role::Control(kind, peer) => {
                let record: ControlReceipt = typed(bytes)?;
                let (binding, owner) = &bindings[peer];
                if record.kind != kind
                    || record.issuer != ReceiptIssuer::Provider
                    || record.session_id != binding.authority.session_id
                    || record.incarnation_id != binding.authority.incarnation_id
                    || record.owner_ids != [owner.owner.id.clone()]
                    || !record.extensions.is_empty()
                    || (record.world_generation.get() != 0
                        && record.world_generation != scope.activation.generation)
                {
                    return Err(changed());
                }
                let next = match kind {
                    ControlReceiptKind::ActivationReady => Role::Ready(peer),
                    ControlReceiptKind::ClosedGate => Role::Gate(peer),
                    ControlReceiptKind::InputCustody => Role::InputCustody(peer),
                    _ => return Err(changed()),
                };
                self.enqueue(&record.record_ref, next)?;
            }
            Role::Ready(peer) => {
                let record: ActivationReadyRecord = typed(bytes)?;
                if record.activation_id != scope.activation.activation_id
                    || record.world_generation != scope.activation.generation
                    || record.world_binding_hash != scope.activation.world_binding_hash
                    || record.owner_ids != [bindings[peer].1.owner.id.clone()]
                    || !record.extensions.is_empty()
                    || record.evidence_refs.len() != 1
                {
                    return Err(changed());
                }
                let gate_control: ControlReceipt =
                    typed(observed(original, &record.evidence_refs[0])?)?;
                let gate: ClosedGateRecord = typed(observed(original, &gate_control.record_ref)?)?;
                if gate.gate_id != record.gate_id || gate.prepared_token != record.prepared_token {
                    return Err(changed());
                }
                self.enqueue(
                    &record.evidence_refs[0],
                    Role::Control(ControlReceiptKind::ClosedGate, peer),
                )?;
            }
            Role::Gate(peer) => {
                let record: ClosedGateRecord = typed(bytes)?;
                if record.owner_ids != [bindings[peer].1.owner.id.clone()]
                    || !record.extensions.is_empty()
                    || record.evidence_refs != [record.physical_status_ref.clone()]
                {
                    return Err(changed());
                }
                self.enqueue(&record.physical_status_ref, Role::PhysicalStatus(peer))?;
            }
            Role::PhysicalStatus(peer) => {
                let record: PhysicalStatus = json(bytes)?;
                if record.child_pid.get() != u64::from(original_companion_pids[peer])
                    || record.application_status != "parked"
                    || record.physical_pause != "unknown"
                    || !bindings[peer]
                        .0
                        .compatibility
                        .implementation
                        .artifacts
                        .iter()
                        .any(|artifact| {
                            artifact.id.as_str() == "device"
                                && artifact.content == record.native_executable
                        })
                {
                    return Err(changed());
                }
            }
            Role::InputCustody(peer) => {
                let record: InputCustodyRecord = typed(bytes)?;
                owner_input(
                    peer,
                    &record.execution_owner_id,
                    record.owner_generation,
                    &record.input_epoch,
                    bindings,
                )?;
                if !record.extensions.is_empty() || !record.evidence_refs.is_empty() {
                    return Err(changed());
                }
                let pending: PendingInventory =
                    typed(observed(original, &record.pending_inventory)?)?;
                let mut accepted = pending
                    .entries
                    .iter()
                    .filter(|entry| entry.kind == PendingKind::Input);
                let entry = accepted.next().ok_or_else(changed)?;
                if accepted.next().is_some() {
                    return Err(changed());
                }
                let batch: InputBatch = typed(observed(original, &entry.state_ref)?)?;
                if record.batch_hashes != [batch.identity()?]
                    || record.input_watermark != batch.batch_sequence
                    || pending.input_watermark != record.input_watermark
                {
                    return Err(changed());
                }
                self.enqueue(&record.pending_inventory, Role::Pending(peer))?;
            }
            Role::InputBatch(peer) => {
                let record: InputBatch = typed(bytes)?;
                if record.execution_owner_id != bindings[peer].1.owner.id
                    || record.input_epoch != bindings[peer].0.authority.input_epoch
                    || !record.extensions.is_empty()
                {
                    return Err(changed());
                }
                self.events(&record.events, EventStage::Delivery, bindings, original)?;
            }
            Role::Pending(peer) => {
                let record: PendingInventory = typed(bytes)?;
                owner_input(
                    peer,
                    &record.execution_owner_id,
                    record.owner_generation,
                    &record.input_epoch,
                    bindings,
                )?;
                world_owner(
                    peer,
                    &record.owner_binding_hash,
                    &record.world_binding_hash,
                    bindings,
                    scope,
                )?;
                if !record.complete
                    || !record.extensions.is_empty()
                    || record.activation_id.as_ref() != Some(&scope.activation.activation_id)
                    || record.world_generation != scope.activation.generation
                {
                    return Err(changed());
                }
                if record.entries.len() > MAXIMUM_OBJECTS {
                    return Err(credits());
                }
                for entry in record.entries {
                    if entry.owner_id != bindings[peer].1.owner.id
                        || !entry.extensions.is_empty()
                        || entry.deadline.evidence.is_some()
                    {
                        return Err(changed());
                    }
                    let next = match entry.kind {
                        PendingKind::Input => Role::InputBatch(peer),
                        PendingKind::Output => Role::Observation(peer),
                        _ => return Err(changed()),
                    };
                    self.enqueue(&entry.state_ref, next)?;
                }
            }
            Role::Stop(peer) => {
                let record: StopReceipt = typed(bytes)?;
                world_owner(
                    peer,
                    &record.owner_binding_hash,
                    &record.world_binding_hash,
                    bindings,
                    scope,
                )?;
                if record.session_id != bindings[peer].0.authority.session_id
                    || record.incarnation_id != bindings[peer].0.authority.incarnation_id
                    || record.execution_owner_id != bindings[peer].1.owner.id
                    || record.owner_generation != bindings[peer].0.authority.owner_generation
                    || record.activation_id != scope.activation.activation_id
                    || record.world_generation != scope.activation.generation
                    || Some(&record.operation_id) != scope.operation_id.as_ref()
                    || record.grant_id.as_ref()
                        != scope.grant.as_ref().map(|grant| &grant.window_id)
                    || !record.extensions.is_empty()
                    || record.evidence_refs != [record.physical_measurement_ref.clone()]
                    || record.mode != OperatingMode::Quantized
                    || record.physical_stop != PhysicalStop::ObservationClosed
                    || record.cause.as_str() != "application-window-complete"
                    || record.prefix_kind != ClosureKind::Through
                    || record.participant_ids != bindings[peer].1.owner.participant_ids
                    || !record.output_lower_bounds.is_empty()
                {
                    return Err(changed());
                }
                let native: DeviceReceipt =
                    json(observed(original, &record.physical_measurement_ref)?)?;
                let reached = crucible_node_contract::Position::new(
                    native.grant.publication.time_ps,
                    U64::new(0),
                    crucible_node_contract::Phase::BoundaryControl,
                );
                if record.grant_id.as_ref() != Some(&native.grant.window_id)
                    || record.reached != Some(reached)
                    || record.production_prefix != native.grant.publication
                    || scope.grant.as_ref() != Some(&native.grant)
                {
                    return Err(changed());
                }
                self.enqueue(
                    &record.input_custody,
                    Role::Control(ControlReceiptKind::InputCustody, peer),
                )?;
                self.enqueue(&record.pending_inventory, Role::Pending(peer))?;
                self.enqueue(&record.observation_batch, Role::Observation(peer))?;
                self.enqueue(&record.physical_measurement_ref, Role::Native(peer))?;
            }
            Role::Observation(peer) | Role::CommittedObservation(peer) => {
                let record: ObservationBatch = typed(bytes)?;
                let visibility = if matches!(role, Role::CommittedObservation(_)) {
                    Visibility::Committed
                } else {
                    Visibility::Staged
                };
                if record.visibility != visibility {
                    return Err(changed());
                }
                world_owner(
                    peer,
                    &record.owner_binding_hash,
                    &record.world_binding_hash,
                    bindings,
                    scope,
                )?;
                if record.execution_owner_id != bindings[peer].1.owner.id
                    || record.owner_generation != bindings[peer].0.authority.owner_generation
                    || record.activation_id != scope.activation.activation_id
                    || record.world_generation != scope.activation.generation
                    || Some(&record.operation_id) != scope.operation_id.as_ref()
                    || record.grant_id.as_ref()
                        != scope.grant.as_ref().map(|grant| &grant.window_id)
                    || !record.extensions.is_empty()
                {
                    return Err(changed());
                }
                let native: DeviceReceipt = json(observed(original, &record.measurement_ref)?)?;
                if record.grant_id.as_ref() != Some(&native.grant.window_id)
                    || scope.grant.as_ref() != Some(&native.grant)
                    || record.events.len() != 1
                    || record.events[0].source.node_id != bindings[peer].0.compatibility.node_id
                    || record.events[0].provenance_ref != record.measurement_ref
                {
                    return Err(changed());
                }
                self.enqueue(&record.measurement_ref, Role::Native(peer))?;
                self.events(&record.events, EventStage::Publication, bindings, original)?;
            }
            Role::Native(peer) => {
                let record: DeviceReceipt = json(bytes)?;
                if record.grant.owner_id != bindings[peer].1.owner.id
                    || record.grant.incarnation_id != bindings[peer].0.authority.incarnation_id
                    || record.grant.generation != bindings[peer].0.authority.owner_generation
                    || !grants.contains(&record.grant)
                    || !record.application_parked
                    || record.measured_host_ns > record.grant.host_budget_ns
                {
                    return Err(changed());
                }
            }
            Role::Consumption(peer) => {
                let record: PublicationConsumption = typed(bytes)?;
                if record.session_id != bindings[peer].0.authority.session_id
                    || record.incarnation_id != bindings[peer].0.authority.incarnation_id
                    || record.world_binding_hash != scope.activation.world_binding_hash
                    || Some(&record.operation_id) != scope.operation_id.as_ref()
                    || scope.grant.as_ref().is_none_or(|grant| {
                        record.grant_id != grant.window_id
                            || record.publication != grant.publication
                    })
                    || !record.extensions.is_empty()
                    || record.stop_receipt != scope.evidence_roots[1]
                {
                    return Err(changed());
                }
                let batch: ObservationBatch = typed(observed(original, &scope.evidence_roots[2])?)?;
                if batch.identity()? != record.observation_batch_hash {
                    return Err(changed());
                }
                self.enqueue(&record.stop_receipt, Role::Stop(peer))?;
            }
            Role::Manifest => {
                let record: ActivationManifest = typed(bytes)?;
                let coordinator = observed(original, &record.coordinator_state_ref)?;
                world.verify(&record, coordinator)?;
                self.enqueue(&record.coordinator_state_ref, Role::Coordinator)?;
                for owner in record.owners {
                    let peer = bindings
                        .iter()
                        .position(|(_, binding)| binding.owner.id == owner.owner_id)
                        .ok_or_else(changed)?;
                    self.enqueue(
                        &owner.ready_receipt,
                        Role::Control(ControlReceiptKind::ActivationReady, peer),
                    )?;
                }
            }
            Role::Coordinator | Role::Payload => {}
        }
        Ok(())
    }

    fn events(
        &mut self,
        events: &[Event],
        expected_stage: EventStage,
        bindings: &[(NodeBinding, OwnerBinding)],
        original: &[&RecordedReferenceObservation],
    ) -> Result<(), ProviderError> {
        if events.len() > MAXIMUM_OBJECTS {
            return Err(credits());
        }
        for event in events {
            event.validate()?;
            let producer = bindings
                .iter()
                .position(|(binding, _)| binding.compatibility.node_id == event.source.node_id)
                .ok_or_else(changed)?;
            if event.stage != expected_stage
                || !event.extensions.is_empty()
                || !event.causal_parent_ids.is_empty()
            {
                return Err(changed());
            }
            // Both event stages use this installed profile's original native
            // receipt codec. Delivery retains the producer proof unchanged;
            // coordinates alone never select a producer or manufacture an ID.
            let native: DeviceReceipt = json(observed(original, &event.provenance_ref)?)?;
            if native.grant.publication != event.publication_position
                || canonical_bytes(&native.output)? != observed(original, &event.payload)?
            {
                return Err(changed());
            }
            self.enqueue(&event.payload, Role::Payload)?;
            self.enqueue(&event.provenance_ref, Role::Native(producer))?;
        }
        Ok(())
    }
}

#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalStatus {
    child_pid: U64,
    application_status: String,
    native_executable: ContentRef,
    physical_pause: String,
}

fn observed<'a>(
    originals: &[&'a RecordedReferenceObservation],
    reference: &ContentRef,
) -> Result<&'a [u8], ProviderError> {
    if reference.length.get() > MAXIMUM_BYTES as u64 {
        return Err(credits());
    }
    let mut retained: Option<&'a [u8]> = None;
    for original in originals {
        let mut matches = original
            .evidence
            .objects
            .iter()
            .filter(|object| object.reference == *reference);
        if let Some(object) = matches.next() {
            if matches.next().is_some() {
                return Err(changed());
            }
            object.reference.verify(object.bytes.as_slice())?;
            if retained.is_some_and(|bytes| bytes != object.bytes.as_slice()) {
                return Err(changed());
            }
            retained = Some(object.bytes.as_slice());
        }
    }
    retained.ok_or_else(changed)
}

fn json<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, ProviderError> {
    if bytes.len() > MAXIMUM_JSON_BYTES {
        return Err(credits());
    }
    let record: T = serde_json::from_slice(bytes).map_err(|_| changed())?;
    if canonical_bytes(&record)? != bytes {
        return Err(changed());
    }
    Ok(record)
}

fn typed<T: DeserializeOwned + Serialize + Validate>(bytes: &[u8]) -> Result<T, ProviderError> {
    let record: T = json(bytes)?;
    record.validate()?;
    Ok(record)
}

fn exact_roots(
    scope: &CnpCompletedLifecycleScope,
    roots: &[&ContentRef],
) -> Result<(), ProviderError> {
    if scope.evidence_roots.len() != roots.len()
        || scope
            .evidence_roots
            .iter()
            .zip(roots)
            .any(|(actual, expected)| actual != *expected)
    {
        return Err(changed());
    }
    Ok(())
}

fn owner_input(
    peer: usize,
    owner: &crucible_node_contract::Id,
    generation: U64,
    epoch: &crucible_node_contract::Id,
    bindings: &[(NodeBinding, OwnerBinding)],
) -> Result<(), ProviderError> {
    if owner != &bindings[peer].1.owner.id
        || generation != bindings[peer].0.authority.owner_generation
        || epoch != &bindings[peer].0.authority.input_epoch
    {
        return Err(changed());
    }
    Ok(())
}

fn world_owner(
    peer: usize,
    owner: &crucible_node_contract::HashRef,
    world: &crucible_node_contract::HashRef,
    bindings: &[(NodeBinding, OwnerBinding)],
    scope: &CnpCompletedLifecycleScope,
) -> Result<(), ProviderError> {
    if owner != &bindings[peer].1.identity()? || world != &scope.activation.world_binding_hash {
        return Err(changed());
    }
    Ok(())
}

fn changed() -> ProviderError {
    ProviderError::Correlation("original typed lifecycle evidence differs")
}
fn credits() -> ProviderError {
    ProviderError::ResourceExhausted("typed lifecycle evidence read credits")
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?,
    )?)
}

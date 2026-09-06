//! Durable-before-I/O destination-slot attempt records.
//!
//! The record keeps the exact signed plan template, deadline-bearing request,
//! lease-bound envelope, logical-slot references, and any ready resource that a
//! reap must preserve:
//!
//! ```text
//! AOSDSE02 | flags:1 | action:1 | reserved:2 | request-id:16 |
//! assignment-target:56 | slot-id:16 | spec-digest:32 | spec-size:8 |
//! assignment:48 | semantic-digest:32 | plan-digest:32 |
//! template-digest:32 | lease-digest:32 | lease-generation:8 | deadline:8 |
//! ready-resource:120 | template-size:4 | body-size:4 | packet-size:4 |
//! template | body | packet | record-digest:32
//! ```

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod, DestinationSlotAction};
use aos_sandbox_core::format::{
    decode_broker_authorization_plan, decode_ownership_lease, decode_signature,
};
use aos_sandbox_core::model::SignaturePurpose;
use aos_sandbox_core::{
    BrokerAudience, DecodeLimits, MediaType, ObjectDigest, PortableMediaType, RawPairedClockSample,
    descriptor_for_bytes,
};
use aos_sandbox_protocol::semantics::canonical_destination_slot_semantics_v1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{MAXIMUM_REQUEST_BYTES, decode_request_envelope};
use buffa::Enumeration as _;
use sha2::{Digest as _, Sha256};

use super::{
    CARRIER_VERSION, DestinationSlotEffectError, METHOD, PreparedCurrentDestinationSlotDispatchV1,
    PreparedCurrentDestinationSlotResumeDispatchV1, PreparedOperation, RESPONSE_BYTES,
    ReadyResourceExpectation, decode_request, logical_slot_for_request, validate_target,
};
use crate::attachment_slot_state;
use crate::dispatch::{
    BrokerDispatchAttemptV1, BrokerDispatchSemanticIdentityV1, semantic_identity_digest,
    template_digest_from_parts, validate_durable_attempt_body, validate_durable_deadline_free_body,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_authority::{
    DurableRuntimeAuthorityReferenceV1, RuntimeAuthorityLimits, RuntimeAuthorityStateV1,
    RuntimeAuthorityStore, binding_for_durable_reference_in_validated_namespace,
};
use crate::{
    BrokerDispatchTemplateV1, Journal, JournalRecord, JournalTransaction, RecordNamespace,
};

#[cfg(test)]
mod tests;

const NAMESPACE: RecordNamespace = RecordNamespace::DestinationSlotAttempt;
const MAGIC: &[u8; 8] = b"AOSDSE02";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.destination-slot-attempt.v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.destination-slot-attempt.transaction.v2\0";
const FIXED_RECORD_BYTES: usize = 496;
const MAXIMUM_ATTEMPTS: usize = 16_384;
const MAXIMUM_NAMESPACE_BYTES: usize = 256 * 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 3 * MAXIMUM_REQUEST_BYTES + FIXED_RECORD_BYTES;
const FLAG_READY_EXPECTATION: u8 = 1;

/// Reports whether exact durable destination-slot admission committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationSlotAttemptAdmissionOutcomeV1 {
    /// The exact attempt became durable in this call.
    Admitted,
    /// The exact attempt was already durable under the operation identity.
    Replay,
}

/// Retains live authority for one destination-slot packet admitted before I/O.
pub struct DurableCurrentDestinationSlotAttemptV1 {
    live: LiveDispatch,
    resume_evidence: Option<crate::CurrentDestinationSlotReconciliationV1>,
    attempt: BrokerDispatchAttemptV1,
    record: Record,
    outcome: DestinationSlotAttemptAdmissionOutcomeV1,
    packet_source: PacketSource,
}

struct LiveDispatch {
    slot: crate::DurableAttachmentSlotV1,
    target: crate::runtime_scope::CurrentAssignmentTarget,
    template: BrokerDispatchTemplateV1,
}

#[derive(Clone, Copy)]
enum PacketSource {
    Recorded,
    Reconstructed,
}

impl DurableCurrentDestinationSlotAttemptV1 {
    /// Returns whether this call admitted or replayed the exact durable record.
    #[must_use]
    pub const fn outcome(&self) -> DestinationSlotAttemptAdmissionOutcomeV1 {
        self.outcome
    }

    /// Returns the logical operation identity used as Mount's request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id
    }

    /// Returns the digest of the complete durable attempt record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Borrows the exact signed and lease-bound packet ready for Mount.
    #[must_use]
    pub const fn dispatch_attempt(&self) -> &BrokerDispatchAttemptV1 {
        &self.attempt
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if let Some(evidence) = &self.resume_evidence {
            evidence.recheck(journal)?;
        }
        self.live.recheck(journal, clock)?;
        crate::mount_preparation::check_mount_deadline(
            self.attempt.deadline_boottime_nanoseconds(),
        )?;
        let history = History::load(journal)?;
        let matches = match self.packet_source {
            PacketSource::Recorded => self.record.matches_attempt(&self.live, &self.attempt)?,
            PacketSource::Reconstructed => self
                .record
                .matches_resumed_attempt(&self.live, &self.attempt)?,
        };
        if history.records.get(&self.record.request_id) != Some(&self.record) || !matches {
            return Err(DestinationSlotEffectError::Conflict);
        }
        if let Some(evidence) = &self.resume_evidence {
            evidence.recheck(journal)?;
        }
        self.live.recheck(journal, clock)?;
        Ok(())
    }

    pub(super) const fn record(&self) -> &Record {
        &self.record
    }

    pub(super) fn recheck_live<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.live.recheck(journal, clock)?;
        crate::mount_preparation::check_mount_deadline(
            self.attempt.deadline_boottime_nanoseconds(),
        )?;
        Ok(())
    }
}

impl LiveDispatch {
    fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        attachment_slot_state::recheck_current(journal, &self.slot)?;
        self.target.recheck(journal, clock)?;
        validate_target(&self.slot, &self.target)?;
        self.target.verify_mount_plan_version(
            journal,
            self.template.signed_plan(),
            CARRIER_VERSION,
            clock,
        )?;
        attachment_slot_state::recheck_current(journal, &self.slot)?;
        self.target.recheck(journal, clock)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Record {
    request_id: [u8; 16],
    assignment_target: DurableRuntimeAuthorityReferenceV1,
    slot_id: [u8; 16],
    sandbox_spec_digest: [u8; 32],
    sandbox_spec_size: u64,
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    semantic_digest: [u8; 32],
    plan_digest: [u8; 32],
    template_digest: [u8; 32],
    lease_digest: [u8; 32],
    lease_generation: u64,
    deadline_boottime_nanoseconds: u64,
    action: DestinationSlotAction,
    ready: Option<ReadyResourceExpectation>,
    template_body: Vec<u8>,
    body: Vec<u8>,
    packet: Vec<u8>,
    digest: [u8; 32],
}

impl Record {
    fn from_attempt(
        live: &LiveDispatch,
        ready: Option<ReadyResourceExpectation>,
        attempt: &BrokerDispatchAttemptV1,
    ) -> Result<Self, DestinationSlotEffectError> {
        let request = decode_request(attempt.body(), attempt.deadline_boottime_nanoseconds())?;
        let plan = live.template.signed_plan().plan();
        let assignment = plan.assignment();
        let mut record = Self {
            request_id: *request.header().request_id(),
            assignment_target: live.target.durable_reference(),
            slot_id: *request.destination_slot_id(),
            sandbox_spec_digest: *request.sandbox_spec().digest().as_bytes(),
            sandbox_spec_size: request.sandbox_spec().encoded_size(),
            assignment_epoch: assignment.epoch().get(),
            desired_generation: assignment.desired_generation().get(),
            assignment_digest: *assignment.digest().as_bytes(),
            semantic_digest: *semantic_identity_digest(live.template.semantics()).as_bytes(),
            plan_digest: *live.template.signed_plan().digest().as_bytes(),
            template_digest: *live.template.digest().as_bytes(),
            lease_digest: *attempt.lease_digest().as_bytes(),
            lease_generation: attempt.lease_generation(),
            deadline_boottime_nanoseconds: attempt.deadline_boottime_nanoseconds(),
            action: request.action(),
            ready,
            template_body: live.template.body_without_deadline().to_vec(),
            body: attempt.body().to_vec(),
            packet: attempt.packet().to_vec(),
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate_contents()?;
        Ok(record)
    }

    pub(super) const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub(super) const fn assignment_target(&self) -> DurableRuntimeAuthorityReferenceV1 {
        self.assignment_target
    }

    pub(super) const fn plan_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.plan_digest)
    }

    pub(super) const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.digest)
    }

    pub(super) const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    pub(super) fn body_without_deadline(&self) -> &[u8] {
        &self.template_body
    }

    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(super) const fn ready_expectation(&self) -> Option<ReadyResourceExpectation> {
        self.ready
    }

    pub(super) fn matches_resume_template(&self, template: &BrokerDispatchTemplateV1) -> bool {
        let assignment = template.signed_plan().plan().assignment();
        self.assignment_epoch == assignment.epoch().get()
            && self.desired_generation == assignment.desired_generation().get()
            && self.assignment_digest == *assignment.digest().as_bytes()
            && self.plan_digest == *template.signed_plan().digest().as_bytes()
            && self.template_digest == *template.digest().as_bytes()
            && self.semantic_digest == *semantic_identity_digest(template.semantics()).as_bytes()
            && self.template_body == template.body_without_deadline()
    }

    fn matches_attempt(
        &self,
        live: &LiveDispatch,
        attempt: &BrokerDispatchAttemptV1,
    ) -> Result<bool, DestinationSlotEffectError> {
        Ok(self == &Self::from_attempt(live, self.ready, attempt)?)
    }

    fn matches_resumed_attempt(
        &self,
        live: &LiveDispatch,
        attempt: &BrokerDispatchAttemptV1,
    ) -> Result<bool, DestinationSlotEffectError> {
        let candidate = Self::from_attempt(live, self.ready, attempt)?;
        Ok(self.matches_resumed_record(&candidate))
    }

    fn matches_resumed_record(&self, candidate: &Self) -> bool {
        self.request_id == candidate.request_id
            && self.assignment_target == candidate.assignment_target
            && self.slot_id == candidate.slot_id
            && self.sandbox_spec_digest == candidate.sandbox_spec_digest
            && self.sandbox_spec_size == candidate.sandbox_spec_size
            && self.assignment_epoch == candidate.assignment_epoch
            && self.desired_generation == candidate.desired_generation
            && self.assignment_digest == candidate.assignment_digest
            && self.semantic_digest == candidate.semantic_digest
            && self.plan_digest == candidate.plan_digest
            && self.template_digest == candidate.template_digest
            && self.deadline_boottime_nanoseconds == candidate.deadline_boottime_nanoseconds
            && self.action == candidate.action
            && self.ready == candidate.ready
            && self.template_body == candidate.template_body
            && self.body == candidate.body
            && (candidate.lease_generation > self.lease_generation
                || (candidate.lease_generation == self.lease_generation
                    && candidate.lease_digest == self.lease_digest))
    }

    fn validate_contents(&self) -> Result<(), DestinationSlotEffectError> {
        if self.request_id == [0; 16]
            || self.assignment_target.sandbox().as_bytes() == &[0; 16]
            || self.assignment_target.revision() == 0
            || self.assignment_target.binding_digest().as_bytes() == &[0; 32]
            || self.slot_id == [0; 16]
            || self.sandbox_spec_digest == [0; 32]
            || self.sandbox_spec_size == 0
            || self.assignment_epoch == 0
            || self.desired_generation == 0
            || self.assignment_digest == [0; 32]
            || self.semantic_digest == [0; 32]
            || self.plan_digest == [0; 32]
            || self.template_digest == [0; 32]
            || self.lease_digest == [0; 32]
            || self.lease_generation == 0
            || self.deadline_boottime_nanoseconds == 0
            || self.template_body.is_empty()
            || self.template_body.len() > MAXIMUM_REQUEST_BYTES
            || self.body.is_empty()
            || self.body.len() > MAXIMUM_REQUEST_BYTES
            || self.packet.is_empty()
            || self.packet.len() > MAXIMUM_REQUEST_BYTES
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || self.compute_digest() != self.digest
            || self.ready.is_some_and(|ready| {
                !ready.is_valid() || ready.materialization_operation_id == self.request_id
            })
            || !validate_durable_deadline_free_body(&self.template_body)
            || !validate_durable_attempt_body(
                &self.template_body,
                self.deadline_boottime_nanoseconds,
                &self.body,
            )
        {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        match self.action {
            DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE if self.ready.is_none() => {}
            DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP if self.ready.is_some() => {}
            _ => return Err(DestinationSlotEffectError::CorruptState),
        }

        let request = decode_request(&self.body, self.deadline_boottime_nanoseconds)
            .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        self.validate_request(&request)?;
        let envelope =
            decode_request_envelope(&self.packet, aos_sandbox_core::ProtocolId::MountBroker, 0)
                .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        if envelope.method() != METHOD
            || !envelope.descriptors().is_empty()
            || envelope.body() != self.body
        {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        let artifacts = envelope
            .authorization()
            .ok_or(DestinationSlotEffectError::CorruptState)?;
        self.validate_artifacts(artifacts, &request)
    }

    fn validate_request(
        &self,
        request: &aos_sandbox_protocol::ValidatedDestinationSlotRequest,
    ) -> Result<(), DestinationSlotEffectError> {
        let fence = request.fence();
        if request.header().request_id() != &self.request_id
            || request.header().protocol_version() != CARRIER_VERSION
            || request.header().audience() != Audience::AUDIENCE_NODE_CONTROLLER
            || request.header().deadline_boottime_nanoseconds()
                != self.deadline_boottime_nanoseconds
            || request.header().maximum_response_bytes() != RESPONSE_BYTES
            || request.action() != self.action
            || request.destination_slot_id() != &self.slot_id
            || request.sandbox_spec().digest().as_bytes() != &self.sandbox_spec_digest
            || request.sandbox_spec().encoded_size() != self.sandbox_spec_size
            || request.binding_fence().sandbox_id() != self.assignment_target.sandbox().as_bytes()
            || fence.assignment_epoch() != self.assignment_epoch
            || fence.desired_generation() != self.desired_generation
            || fence.assignment_digest() != &self.assignment_digest
            || request.expected_resource_digest()
                != self.ready.map(|value| value.ready_resource_digest).as_ref()
        {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        Ok(())
    }

    fn validate_artifacts(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &aos_sandbox_protocol::ValidatedDestinationSlotRequest,
    ) -> Result<(), DestinationSlotEffectError> {
        let plan =
            decode_broker_authorization_plan(artifacts.broker_plan(), DecodeLimits::default())
                .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let lease = decode_ownership_lease(artifacts.ownership_lease(), DecodeLimits::default())
            .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let plan_signature =
            decode_signature(artifacts.broker_plan_signature(), DecodeLimits::default())
                .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let lease_signature = decode_signature(
            artifacts.ownership_lease_signature(),
            DecodeLimits::default(),
        )
        .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let plan_descriptor = artifact_descriptor(
            PortableMediaType::BrokerAuthorizationPlan,
            artifacts.broker_plan(),
        )?;
        let lease_descriptor = artifact_descriptor(
            PortableMediaType::OwnershipLease,
            artifacts.ownership_lease(),
        )?;
        let assignment = plan.assignment();
        let lease_assignment = lease.assignment();

        if plan.audience() != BrokerAudience::Mount
            || plan.protocol() != aos_sandbox_core::ProtocolId::MountBroker
            || plan.protocol_version() != CARRIER_VERSION
            || assignment.sandbox() != self.assignment_target.sandbox()
            || assignment.incarnation().as_bytes() != request.binding_fence().incarnation_id()
            || assignment.epoch().get() != self.assignment_epoch
            || assignment.desired_generation().get() != self.desired_generation
            || assignment.digest().as_bytes() != &self.assignment_digest
            || lease_assignment.sandbox() != assignment.sandbox()
            || lease_assignment.incarnation() != assignment.incarnation()
            || lease_assignment.epoch() != assignment.epoch()
            || lease_assignment.digest() != assignment.digest()
            || lease.node() != plan.node()
            || lease.lease_generation() != self.lease_generation
            || plan_descriptor.digest().as_bytes() != &self.plan_digest
            || lease_descriptor.digest().as_bytes() != &self.lease_digest
            || plan_signature.statement().subject() != &plan_descriptor
            || plan_signature.statement().purpose() != SignaturePurpose::BrokerAuthorization
            || plan_signature.statement().issued_seconds() != plan.issued_seconds()
            || plan_signature.statement().expires_seconds() != Some(plan.expires_seconds())
            || lease_signature.statement().subject() != &lease_descriptor
            || lease_signature.statement().purpose() != SignaturePurpose::OwnershipLease
            || lease_signature.statement().signer() != plan.ownership_authority()
            || lease_signature.statement().issued_seconds() != lease.authority_issued_seconds()
            || lease_signature.statement().expires_seconds()
                != Some(lease.authority_expires_seconds())
        {
            return Err(DestinationSlotEffectError::CorruptState);
        }

        let canonical = canonical_destination_slot_semantics_v1(request)
            .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            canonical.verb(),
            canonical.target(),
            canonical.commitment(),
        );
        let request_bytes =
            u32::try_from(self.body.len()).map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let matching_grant = plan.grants().iter().any(|grant| {
            grant.verb() == semantics.verb()
                && grant.target() == semantics.target()
                && grant.argument_commitment() == semantics.argument_commitment()
                && request_bytes <= grant.maximum_request_bytes()
                && grant.maximum_descriptors() == 0
        });
        if !matching_grant
            || semantic_identity_digest(semantics).as_bytes() != &self.semantic_digest
            || template_digest_from_parts(
                plan_descriptor.digest(),
                artifacts.broker_plan_signature(),
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT,
                &self.template_body,
                &[],
                semantics,
            )
            .as_bytes()
                != &self.template_digest
        {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        Ok(())
    }

    fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(17);
        key.push(b'a');
        key.extend_from_slice(&self.request_id);
        key
    }

    fn encoded_len(&self) -> usize {
        FIXED_RECORD_BYTES
            .saturating_add(self.template_body.len())
            .saturating_add(self.body.len())
            .saturating_add(self.packet.len())
    }

    fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(RECORD_DOMAIN);
        digest.update(self.encode_without_digest());
        digest.finalize().into()
    }

    fn encode_without_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len().saturating_sub(32));
        bytes.extend_from_slice(MAGIC);
        bytes.push(if self.ready.is_some() {
            FLAG_READY_EXPECTATION
        } else {
            0
        });
        bytes.push(self.action as i32 as u8);
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.request_id);
        encode_assignment_target(&mut bytes, self.assignment_target);
        bytes.extend_from_slice(&self.slot_id);
        bytes.extend_from_slice(&self.sandbox_spec_digest);
        bytes.extend_from_slice(&self.sandbox_spec_size.to_be_bytes());
        bytes.extend_from_slice(&self.assignment_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.desired_generation.to_be_bytes());
        bytes.extend_from_slice(&self.assignment_digest);
        bytes.extend_from_slice(&self.semantic_digest);
        bytes.extend_from_slice(&self.plan_digest);
        bytes.extend_from_slice(&self.template_digest);
        bytes.extend_from_slice(&self.lease_digest);
        bytes.extend_from_slice(&self.lease_generation.to_be_bytes());
        bytes.extend_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        encode_ready(&mut bytes, self.ready);
        bytes.extend_from_slice(&(self.template_body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.packet.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.template_body);
        bytes.extend_from_slice(&self.body);
        bytes.extend_from_slice(&self.packet);
        bytes
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.encode_without_digest();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DestinationSlotEffectError> {
        if bytes.len() < FIXED_RECORD_BYTES || bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.array::<8>()? != *MAGIC {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        let flags = decoder.byte()?;
        if flags & !FLAG_READY_EXPECTATION != 0 {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        let action = DestinationSlotAction::from_i32(i32::from(decoder.byte()?))
            .ok_or(DestinationSlotEffectError::CorruptState)?;
        if decoder.array::<2>()? != [0; 2] {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        let request_id = decoder.array()?;
        let assignment_target = decode_assignment_target(&mut decoder)?;
        let slot_id = decoder.array()?;
        let sandbox_spec_digest = decoder.array()?;
        let sandbox_spec_size = decoder.u64()?;
        let assignment_epoch = decoder.u64()?;
        let desired_generation = decoder.u64()?;
        let assignment_digest = decoder.array()?;
        let semantic_digest = decoder.array()?;
        let plan_digest = decoder.array()?;
        let template_digest = decoder.array()?;
        let lease_digest = decoder.array()?;
        let lease_generation = decoder.u64()?;
        let deadline_boottime_nanoseconds = decoder.u64()?;
        let ready = decode_ready(&mut decoder, flags & FLAG_READY_EXPECTATION != 0)?;
        let template_len = decoder.u32_as_usize()?;
        let body_len = decoder.u32_as_usize()?;
        let packet_len = decoder.u32_as_usize()?;
        let template_body = decoder.bytes(template_len)?.to_vec();
        let body = decoder.bytes(body_len)?.to_vec();
        let packet = decoder.bytes(packet_len)?.to_vec();
        let digest = decoder.array()?;
        if !decoder.is_empty() {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        let record = Self {
            request_id,
            assignment_target,
            slot_id,
            sandbox_spec_digest,
            sandbox_spec_size,
            assignment_epoch,
            desired_generation,
            assignment_digest,
            semantic_digest,
            plan_digest,
            template_digest,
            lease_digest,
            lease_generation,
            deadline_boottime_nanoseconds,
            action,
            ready,
            template_body,
            body,
            packet,
            digest,
        };
        record.validate_contents()?;
        Ok(record)
    }

    fn transaction(&self) -> Result<JournalTransaction, DestinationSlotEffectError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }
        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(NAMESPACE, self.key(), self.encode())],
        )?)
    }
}

#[derive(Default)]
pub(super) struct History {
    pub(super) records: BTreeMap<[u8; 16], Record>,
    retained_bytes: usize,
}

impl History {
    pub(super) fn load(journal: &mut Journal) -> Result<Self, DestinationSlotEffectError> {
        journal.ensure_healthy()?;
        let mut history = Self::default();
        let mut decoded = Vec::new();
        for (key, value) in journal.records(NAMESPACE) {
            history.retained_bytes = history
                .retained_bytes
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(DestinationSlotEffectError::Capacity)?;
            if decoded.len() >= MAXIMUM_ATTEMPTS
                || history.retained_bytes > MAXIMUM_NAMESPACE_BYTES
                || value.len() > MAXIMUM_RECORD_BYTES
            {
                return Err(DestinationSlotEffectError::Capacity);
            }
            let record = Record::decode(value)?;
            if key != record.key()
                || journal
                    .get(RecordNamespace::MountAttempt, &record.key())
                    .is_some()
            {
                return Err(DestinationSlotEffectError::CorruptState);
            }
            decoded.push(record);
        }

        if !decoded.is_empty() {
            attachment_slot_state::validate_namespace(journal)?;
            RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?;
        }
        for record in decoded {
            let request = decode_request(&record.body, record.deadline_boottime_nanoseconds)
                .map_err(|_| DestinationSlotEffectError::CorruptState)?;
            let slot = logical_slot_for_request(journal, &request)?;
            let spec = crate::sandbox_spec_state::get_in_validated_namespace(
                journal,
                slot.sandbox_spec(),
            )?
            .ok_or(DestinationSlotEffectError::CorruptState)?;
            if spec.canonical_bytes() != request.sandbox_spec_bytes() {
                return Err(DestinationSlotEffectError::CorruptState);
            }
            let binding = binding_for_durable_reference_in_validated_namespace(
                journal,
                record.assignment_target,
            )?;
            let manifest = binding.manifest().manifest();
            let fence = request.binding_fence();
            if binding.state() != RuntimeAuthorityStateV1::Bound
                || binding.holder().is_none()
                || manifest.incarnation().as_bytes() != fence.incarnation_id()
                || manifest.epoch().get() != fence.assignment_epoch()
                || manifest.desired_generation().get() != fence.desired_generation()
                || binding.assignment_digest().as_bytes() != fence.assignment_digest()
                || manifest.namespace_generation().get() != request.namespace_generation()
                || manifest.sandbox_spec() != request.sandbox_spec()
            {
                return Err(DestinationSlotEffectError::CorruptState);
            }
            if history.records.insert(record.request_id, record).is_some() {
                return Err(DestinationSlotEffectError::CorruptState);
            }
        }

        validate_materialization_links(&history.records)?;
        Ok(history)
    }

    fn ensure_capacity(&self, record: &Record) -> Result<(), DestinationSlotEffectError> {
        let next = self
            .retained_bytes
            .checked_add(record.key().len())
            .and_then(|size| size.checked_add(record.encoded_len()))
            .ok_or(DestinationSlotEffectError::Capacity)?;
        if self.records.len() >= MAXIMUM_ATTEMPTS || next > MAXIMUM_NAMESPACE_BYTES {
            return Err(DestinationSlotEffectError::Capacity);
        }
        Ok(())
    }
}

fn validate_materialization_links(
    records: &BTreeMap<[u8; 16], Record>,
) -> Result<(), DestinationSlotEffectError> {
    for record in records.values() {
        let Some(ready) = record.ready else {
            continue;
        };
        let Some(materialization) = records.get(&ready.materialization_operation_id) else {
            continue;
        };

        let request = decode_request(
            &materialization.body,
            materialization.deadline_boottime_nanoseconds,
        )
        .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let reap_request = decode_request(&record.body, record.deadline_boottime_nanoseconds)
            .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let materialization_digest: [u8; 32] = Sha256::digest(&materialization.body).into();
        if materialization.action != DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE
            || request.fence()
                != reap_request
                    .resource_fence()
                    .ok_or(DestinationSlotEffectError::CorruptState)?
            || materialization_digest != ready.materialization_request_digest
        {
            return Err(DestinationSlotEffectError::CorruptState);
        }
    }
    Ok(())
}

pub(super) fn admit_current<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentDestinationSlotDispatchV1,
    deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<DurableCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    if deadline_boottime_nanoseconds > prepared.operation.valid_until_boottime_nanoseconds {
        return Err(DestinationSlotEffectError::Deadline);
    }
    let history = History::load(journal)?;
    let attempt = prepared.operation.target.prepare_mount_attempt_version(
        journal,
        &prepared.template,
        deadline_boottime_nanoseconds,
        CARRIER_VERSION,
        clock,
    )?;
    crate::mount_preparation::check_mount_deadline(attempt.deadline_boottime_nanoseconds())?;
    let slot = prepared.operation.reconciliation.slot().clone();
    let ready = prepared.operation.ready;
    let live = LiveDispatch {
        slot,
        target: prepared.operation.target,
        template: prepared.template,
    };
    let record = Record::from_attempt(&live, ready, &attempt)?;
    let outcome = match history.records.get(&record.request_id) {
        Some(existing) if existing == &record => DestinationSlotAttemptAdmissionOutcomeV1::Replay,
        Some(_) => return Err(DestinationSlotEffectError::Conflict),
        None => {
            history.ensure_capacity(&record)?;
            if journal
                .get(RecordNamespace::MountAttempt, &record.key())
                .is_some()
            {
                return Err(DestinationSlotEffectError::Conflict);
            }
            journal.commit(&record.transaction()?)?;
            DestinationSlotAttemptAdmissionOutcomeV1::Admitted
        }
    };
    let committed = History::load(journal)?;
    if committed.records.get(&record.request_id) != Some(&record) {
        return Err(DestinationSlotEffectError::CorruptState);
    }
    live.recheck(journal, clock)?;
    Ok(DurableCurrentDestinationSlotAttemptV1 {
        live,
        resume_evidence: None,
        attempt,
        record,
        outcome,
        packet_source: PacketSource::Recorded,
    })
}

pub(super) fn resume_current<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentDestinationSlotResumeDispatchV1,
    clock: &mut T,
) -> Result<DurableCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    let attempt = prepared.operation.target.prepare_mount_attempt_version(
        journal,
        &prepared.template,
        prepared.record.deadline_boottime_nanoseconds,
        CARRIER_VERSION,
        clock,
    )?;
    let slot = prepared.operation.reconciliation.slot().clone();
    let evidence = prepared.operation.reconciliation;
    let live = LiveDispatch {
        slot,
        target: prepared.operation.target,
        template: prepared.template,
    };
    if !prepared.record.matches_resumed_attempt(&live, &attempt)? {
        return Err(DestinationSlotEffectError::Conflict);
    }
    live.recheck(journal, clock)?;
    Ok(DurableCurrentDestinationSlotAttemptV1 {
        live,
        resume_evidence: Some(evidence),
        attempt,
        record: prepared.record,
        outcome: DestinationSlotAttemptAdmissionOutcomeV1::Replay,
        packet_source: PacketSource::Reconstructed,
    })
}

pub(super) fn replay_record(
    journal: &mut Journal,
    request_id: aos_sandbox_core::OperationId,
) -> Result<Record, DestinationSlotEffectError> {
    History::load(journal)?
        .records
        .get(request_id.as_bytes())
        .cloned()
        .ok_or(DestinationSlotEffectError::NotResumable)
}

pub(super) fn recheck_resume_record(
    journal: &mut Journal,
    operation: &PreparedOperation,
    record: &Record,
) -> Result<(), DestinationSlotEffectError> {
    let history = History::load(journal)?;
    if history.records.get(&record.request_id) != Some(record)
        || operation
            .target
            .validate_durable_reference(journal, record.assignment_target)
            .is_err()
        || record.template_body != operation.body_without_deadline
        || record.ready != operation.ready
        || super::completion::contains(journal, record.request_id)?
    {
        return Err(DestinationSlotEffectError::Conflict);
    }
    let resource = super::matching_resource(
        operation.reconciliation.slot(),
        operation.reconciliation.snapshot().inventory(),
    )?
    .ok_or(DestinationSlotEffectError::Conflict)?;
    let expected_materialization = match operation.reconciliation.action() {
        crate::DestinationSlotReconciliationActionV1::ResumeMaterialize { operation_id }
        | crate::DestinationSlotReconciliationActionV1::ResumeMaterializeForReap {
            operation_id,
            ..
        } => operation_id,
        crate::DestinationSlotReconciliationActionV1::ResumeReap { .. } => {
            aos_sandbox_core::OperationId::from_bytes(
                record
                    .ready
                    .ok_or(DestinationSlotEffectError::CorruptState)?
                    .materialization_operation_id,
            )
        }
        _ => return Err(DestinationSlotEffectError::NotResumable),
    };
    if resource.destination_slot_id() != &record.slot_id
        || resource.materialization().operation_id() != expected_materialization.as_bytes()
    {
        return Err(DestinationSlotEffectError::Conflict);
    }
    let request_digest: [u8; 32] = Sha256::digest(&record.body).into();
    match operation.reconciliation.action() {
        crate::DestinationSlotReconciliationActionV1::ResumeMaterialize { .. }
        | crate::DestinationSlotReconciliationActionV1::ResumeMaterializeForReap { .. } => {
            if record.action != DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE
                || resource.lifecycle()
                    != aos_proto::aos::sandbox::local::v1::DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING
                || resource.materialization().request_digest() != &request_digest
            {
                return Err(DestinationSlotEffectError::Conflict);
            }
        }
        crate::DestinationSlotReconciliationActionV1::ResumeReap { operation_id } => {
            let reap = resource.reap().ok_or(DestinationSlotEffectError::Conflict)?;
            let ready = record.ready.ok_or(DestinationSlotEffectError::CorruptState)?;
            if record.action != DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP
                || resource.lifecycle()
                    != aos_proto::aos::sandbox::local::v1::DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING
                || reap.operation().operation_id() != operation_id.as_bytes()
                || reap.operation().request_digest() != &request_digest
                || reap.expected_resource_digest() != &ready.ready_resource_digest
                || !ready.matches_preserved(resource)
            {
                return Err(DestinationSlotEffectError::Conflict);
            }
        }
        _ => return Err(DestinationSlotEffectError::NotResumable),
    }
    Ok(())
}

pub(crate) fn contains_request_id(journal: &Journal, request_id: &[u8; 16]) -> bool {
    let mut key = Vec::with_capacity(17);
    key.push(b'a');
    key.extend_from_slice(request_id);
    journal.get(NAMESPACE, &key).is_some()
}

pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), DestinationSlotEffectError> {
    History::load(journal).map(|_| ())
}

pub(super) fn state_records(
    journal: &mut Journal,
) -> Result<Vec<super::ControllerStateRecord>, DestinationSlotEffectError> {
    Ok(History::load(journal)?
        .records
        .into_iter()
        .map(|(request_id, record)| (request_id, record.digest))
        .collect())
}

fn artifact_descriptor(
    media_type: PortableMediaType,
    bytes: &[u8],
) -> Result<aos_sandbox_core::ObjectDescriptor, DestinationSlotEffectError> {
    let media_type = MediaType::new(media_type.as_str().to_owned())
        .map_err(|_| DestinationSlotEffectError::CorruptState)?;
    Ok(descriptor_for_bytes(media_type, bytes))
}

fn encode_assignment_target(bytes: &mut Vec<u8>, target: DurableRuntimeAuthorityReferenceV1) {
    bytes.extend_from_slice(target.sandbox().as_bytes());
    bytes.extend_from_slice(&target.revision().to_be_bytes());
    bytes.extend_from_slice(target.binding_digest().as_bytes());
}

fn decode_assignment_target(
    decoder: &mut Decoder<'_>,
) -> Result<DurableRuntimeAuthorityReferenceV1, DestinationSlotEffectError> {
    Ok(DurableRuntimeAuthorityReferenceV1::from_parts(
        aos_sandbox_core::SandboxId::from_bytes(decoder.array()?),
        decoder.u64()?,
        ObjectDigest::from_bytes(decoder.array()?),
    ))
}

fn encode_ready(bytes: &mut Vec<u8>, ready: Option<ReadyResourceExpectation>) {
    let ready = ready.unwrap_or(ReadyResourceExpectation {
        materialization_operation_id: [0; 16],
        materialization_request_digest: [0; 32],
        resource_kernel_boot_id: [0; 16],
        slot_device: 0,
        slot_inode: 0,
        anchor_unique_mount_id: 0,
        ready_resource_digest: [0; 32],
    });
    bytes.extend_from_slice(&ready.materialization_operation_id);
    bytes.extend_from_slice(&ready.materialization_request_digest);
    bytes.extend_from_slice(&ready.resource_kernel_boot_id);
    bytes.extend_from_slice(&ready.slot_device.to_be_bytes());
    bytes.extend_from_slice(&ready.slot_inode.to_be_bytes());
    bytes.extend_from_slice(&ready.anchor_unique_mount_id.to_be_bytes());
    bytes.extend_from_slice(&ready.ready_resource_digest);
}

fn decode_ready(
    decoder: &mut Decoder<'_>,
    present: bool,
) -> Result<Option<ReadyResourceExpectation>, DestinationSlotEffectError> {
    let ready = ReadyResourceExpectation {
        materialization_operation_id: decoder.array()?,
        materialization_request_digest: decoder.array()?,
        resource_kernel_boot_id: decoder.array()?,
        slot_device: decoder.u64()?,
        slot_inode: decoder.u64()?,
        anchor_unique_mount_id: decoder.u64()?,
        ready_resource_digest: decoder.array()?,
    };
    let valid = ready.is_valid();
    match (
        present,
        valid,
        ready
            == ReadyResourceExpectation {
                materialization_operation_id: [0; 16],
                materialization_request_digest: [0; 32],
                resource_kernel_boot_id: [0; 16],
                slot_device: 0,
                slot_inode: 0,
                anchor_unique_mount_id: 0,
                ready_resource_digest: [0; 32],
            },
    ) {
        (true, true, false) => Ok(Some(ready)),
        (false, false, true) => Ok(None),
        _ => Err(DestinationSlotEffectError::CorruptState),
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], DestinationSlotEffectError> {
        let value = self
            .bytes
            .get(..length)
            .ok_or(DestinationSlotEffectError::CorruptState)?;
        self.bytes = self
            .bytes
            .get(length..)
            .ok_or(DestinationSlotEffectError::CorruptState)?;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DestinationSlotEffectError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| DestinationSlotEffectError::CorruptState)
    }

    fn byte(&mut self) -> Result<u8, DestinationSlotEffectError> {
        Ok(self.array::<1>()?[0])
    }

    fn u64(&mut self) -> Result<u64, DestinationSlotEffectError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u32_as_usize(&mut self) -> Result<usize, DestinationSlotEffectError> {
        usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| DestinationSlotEffectError::CorruptState)
    }

    const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

//! Concrete authenticated gateways for backend observations and recovery state.
//!
//! The public envelope types are deliberately untrusted. Only
//! [`BackendEvidenceVerifierV1`] verifies their Ed25519 signature against its
//! fixed trust context and exact runtime bindings. The resulting loaders are
//! private-field, one-shot values and are the only implementations of the
//! sealed loader traits.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{ObjectDigest, ObservationSequence, PayloadBootId};

use super::{
    BackendExecutionInspectionInputV1, BackendExecutionInspectionLoaderV1,
    BackendExecutionInspectionRequestV1, BackendExecutionInspectionV1,
    BackendExecutionInventoryInputV1, BackendExecutionInventoryLoaderV1,
    BackendExecutionInventoryV1, BackendExecutionPhaseV1, BackendLifecycleOperationV1,
    BackendLifecycleRecoveryInputV1, BackendLifecycleRecoveryLoaderV1,
    BackendLifecycleRecoveryRecordV1, BackendRuntimeInspectionInputV1,
    BackendRuntimeInspectionLoaderV1, BackendRuntimeInspectionV1, BackendRuntimePhaseV1,
    ExecutionRecoveryError, RuntimeCurrentnessV1, RuntimeHandleCommitmentV1, RuntimeModelError,
    load_backend_execution_inspection_v1, load_backend_execution_inventory_v1,
    load_backend_lifecycle_recovery_v1, load_backend_runtime_inspection_v1,
};

const LIFECYCLE_DOMAIN: &[u8] = b"aos-runtime-lifecycle-recovery-envelope-v1\0";
const RUNTIME_DOMAIN: &[u8] = b"aos-runtime-inspection-envelope-v1\0";
const INVENTORY_DOMAIN: &[u8] = b"aos-runtime-execution-inventory-envelope-v1\0";
const EXECUTION_BINDING_DOMAIN: &[u8] = b"aos-runtime-execution-inspection-binding-v1\0";
const AGENT_OUTCOME_DOMAIN: &[u8] = b"aos-sandbox-agent-outcome-v1\0";
const AGENT_SIGNATURE_DOMAIN: &[u8] = b"aos-sandbox-agent-outcome-signature-v1\0";

/// Holds one fixed evidence-verification trust root and protected channel context.
pub struct BackendEvidenceVerifierV1 {
    public_key: [u8; 32],
    verifying_key: VerifyingKey,
    trust_context: ObjectDigest,
    channel_binding: ObjectDigest,
    authority_binding: ObjectDigest,
}

impl BackendEvidenceVerifierV1 {
    /// Constructs a verifier without minting any authenticated observation.
    ///
    /// Callers must obtain these inputs from protected configuration. Every
    /// verified capability retains their domain separation in its provenance.
    ///
    /// # Errors
    ///
    /// Returns [`BackendEvidenceVerificationError`] for a malformed key or a
    /// zero protected trust/channel commitment.
    pub fn new(
        public_key: [u8; 32],
        trust_context: ObjectDigest,
        channel_binding: ObjectDigest,
    ) -> Result<Self, BackendEvidenceVerificationError> {
        if public_key == [0; 32]
            || trust_context.as_bytes() == &[0; 32]
            || channel_binding.as_bytes() == &[0; 32]
        {
            return Err(BackendEvidenceVerificationError::InvalidTrustContext);
        }
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| BackendEvidenceVerificationError::InvalidTrustContext)?;
        let authority_binding =
            backend_evidence_authority_binding_v1(public_key, trust_context, channel_binding);
        Ok(Self {
            public_key,
            verifying_key,
            trust_context,
            channel_binding,
            authority_binding,
        })
    }

    /// Returns the exact identity that protected admissions must retain.
    #[must_use]
    pub const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }

    /// Returns the canonical message a lifecycle protected store must sign.
    #[must_use]
    pub fn lifecycle_recovery_signing_message(
        &self,
        input: &BackendLifecycleRecoveryInputV1,
    ) -> [u8; 32] {
        lifecycle_message(self, input)
    }

    /// Returns the canonical message a runtime inspector must sign.
    #[must_use]
    pub fn runtime_inspection_signing_message(
        &self,
        input: &BackendRuntimeInspectionInputV1,
    ) -> [u8; 32] {
        runtime_message(self, input)
    }

    /// Returns the canonical message a complete-inventory source must sign.
    #[must_use]
    pub fn execution_inventory_signing_message(
        &self,
        input: &BackendExecutionInventoryInputV1,
    ) -> [u8; 32] {
        inventory_message(self, input)
    }

    /// Verifies and mints one exact lifecycle recovery capability.
    ///
    /// # Errors
    ///
    /// Returns [`BackendEvidenceVerificationError`] for currentness, plan,
    /// signature, canonical-envelope, or model mismatch.
    pub fn verify_lifecycle_recovery(
        &self,
        expected_authority_binding: ObjectDigest,
        expected_currentness: &RuntimeCurrentnessV1,
        expected_plan_commitment: ObjectDigest,
        mut envelope: SignedBackendLifecycleRecoveryV1,
    ) -> Result<BackendLifecycleRecoveryRecordV1, BackendEvidenceVerificationError> {
        if self.authority_binding != expected_authority_binding
            || &envelope.input.currentness != expected_currentness
            || envelope.input.plan_commitment != expected_plan_commitment
        {
            return Err(BackendEvidenceVerificationError::BindingMismatch);
        }
        let message = lifecycle_message(self, &envelope.input);
        self.verify(&message, &envelope.signature)?;
        envelope.input.authority_binding = self.authority_binding;
        let mut gateway = LifecycleGateway {
            input: Some(envelope.input),
        };
        load_backend_lifecycle_recovery_v1(&mut gateway)
    }

    /// Verifies and mints one exact runtime inspection capability.
    ///
    /// # Errors
    ///
    /// Returns [`BackendEvidenceVerificationError`] for runtime, signature,
    /// canonical-envelope, or model mismatch.
    pub fn verify_runtime_inspection(
        &self,
        expected_authority_binding: ObjectDigest,
        expected_operation: super::BackendOperationIdV1,
        expected_operation_sequence: super::BackendOperationSequenceV1,
        expected_lifecycle_operation: super::BackendLifecycleOperationV1,
        expected_request_commitment: ObjectDigest,
        expected: &RuntimeHandleCommitmentV1,
        mut envelope: SignedBackendRuntimeInspectionV1,
    ) -> Result<BackendRuntimeInspectionV1, BackendEvidenceVerificationError> {
        if self.authority_binding != expected_authority_binding
            || envelope.input.operation != expected_operation
            || envelope.input.operation_sequence != expected_operation_sequence
            || envelope.input.lifecycle_operation != expected_lifecycle_operation
            || envelope.input.request_commitment != expected_request_commitment
            || &envelope.input.commitment != expected
        {
            return Err(BackendEvidenceVerificationError::BindingMismatch);
        }
        let message = runtime_message(self, &envelope.input);
        self.verify(&message, &envelope.signature)?;
        envelope.input.authority_binding = self.authority_binding;
        let mut gateway = RuntimeGateway {
            input: Some(envelope.input),
        };
        load_backend_runtime_inspection_v1(&mut gateway)
    }

    /// Verifies and mints one exact agent-backed execution inspection.
    ///
    /// The gateway recomputes both the agent outcome commitment and the
    /// phase-independent core request binding before checking the signature.
    ///
    /// # Errors
    ///
    /// Returns [`BackendEvidenceVerificationError`] for request, outcome,
    /// signature, channel, currentness, or canonical-envelope mismatch.
    pub fn verify_execution_inspection(
        &self,
        expected: &BackendExecutionInspectionRequestV1,
        expected_observation_sequence: ObservationSequence,
        envelope: SignedBackendExecutionInspectionV1,
    ) -> Result<BackendExecutionInspectionV1, BackendEvidenceVerificationError> {
        let input = &envelope.input;
        if self.authority_binding != expected.evidence_authority_binding()
            || input.operation != expected.operation()
            || input.operation_sequence != expected.operation_sequence()
            || input.effect_request_digest != expected.effect_request_digest()
            || input.execution != expected.execution()
            || input.specification_digest != expected.specification_digest()
            || input.admission_commitment != expected.admission_commitment()
            || &input.runtime != expected.runtime()
            || input.payload_boot_id != expected.payload_boot_id()
            || input.sequence != expected_observation_sequence
            || envelope.transport_operation != *expected.operation().as_bytes()
        {
            return Err(BackendEvidenceVerificationError::BindingMismatch);
        }
        if envelope.transport_session.as_bytes() == &[0; 32]
            || envelope.transport_sequence == 0
            || envelope.transport_sequence == u64::MAX
            || envelope.transport_request_commitment.as_bytes() == &[0; 32]
            || envelope.outcome_commitment.as_bytes() == &[0; 32]
            || envelope.result_bytes.is_empty()
            || envelope.result_bytes.len() > 1_048_576
            || agent_result_digest(&envelope.result_bytes) != envelope.result_digest
        {
            return Err(BackendEvidenceVerificationError::EnvelopeMismatch);
        }
        let outcome = backend_agent_outcome_commitment_v1(
            envelope.transport_session,
            envelope.transport_sequence,
            envelope.transport_operation,
            envelope.transport_request_commitment,
            execution_phase_code(input.phase),
            &envelope.result_bytes,
            envelope.result_digest,
        );
        if outcome != envelope.outcome_commitment {
            return Err(BackendEvidenceVerificationError::EnvelopeMismatch);
        }
        let request_binding = backend_execution_inspection_binding_v1(expected);
        let message = backend_agent_outcome_signing_message_v1(
            self.channel_binding,
            request_binding,
            envelope.transport_session,
            envelope.transport_sequence,
            envelope.transport_operation,
            envelope.transport_request_commitment,
            outcome,
        );
        self.verify(&message, &envelope.signature)?;
        let expected_observation = verified_execution_provenance(
            self,
            &message,
            &envelope.signature,
            request_binding,
            input.phase,
            input.sequence,
        );
        let mut input = envelope.input;
        input.authority_binding = self.authority_binding;
        input.observation_commitment = expected_observation;
        let mut gateway = ExecutionGateway { input: Some(input) };
        load_backend_execution_inspection_v1(&mut gateway)
    }

    /// Verifies and mints one complete exact-runtime execution inventory.
    ///
    /// # Errors
    ///
    /// Returns [`BackendEvidenceVerificationError`] for runtime, payload-boot,
    /// signature, completeness-envelope, or inventory invariant mismatch.
    pub fn verify_execution_inventory(
        &self,
        expected_authority_binding: ObjectDigest,
        expected_runtime: &RuntimeHandleCommitmentV1,
        expected_payload_boot_id: PayloadBootId,
        mut envelope: SignedBackendExecutionInventoryV1,
    ) -> Result<BackendExecutionInventoryV1, BackendEvidenceVerificationError> {
        if self.authority_binding != expected_authority_binding
            || &envelope.input.runtime != expected_runtime
            || envelope.input.payload_boot_id != expected_payload_boot_id
            || envelope
                .input
                .entries
                .iter()
                .any(|entry| entry.authority_binding() != self.authority_binding)
        {
            return Err(BackendEvidenceVerificationError::BindingMismatch);
        }
        let message = inventory_message(self, &envelope.input);
        self.verify(&message, &envelope.signature)?;
        envelope.input.authority_binding = self.authority_binding;
        let mut gateway = InventoryGateway {
            input: Some(envelope.input),
        };
        load_backend_execution_inventory_v1(&mut gateway)
    }

    fn verify(
        &self,
        message: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), BackendEvidenceVerificationError> {
        self.verifying_key
            .verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| BackendEvidenceVerificationError::SignatureInvalid)
    }
}

/// Carries an untrusted signed lifecycle-recovery envelope.
pub struct SignedBackendLifecycleRecoveryV1 {
    input: BackendLifecycleRecoveryInputV1,
    signature: [u8; 64],
}

impl SignedBackendLifecycleRecoveryV1 {
    /// Wraps untrusted lifecycle fields and their detached signature.
    #[must_use]
    pub const fn new(input: BackendLifecycleRecoveryInputV1, signature: [u8; 64]) -> Self {
        Self { input, signature }
    }
}

/// Carries an untrusted signed runtime-inspection envelope.
pub struct SignedBackendRuntimeInspectionV1 {
    input: BackendRuntimeInspectionInputV1,
    signature: [u8; 64],
}

impl SignedBackendRuntimeInspectionV1 {
    /// Wraps untrusted runtime fields and their detached signature.
    #[must_use]
    pub const fn new(input: BackendRuntimeInspectionInputV1, signature: [u8; 64]) -> Self {
        Self { input, signature }
    }
}

/// Carries an untrusted signed complete-inventory envelope.
pub struct SignedBackendExecutionInventoryV1 {
    input: BackendExecutionInventoryInputV1,
    signature: [u8; 64],
}

impl SignedBackendExecutionInventoryV1 {
    /// Wraps untrusted complete-inventory fields and their detached signature.
    #[must_use]
    pub const fn new(input: BackendExecutionInventoryInputV1, signature: [u8; 64]) -> Self {
        Self { input, signature }
    }
}

/// Carries one untrusted agent outcome projected to exact core inspection fields.
pub struct SignedBackendExecutionInspectionV1 {
    input: BackendExecutionInspectionInputV1,
    transport_session: ObjectDigest,
    transport_sequence: u64,
    transport_operation: [u8; 16],
    transport_request_commitment: ObjectDigest,
    outcome_commitment: ObjectDigest,
    result_bytes: Vec<u8>,
    result_digest: ObjectDigest,
    signature: [u8; 64],
}

impl SignedBackendExecutionInspectionV1 {
    /// Wraps untrusted core projection and complete agent outcome evidence.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        input: BackendExecutionInspectionInputV1,
        transport_session: ObjectDigest,
        transport_sequence: u64,
        transport_operation: [u8; 16],
        transport_request_commitment: ObjectDigest,
        outcome_commitment: ObjectDigest,
        result_bytes: Vec<u8>,
        result_digest: ObjectDigest,
        signature: [u8; 64],
    ) -> Self {
        Self {
            input,
            transport_session,
            transport_sequence,
            transport_operation,
            transport_request_commitment,
            outcome_commitment,
            result_bytes,
            result_digest,
            signature,
        }
    }
}

/// Derives the exact phase-independent core execution-request binding.
#[must_use]
pub fn backend_execution_inspection_binding_v1(
    request: &BackendExecutionInspectionRequestV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(EXECUTION_BINDING_DOMAIN);
    digest.update(request.evidence_authority_binding().as_bytes());
    digest.update(request.operation().as_bytes());
    digest.update(request.operation_sequence().get().to_be_bytes());
    digest.update(request.effect_request_digest().as_bytes());
    digest.update(request.execution().as_bytes());
    digest.update(request.specification_digest().as_bytes());
    digest.update(request.admission_commitment().as_bytes());
    update_runtime_handle(&mut digest, request.runtime());
    digest.update(request.payload_boot_id().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Derives the verifier identity retained by protected admission authority.
#[must_use]
pub fn backend_evidence_authority_binding_v1(
    public_key: [u8; 32],
    trust_context: ObjectDigest,
    channel_binding: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-runtime-evidence-authority-v1\0");
    digest.update(public_key);
    digest.update(trust_context.as_bytes());
    digest.update(channel_binding.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Derives the canonical outcome commitment shared with the guest agent.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn backend_agent_outcome_commitment_v1(
    session: ObjectDigest,
    sequence: u64,
    operation: [u8; 16],
    request_commitment: ObjectDigest,
    phase_code: u8,
    result_bytes: &[u8],
    result_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(AGENT_OUTCOME_DOMAIN);
    digest.update(session.as_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(operation);
    digest.update(request_commitment.as_bytes());
    digest.update([phase_code]);
    digest.update((result_bytes.len() as u64).to_be_bytes());
    digest.update(result_bytes);
    digest.update(result_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Derives the canonical post-handshake signature message shared with the agent.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn backend_agent_outcome_signing_message_v1(
    channel: ObjectDigest,
    backend_request_binding: ObjectDigest,
    session: ObjectDigest,
    sequence: u64,
    operation: [u8; 16],
    request_commitment: ObjectDigest,
    outcome_commitment: ObjectDigest,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AGENT_SIGNATURE_DOMAIN);
    digest.update(channel.as_bytes());
    digest.update(backend_request_binding.as_bytes());
    digest.update(session.as_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(operation);
    digest.update(request_commitment.as_bytes());
    digest.update(outcome_commitment.as_bytes());
    digest.finalize().into()
}

struct LifecycleGateway {
    input: Option<BackendLifecycleRecoveryInputV1>,
}

impl super::sealed::BackendLifecycleRecoveryLoaderV1 for LifecycleGateway {}

impl BackendLifecycleRecoveryLoaderV1 for LifecycleGateway {
    type Error = BackendEvidenceVerificationError;

    fn load_authenticated_lifecycle_recovery(
        &mut self,
    ) -> Result<BackendLifecycleRecoveryInputV1, Self::Error> {
        self.input
            .take()
            .ok_or(BackendEvidenceVerificationError::Consumed)
    }
}

struct RuntimeGateway {
    input: Option<BackendRuntimeInspectionInputV1>,
}

impl super::sealed::BackendRuntimeInspectionLoaderV1 for RuntimeGateway {}

impl BackendRuntimeInspectionLoaderV1 for RuntimeGateway {
    type Error = BackendEvidenceVerificationError;

    fn load_authenticated_runtime_inspection(
        &mut self,
    ) -> Result<BackendRuntimeInspectionInputV1, Self::Error> {
        self.input
            .take()
            .ok_or(BackendEvidenceVerificationError::Consumed)
    }
}

struct ExecutionGateway {
    input: Option<BackendExecutionInspectionInputV1>,
}

impl super::sealed::BackendExecutionInspectionLoaderV1 for ExecutionGateway {}

impl BackendExecutionInspectionLoaderV1 for ExecutionGateway {
    type Error = BackendEvidenceVerificationError;

    fn load_authenticated_inspection(
        &mut self,
    ) -> Result<BackendExecutionInspectionInputV1, Self::Error> {
        self.input
            .take()
            .ok_or(BackendEvidenceVerificationError::Consumed)
    }
}

struct InventoryGateway {
    input: Option<BackendExecutionInventoryInputV1>,
}

impl super::sealed::BackendExecutionInventoryLoaderV1 for InventoryGateway {}

impl BackendExecutionInventoryLoaderV1 for InventoryGateway {
    type Error = BackendEvidenceVerificationError;

    fn load_authenticated_inventory(
        &mut self,
    ) -> Result<BackendExecutionInventoryInputV1, Self::Error> {
        self.input
            .take()
            .ok_or(BackendEvidenceVerificationError::Consumed)
    }
}

fn lifecycle_message(
    verifier: &BackendEvidenceVerifierV1,
    input: &BackendLifecycleRecoveryInputV1,
) -> [u8; 32] {
    let mut digest = envelope_prefix(verifier, LIFECYCLE_DOMAIN);
    digest.update(input.operation.as_bytes());
    digest.update(input.sequence.get().to_be_bytes());
    digest.update([lifecycle_code(input.lifecycle_operation)]);
    update_currentness(&mut digest, &input.currentness);
    digest.update(input.plan_commitment.as_bytes());
    update_optional_digest(&mut digest, input.runtime_handle);
    digest.update(input.request_commitment.as_bytes());
    digest.update(input.journal_sequence.to_be_bytes());
    digest.update(input.provenance_commitment.as_bytes());
    digest.finalize().into()
}

fn runtime_message(
    verifier: &BackendEvidenceVerifierV1,
    input: &BackendRuntimeInspectionInputV1,
) -> [u8; 32] {
    let mut digest = envelope_prefix(verifier, RUNTIME_DOMAIN);
    digest.update(input.operation.as_bytes());
    digest.update(input.operation_sequence.get().to_be_bytes());
    digest.update([lifecycle_code(input.lifecycle_operation)]);
    digest.update(input.request_commitment.as_bytes());
    update_runtime_handle(&mut digest, &input.commitment);
    digest.update([runtime_phase_code(input.phase)]);
    digest.update(input.sequence.get().to_be_bytes());
    digest.update(input.observation_commitment.as_bytes());
    digest.finalize().into()
}

fn inventory_message(
    verifier: &BackendEvidenceVerifierV1,
    input: &BackendExecutionInventoryInputV1,
) -> [u8; 32] {
    let mut digest = envelope_prefix(verifier, INVENTORY_DOMAIN);
    update_runtime_handle(&mut digest, &input.runtime);
    digest.update(input.payload_boot_id.as_bytes());
    digest.update(input.inventory_generation.to_be_bytes());
    digest.update(input.sequence_floor.get().to_be_bytes());
    digest.update((input.entries.len() as u64).to_be_bytes());
    for entry in &input.entries {
        digest.update(entry.authority_binding().as_bytes());
        digest.update(entry.operation().as_bytes());
        digest.update(entry.operation_sequence().get().to_be_bytes());
        digest.update(entry.effect_request_digest().as_bytes());
        digest.update(entry.execution().as_bytes());
        digest.update(entry.specification_digest().as_bytes());
        digest.update(entry.admission_commitment().as_bytes());
        update_runtime_handle(&mut digest, entry.runtime());
        digest.update(entry.payload_boot_id().as_bytes());
        digest.update([execution_phase_code(entry.phase())]);
        digest.update(entry.sequence().get().to_be_bytes());
        digest.update(entry.observation_commitment().as_bytes());
    }
    digest.update(input.provenance_commitment.as_bytes());
    digest.finalize().into()
}

fn envelope_prefix(verifier: &BackendEvidenceVerifierV1, domain: &[u8]) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(verifier.trust_context.as_bytes());
    digest.update(verifier.channel_binding.as_bytes());
    digest.update(verifier.public_key);
    digest
}

fn verified_execution_provenance(
    verifier: &BackendEvidenceVerifierV1,
    message: &[u8; 32],
    signature: &[u8; 64],
    request_binding: ObjectDigest,
    phase: BackendExecutionPhaseV1,
    sequence: ObservationSequence,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-runtime-verified-evidence-provenance-v1\0");
    digest.update(verifier.trust_context.as_bytes());
    digest.update(verifier.channel_binding.as_bytes());
    digest.update(verifier.public_key);
    digest.update(message);
    digest.update(signature);
    digest.update(request_binding.as_bytes());
    digest.update([execution_phase_code(phase)]);
    digest.update(sequence.get().to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn agent_result_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-result-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn update_currentness(digest: &mut Sha256, currentness: &RuntimeCurrentnessV1) {
    digest.update(currentness.sandbox().as_bytes());
    digest.update(currentness.incarnation().as_bytes());
    digest.update(currentness.node().as_bytes());
    digest.update(currentness.assignment_epoch().get().to_be_bytes());
    digest.update(currentness.assignment_digest().as_bytes());
    digest.update(currentness.desired_generation().get().to_be_bytes());
    digest.update(currentness.namespace_generation().get().to_be_bytes());
}

fn update_runtime_handle(digest: &mut Sha256, runtime: &RuntimeHandleCommitmentV1) {
    update_currentness(digest, runtime.currentness());
    digest.update(runtime.plan_commitment().as_bytes());
    digest.update(runtime.handle().as_bytes());
}

fn update_optional_digest(digest: &mut Sha256, value: Option<ObjectDigest>) {
    match value {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
    }
}

const fn lifecycle_code(operation: BackendLifecycleOperationV1) -> u8 {
    match operation {
        BackendLifecycleOperationV1::Prepare => 1,
        BackendLifecycleOperationV1::Start => 2,
        BackendLifecycleOperationV1::Freeze => 3,
        BackendLifecycleOperationV1::Thaw => 4,
        BackendLifecycleOperationV1::Stop => 5,
        BackendLifecycleOperationV1::Destroy => 6,
        BackendLifecycleOperationV1::Inspect => 7,
        BackendLifecycleOperationV1::Kill => 8,
    }
}

const fn runtime_phase_code(phase: BackendRuntimePhaseV1) -> u8 {
    match phase {
        BackendRuntimePhaseV1::Prepared => 1,
        BackendRuntimePhaseV1::Starting => 2,
        BackendRuntimePhaseV1::Running => 3,
        BackendRuntimePhaseV1::Frozen => 4,
        BackendRuntimePhaseV1::Stopping => 5,
        BackendRuntimePhaseV1::Stopped => 6,
        BackendRuntimePhaseV1::Failed => 7,
        BackendRuntimePhaseV1::Absent => 8,
    }
}

const fn execution_phase_code(phase: BackendExecutionPhaseV1) -> u8 {
    match phase {
        BackendExecutionPhaseV1::Authorized => 1,
        BackendExecutionPhaseV1::Starting => 2,
        BackendExecutionPhaseV1::Running => 3,
        BackendExecutionPhaseV1::Exited => 4,
        BackendExecutionPhaseV1::Canceled => 5,
        BackendExecutionPhaseV1::Failed => 6,
        BackendExecutionPhaseV1::Lost => 7,
    }
}

/// Reports concrete signature, binding, or one-shot gateway rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BackendEvidenceVerificationError {
    /// The configured public key or protected context is invalid.
    #[error("backend evidence trust context is invalid")]
    InvalidTrustContext,
    /// The signed envelope targets different protected currentness.
    #[error("backend evidence binding does not match")]
    BindingMismatch,
    /// The signature does not authenticate the canonical envelope.
    #[error("backend evidence signature is invalid")]
    SignatureInvalid,
    /// Canonical outcome or provenance commitments do not match.
    #[error("backend evidence envelope is inconsistent")]
    EnvelopeMismatch,
    /// A one-shot authenticated loader was consumed more than once.
    #[error("backend evidence gateway was already consumed")]
    Consumed,
    /// Portable runtime model validation failed.
    #[error("backend evidence runtime model failed: {0}")]
    Runtime(#[from] RuntimeModelError),
    /// Portable complete-inventory validation failed.
    #[error("backend evidence inventory failed: {0}")]
    Inventory(#[from] ExecutionRecoveryError),
}

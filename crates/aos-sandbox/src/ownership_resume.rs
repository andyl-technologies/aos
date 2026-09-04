//! Explicit ownership-gate resumption for the unprivileged node controller.
//!
//! Ordinary reconciliation never enters this module and never contacts an
//! ownership authority. An operator-triggered controller call first queries
//! the exact durable transaction, then begins or completes only that immutable
//! claim. Returned carrier fields remain hostile until the negotiated session
//! validates their transcript, method, transaction, and outcome.

use aos_sandbox_core::{OperationId, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_ownership_protocol::protocol::{
    MAXIMUM_OWNERSHIP_REQUEST_BYTES, MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
    MINIMUM_OWNERSHIP_RESPONSE_BYTES, NegotiatedOwnershipSessionV1, OwnershipErrorRecoveryV1,
    OwnershipMethodV1, OwnershipProtocolErrorCodeV1, OwnershipProtocolValidationError,
    OwnershipRequestBodyV1, OwnershipRequestEnvelopeV1, OwnershipResponseOutcomeV1,
    OwnershipTransactionReferenceV1, OwnershipTransactionStatusV1,
};

use crate::{
    AuthorityPublicationError, AuthorityPublicationStore, OwnershipAuthorityVerifier,
    OwnershipGateActivationOutcome, OwnershipGateStatusV1, OwnershipLeaseAcquisitionError,
    Reconciler, ReconcilerError, SingleNodeEffectExecutor,
};

const REQUIRED_METHODS: [OwnershipMethodV1; 3] = [
    OwnershipMethodV1::Begin,
    OwnershipMethodV1::CompleteOrResume,
    OwnershipMethodV1::Query,
];

/// Carries independently decoded, untrusted ownership-response fields.
///
/// A carrier constructs this value without normalizing echoed metadata. The
/// controller submits every field to
/// [`NegotiatedOwnershipSessionV1::validate_response_parts`] before observing
/// the outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedOwnershipResponsePartsV1 {
    binding: [u8; 32],
    method: OwnershipMethodV1,
    transaction: OwnershipTransactionReferenceV1,
    outcome: OwnershipResponseOutcomeV1,
}

impl UntrustedOwnershipResponsePartsV1 {
    /// Retains independently decoded fields for controller-side validation.
    #[must_use]
    pub const fn new(
        binding: [u8; 32],
        method: OwnershipMethodV1,
        transaction: OwnershipTransactionReferenceV1,
        outcome: OwnershipResponseOutcomeV1,
    ) -> Self {
        Self {
            binding,
            method,
            transaction,
            outcome,
        }
    }
}

/// Exchanges ownership messages over one already-authenticated carrier.
///
/// Implementations own transport authentication, byte framing, deadlines, and
/// allocation ceilings. Before allocating or decoding a response, an adapter
/// must reject its carrier frame length above
/// [`NegotiatedOwnershipSessionV1::maximum_response_bytes`]. The negotiated
/// semantic session must describe those exact carrier limits. Response fields
/// are returned without semantic trust; the controller validates them
/// independently. An observed post-allocation wire size is deliberately not a
/// substitute for enforcement at the carrier framing boundary.
pub trait OwnershipAuthoritySessionClient {
    /// Returns the immutable negotiated semantic contract for this connection.
    fn session(&self) -> &NegotiatedOwnershipSessionV1;

    /// Sends one validated request and returns independently decoded fields.
    ///
    /// The implementation must authenticate the peer and enforce the session's
    /// complete response ceiling at its framing layer before allocating the
    /// decoded outcome or any artifact buffers.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipSessionTransportError`] when no authenticated,
    /// bounded response can be delivered.
    fn exchange(
        &mut self,
        request: &OwnershipRequestEnvelopeV1,
    ) -> Result<UntrustedOwnershipResponsePartsV1, OwnershipSessionTransportError>;
}

/// Classifies carrier failure by its safe controller recovery action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipSessionTransportError {
    /// Delivery or response status is indeterminate, so exact query is required.
    #[error("ownership authority transport is unavailable")]
    Unavailable,
    /// Authentication, framing, canonical decoding, or integrity failed.
    #[error("ownership authority transport integrity failed")]
    IntegrityFailure,
}

/// Reports failure to obtain a local paired-clock observation.
///
/// The observation is input to cryptographic liveness checking only. It is not
/// a sealed protected-clock capability and cannot authorize a broker effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("local ownership clock observation is unavailable")]
pub struct OwnershipClockObservationError;

/// Reports the durable result of one explicit ownership resume attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipResumeOutcomeV1 {
    /// Exact authority publication and gate release committed atomically.
    Activated,
    /// The gate was already activated and its durable publication is valid.
    Replay,
    /// The exact authority transaction remains durably pending.
    Pending,
    /// The transaction result is indeterminate; a later call must query first.
    Unavailable,
    /// Authoritative ownership changed and the operation requires fresh planning.
    RefreshAndReplan(OwnershipProtocolErrorCodeV1),
    /// Fixed authority capacity requires an explicit state transition.
    AwaitStateChange(OwnershipProtocolErrorCodeV1),
}

/// Reports a fail-closed explicit ownership-resume failure.
#[derive(Debug, thiserror::Error)]
pub enum OwnershipResumeError {
    /// The operation is absent, ungated, or its durable ledger is corrupt.
    #[error("ownership gate lookup or activation failed: {0}")]
    Reconciler(#[from] ReconcilerError),
    /// The client session differs from the gate's exact protocol contract.
    #[error("ownership authority session does not match the durable gate")]
    SessionContract,
    /// Independently decoded response fields violate the negotiated protocol.
    #[error("ownership authority response failed protocol validation: {0}")]
    Protocol(#[from] OwnershipProtocolValidationError),
    /// The authenticated carrier reported an integrity failure.
    #[error("ownership authority carrier or protected state failed integrity")]
    IntegrityFailure,
    /// The authority rejected an exact operation in a non-retryable way.
    #[error("ownership authority rejected the exact durable transaction")]
    AuthorityRejected(OwnershipProtocolErrorCodeV1),
    /// A local paired-clock observation was unavailable after response receipt.
    #[error("local ownership clock observation is unavailable")]
    ClockObservationUnavailable(#[from] OwnershipClockObservationError),
    /// The returned four-artifact response failed cryptographic or clock checks.
    #[error("ownership authority returned invalid or stale artifacts: {0}")]
    InvalidArtifacts(#[from] OwnershipLeaseAcquisitionError),
    /// Verified artifacts could not bind the exact durable publication draft.
    #[error("ownership authority publication binding failed: {0}")]
    Publication(#[from] AuthorityPublicationError),
}

/// Explicitly resumes one durable ownership gate.
pub(crate) fn resume_ownership<E, A, C>(
    reconciler: &mut Reconciler<E>,
    operation_id: OperationId,
    client: &mut A,
    verifier: &OwnershipAuthorityVerifier,
    observe_clock: &mut C,
) -> Result<OwnershipResumeOutcomeV1, OwnershipResumeError>
where
    E: SingleNodeEffectExecutor,
    A: OwnershipAuthoritySessionClient,
    C: FnMut() -> Result<RawPairedClockSample, OwnershipClockObservationError>,
{
    let gate = reconciler
        .ownership_gate(operation_id)?
        .ok_or(ReconcilerError::OwnershipGateNotFound)?;
    let plan = match gate {
        OwnershipGateStatusV1::Activated { .. } => {
            return Ok(OwnershipResumeOutcomeV1::Replay);
        }
        OwnershipGateStatusV1::Pending(plan) => plan,
    };

    let session = client.session().clone();
    validate_session_contract(&session, plan.expected_authority(), plan.claim())?;
    if verifier.authority() != plan.expected_authority() {
        return Err(OwnershipResumeError::SessionContract);
    }
    let transaction = OwnershipTransactionReferenceV1::from_claim(plan.claim());
    let query = session.request(OwnershipRequestBodyV1::Query(transaction))?;
    let query_status = exchange_status(client, &session, &query)?;
    let completed = match query_status {
        ExchangeStatus::Status(OwnershipTransactionStatusV1::Absent) => {
            let begin = session.request(OwnershipRequestBodyV1::Begin(Box::new(
                plan.claim().clone(),
            )))?;
            match exchange_status(client, &session, &begin)? {
                ExchangeStatus::Status(OwnershipTransactionStatusV1::Completed(response)) => {
                    Some(response)
                }
                ExchangeStatus::Status(OwnershipTransactionStatusV1::Pending) => {
                    match complete_or_resume(client, &session, transaction)? {
                        ExchangeStatus::Status(OwnershipTransactionStatusV1::Completed(
                            response,
                        )) => Some(response),
                        ExchangeStatus::Status(OwnershipTransactionStatusV1::Pending) => None,
                        ExchangeStatus::Unavailable => {
                            return Ok(OwnershipResumeOutcomeV1::Unavailable);
                        }
                        ExchangeStatus::RefreshAndReplan(code) => {
                            return Ok(OwnershipResumeOutcomeV1::RefreshAndReplan(code));
                        }
                        ExchangeStatus::AwaitStateChange(code) => {
                            return Ok(OwnershipResumeOutcomeV1::AwaitStateChange(code));
                        }
                        ExchangeStatus::Status(OwnershipTransactionStatusV1::Absent) => {
                            return Err(OwnershipResumeError::SessionContract);
                        }
                    }
                }
                ExchangeStatus::Unavailable => return Ok(OwnershipResumeOutcomeV1::Unavailable),
                ExchangeStatus::RefreshAndReplan(code) => {
                    return Ok(OwnershipResumeOutcomeV1::RefreshAndReplan(code));
                }
                ExchangeStatus::AwaitStateChange(code) => {
                    return Ok(OwnershipResumeOutcomeV1::AwaitStateChange(code));
                }
                ExchangeStatus::Status(OwnershipTransactionStatusV1::Absent) => {
                    return Err(OwnershipResumeError::SessionContract);
                }
            }
        }
        ExchangeStatus::Status(OwnershipTransactionStatusV1::Pending) => {
            match complete_or_resume(client, &session, transaction)? {
                ExchangeStatus::Status(OwnershipTransactionStatusV1::Completed(response)) => {
                    Some(response)
                }
                ExchangeStatus::Status(OwnershipTransactionStatusV1::Pending) => None,
                ExchangeStatus::Unavailable => {
                    return Ok(OwnershipResumeOutcomeV1::Unavailable);
                }
                ExchangeStatus::RefreshAndReplan(code) => {
                    return Ok(OwnershipResumeOutcomeV1::RefreshAndReplan(code));
                }
                ExchangeStatus::AwaitStateChange(code) => {
                    return Ok(OwnershipResumeOutcomeV1::AwaitStateChange(code));
                }
                ExchangeStatus::Status(OwnershipTransactionStatusV1::Absent) => {
                    return Err(OwnershipResumeError::SessionContract);
                }
            }
        }
        ExchangeStatus::Status(OwnershipTransactionStatusV1::Completed(response)) => Some(response),
        ExchangeStatus::Unavailable => return Ok(OwnershipResumeOutcomeV1::Unavailable),
        ExchangeStatus::RefreshAndReplan(code) => {
            return Ok(OwnershipResumeOutcomeV1::RefreshAndReplan(code));
        }
        ExchangeStatus::AwaitStateChange(code) => {
            return Ok(OwnershipResumeOutcomeV1::AwaitStateChange(code));
        }
    };

    let Some(response) = completed else {
        return Ok(OwnershipResumeOutcomeV1::Pending);
    };
    // This caller-supplied observation rejects expired or not-yet-live
    // artifacts before publication. It is not a protected capability:
    // publication and gate release remain non-authorizing, and each broker
    // independently verifies protected current time and every fence before an
    // effect.
    let clock = observe_clock()?;
    let signed = verifier.verify_response(plan.claim(), response, &clock)?;
    let prepared = plan
        .publication_draft()
        .clone()
        .bind_lease(plan.claim(), signed)?;
    let activation = AuthorityPublicationStore::new(reconciler.journal_mut())
        .prepare_gate_activation(plan.publication_draft(), &prepared)?;
    match reconciler.activate_ownership_gate(operation_id, activation)? {
        OwnershipGateActivationOutcome::Activated => Ok(OwnershipResumeOutcomeV1::Activated),
        OwnershipGateActivationOutcome::Replay => Ok(OwnershipResumeOutcomeV1::Replay),
    }
}

fn validate_session_contract(
    session: &NegotiatedOwnershipSessionV1,
    expected_authority: &aos_sandbox_core::model::KeyReference,
    claim: &aos_sandbox_ownership_protocol::OwnershipClaimV1,
) -> Result<(), OwnershipResumeError> {
    let request_bound = usize::try_from(session.maximum_request_bytes())
        .map_err(|_| OwnershipResumeError::SessionContract)?;
    if session.version() != ProtocolVersion::new(1, 0)
        || session.authority() != expected_authority
        || session.methods() != REQUIRED_METHODS
        || session.maximum_request_bytes() != MAXIMUM_OWNERSHIP_REQUEST_BYTES
        || !(MINIMUM_OWNERSHIP_RESPONSE_BYTES..=MAXIMUM_OWNERSHIP_RESPONSE_BYTES)
            .contains(&session.maximum_response_bytes())
        || session.maximum_requested_lease_seconds()
            != aos_sandbox_ownership_protocol::MAXIMUM_REQUESTED_DURATION_SECONDS
        || claim.canonical_bytes().len() > request_bound
        || claim.requested_maximum_seconds() > session.maximum_requested_lease_seconds()
    {
        return Err(OwnershipResumeError::SessionContract);
    }
    Ok(())
}

fn complete_or_resume<A: OwnershipAuthoritySessionClient>(
    client: &mut A,
    session: &NegotiatedOwnershipSessionV1,
    transaction: OwnershipTransactionReferenceV1,
) -> Result<ExchangeStatus, OwnershipResumeError> {
    let request = session.request(OwnershipRequestBodyV1::CompleteOrResume(transaction))?;
    exchange_status(client, session, &request)
}

enum ExchangeStatus {
    Status(OwnershipTransactionStatusV1),
    Unavailable,
    RefreshAndReplan(OwnershipProtocolErrorCodeV1),
    AwaitStateChange(OwnershipProtocolErrorCodeV1),
}

fn exchange_status<A: OwnershipAuthoritySessionClient>(
    client: &mut A,
    session: &NegotiatedOwnershipSessionV1,
    request: &OwnershipRequestEnvelopeV1,
) -> Result<ExchangeStatus, OwnershipResumeError> {
    let parts = match client.exchange(request) {
        Ok(parts) => parts,
        Err(OwnershipSessionTransportError::Unavailable) => return Ok(ExchangeStatus::Unavailable),
        Err(OwnershipSessionTransportError::IntegrityFailure) => {
            return Err(OwnershipResumeError::IntegrityFailure);
        }
    };
    let response = session.validate_response_parts(
        request,
        parts.binding,
        parts.method,
        parts.transaction,
        parts.outcome,
    )?;
    match response.outcome().clone() {
        OwnershipResponseOutcomeV1::Status(status) => Ok(ExchangeStatus::Status(status)),
        OwnershipResponseOutcomeV1::Error(code) => map_protocol_error(code),
    }
}

fn map_protocol_error(
    code: OwnershipProtocolErrorCodeV1,
) -> Result<ExchangeStatus, OwnershipResumeError> {
    match code.recovery() {
        OwnershipErrorRecoveryV1::QueryThenRetryExact => Ok(ExchangeStatus::Unavailable),
        OwnershipErrorRecoveryV1::RefreshAndReplan => Ok(ExchangeStatus::RefreshAndReplan(code)),
        OwnershipErrorRecoveryV1::AwaitStateChange => Ok(ExchangeStatus::AwaitStateChange(code)),
        OwnershipErrorRecoveryV1::Quarantine => Err(OwnershipResumeError::IntegrityFailure),
        OwnershipErrorRecoveryV1::CorrectRequest => {
            Err(OwnershipResumeError::AuthorityRejected(code))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::PathBuf;

    use aos_sandbox_core::format::{encode_ownership_lease, encode_signature, encode_trust_policy};
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        DecodeLimits, MediaType, ObjectDescriptor, ObjectDigest, OwnershipLease,
        OwnershipLeaseTrustAnchor, PortableMediaType, RawClockProvenance, TrustScopeId,
        descriptor_for_bytes, sign_statement,
    };
    use aos_sandbox_ownership_protocol::protocol::OwnershipClientHelloV1;
    use aos_sandbox_ownership_protocol::{
        OwnershipTransactionReceiptV1, UnverifiedOwnershipLeaseResponse,
    };
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::publication::tests::{activation_claim, activation_fixture};
    use crate::{
        ActivatedOperationCompiler, EffectDomain, EffectFailure, EffectObservation, EffectPlan,
        EffectReceipt, IdempotencyKey, Journal, JournalLimits, NodeController,
        NodeControllerLimits, OperationCompilationError, OperationPlan,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-sandbox-ownership-resume-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("controller.journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct Executor(BTreeMap<(OperationId, u32), EffectReceipt>);

    impl SingleNodeEffectExecutor for Executor {
        fn observe(
            &mut self,
            operation_id: OperationId,
            step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            Ok(self
                .0
                .get(&(operation_id, step))
                .cloned()
                .map_or(EffectObservation::Absent, EffectObservation::Applied))
        }

        fn apply(
            &mut self,
            operation_id: OperationId,
            step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            let receipt = EffectReceipt::new(vec![1]).unwrap();
            self.0.insert((operation_id, step), receipt.clone());
            Ok(receipt)
        }
    }

    struct NoCompiler;

    impl ActivatedOperationCompiler for NoCompiler {
        fn compile(
            &mut self,
            _canonical_request: &[u8],
            _request_digest: [u8; 32],
        ) -> Result<OperationPlan, OperationCompilationError> {
            Err(OperationCompilationError::Rejected)
        }
    }

    struct ScriptedClient {
        session: NegotiatedOwnershipSessionV1,
        responses: VecDeque<Result<OwnershipResponseOutcomeV1, OwnershipSessionTransportError>>,
        methods: Vec<OwnershipMethodV1>,
        session_calls: Cell<usize>,
        substitute_binding: bool,
        substitute_method: bool,
        substitute_transaction: bool,
    }

    impl ScriptedClient {
        fn new(
            authority: KeyReference,
            responses: impl IntoIterator<
                Item = Result<OwnershipResponseOutcomeV1, OwnershipSessionTransportError>,
            >,
        ) -> Self {
            let hello = OwnershipClientHelloV1::new(
                [0x41; 32],
                ProtocolVersion::new(1, 0),
                authority.clone(),
                REQUIRED_METHODS.to_vec(),
                MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
            )
            .unwrap();
            let session = NegotiatedOwnershipSessionV1::negotiate(
                &hello,
                [0x42; 32],
                authority,
                REQUIRED_METHODS.to_vec(),
            )
            .unwrap();
            Self {
                session,
                responses: responses.into_iter().collect(),
                methods: Vec::new(),
                session_calls: Cell::new(0),
                substitute_binding: false,
                substitute_method: false,
                substitute_transaction: false,
            }
        }

        fn response_parts(
            &self,
            request: &OwnershipRequestEnvelopeV1,
            outcome: OwnershipResponseOutcomeV1,
        ) -> UntrustedOwnershipResponsePartsV1 {
            let mut binding = *request.session_binding();
            if self.substitute_binding {
                binding[0] ^= 0xff;
            }
            let method = if self.substitute_method {
                match request.method() {
                    OwnershipMethodV1::Begin => OwnershipMethodV1::Query,
                    OwnershipMethodV1::CompleteOrResume | OwnershipMethodV1::Query => {
                        OwnershipMethodV1::Begin
                    }
                }
            } else {
                request.method()
            };
            let transaction = if self.substitute_transaction {
                OwnershipTransactionReferenceV1::new(
                    [0xee; 16],
                    ObjectDigest::from_bytes([0xef; 32]),
                )
                .unwrap()
            } else {
                request.transaction()
            };
            UntrustedOwnershipResponsePartsV1::new(binding, method, transaction, outcome)
        }
    }

    impl OwnershipAuthoritySessionClient for ScriptedClient {
        fn session(&self) -> &NegotiatedOwnershipSessionV1 {
            self.session_calls.set(self.session_calls.get() + 1);
            &self.session
        }

        fn exchange(
            &mut self,
            request: &OwnershipRequestEnvelopeV1,
        ) -> Result<UntrustedOwnershipResponsePartsV1, OwnershipSessionTransportError> {
            self.methods.push(request.method());
            let outcome = self
                .responses
                .pop_front()
                .unwrap_or_else(|| panic!("missing scripted response"))?;
            Ok(self.response_parts(request, outcome))
        }
    }

    fn gated_controller() -> (
        TestDirectory,
        NodeController<NoCompiler, Executor>,
        OperationPlan,
        crate::AuthorityPublicationDraftV1,
    ) {
        let directory = TestDirectory::new();
        let (draft, _) = activation_fixture(1);
        let claim = activation_claim(&draft, 1);
        let plan = OperationPlan::ownership_gated(
            OperationId::from_bytes([0x71; 16]),
            IdempotencyKey::new(b"ownership-resume".to_vec()).unwrap(),
            [0x72; 32],
            b"sandbox".to_vec(),
            b"ownership-pending".to_vec(),
            vec![EffectPlan::new(EffectDomain::Guardian, b"arm".to_vec()).unwrap()],
            claim,
            draft.clone(),
        )
        .unwrap();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        reconciler.accept(&plan).unwrap();
        let controller = NodeController::new(
            crate::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0x73; 32])).unwrap(),
            NodeControllerLimits::default(),
            NoCompiler,
            reconciler,
        );
        (directory, controller, plan, draft)
    }

    fn open_controller(path: &std::path::Path) -> NodeController<NoCompiler, Executor> {
        let (journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        NodeController::new(
            crate::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0x73; 32])).unwrap(),
            NodeControllerLimits::default(),
            NoCompiler,
            Reconciler::new(journal, Executor::default()),
        )
    }

    fn assert_pending_without_current(
        path: &std::path::Path,
        operation_id: OperationId,
        sandbox: aos_sandbox_core::SandboxId,
    ) {
        let (journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        assert!(matches!(
            reconciler.ownership_gate(operation_id).unwrap(),
            Some(OwnershipGateStatusV1::Pending(_))
        ));
        assert!(
            AuthorityPublicationStore::new(reconciler.journal_mut())
                .current(sandbox)
                .unwrap()
                .is_none()
        );
    }

    fn ownership_signer() -> (SigningKey, KeyReference) {
        let key = SigningKey::from_bytes(&[41; 32]);
        let signer = KeyReference::new(
            StableKeyId::new("lease".to_owned()).unwrap(),
            1,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            KeyUsage::OwnershipLease,
        );
        (key, signer)
    }

    fn trust_material(
        key: &SigningKey,
        signer: &KeyReference,
    ) -> (OwnershipAuthorityVerifier, TrustScopeId, ObjectDescriptor) {
        let scope = TrustScopeId::from_bytes([61; 16]);
        let policy = TrustPolicy::new(
            scope,
            SignaturePurpose::OwnershipLease,
            vec![signer.clone()],
            Vec::new(),
        )
        .unwrap();
        let policy_bytes = encode_trust_policy(&policy);
        let policy_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &policy_bytes,
        );
        let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            policy_bytes,
            policy_descriptor.clone(),
            scope,
            signer.clone(),
            key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap();
        (
            OwnershipAuthorityVerifier::new(anchor, signer.clone()),
            scope,
            policy_descriptor,
        )
    }

    fn completed_response(
        draft: &crate::AuthorityPublicationDraftV1,
    ) -> (OwnershipAuthorityVerifier, UnverifiedOwnershipLeaseResponse) {
        let claim = activation_claim(draft, 1);
        let (key, signer) = ownership_signer();
        let (verifier, scope, policy_descriptor) = trust_material(&key, &signer);
        let lease =
            OwnershipLease::new(claim.assignment(), claim.node(), 1, 110, 190, 5, [1; 16]).unwrap();
        let lease_bytes = encode_ownership_lease(&lease);
        let lease_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned()).unwrap(),
            &lease_bytes,
        );
        let lease_statement = SignatureStatement::new(
            lease_descriptor,
            scope,
            signer.clone(),
            SignaturePurpose::OwnershipLease,
            110,
            Some(190),
            policy_descriptor.clone(),
        )
        .unwrap();
        let lease_signature = sign_statement(lease_statement, &key).unwrap();
        let receipt =
            OwnershipTransactionReceiptV1::new(signer.clone(), &claim, &lease_bytes).unwrap();
        let receipt_descriptor = descriptor_for_bytes(
            MediaType::new(
                PortableMediaType::OwnershipTransactionReceipt
                    .as_str()
                    .to_owned(),
            )
            .unwrap(),
            receipt.canonical_bytes(),
        );
        let receipt_statement = SignatureStatement::new(
            receipt_descriptor,
            scope,
            signer,
            SignaturePurpose::OwnershipLease,
            110,
            Some(190),
            policy_descriptor,
        )
        .unwrap();
        let receipt_signature = sign_statement(receipt_statement, &key).unwrap();
        let response = UnverifiedOwnershipLeaseResponse::from_transport(
            lease_bytes,
            encode_signature(&lease_signature),
            receipt.canonical_bytes().to_vec(),
            encode_signature(&receipt_signature),
        )
        .unwrap();
        (verifier, response)
    }

    fn live_clock() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([0x51; 16]).unwrap(),
            [0x52; 16],
            150,
            1_000,
        )
        .unwrap()
    }

    fn status(
        status: OwnershipTransactionStatusV1,
    ) -> Result<OwnershipResponseOutcomeV1, OwnershipSessionTransportError> {
        Ok(OwnershipResponseOutcomeV1::Status(status))
    }

    #[test]
    fn explicit_resume_queries_begins_completes_and_activates_atomically() {
        let (directory, mut controller, plan, draft) = gated_controller();
        let (verifier, response) = completed_response(&draft);
        let mut client = ScriptedClient::new(
            draft.ownership_authority().clone(),
            [
                status(OwnershipTransactionStatusV1::Absent),
                status(OwnershipTransactionStatusV1::Pending),
                status(OwnershipTransactionStatusV1::Completed(response)),
            ],
        );
        let mut clock_calls = 0;
        let result = controller
            .resume_ownership(plan.operation_id(), &mut client, &verifier, &mut || {
                clock_calls += 1;
                Ok(live_clock())
            })
            .unwrap();

        assert_eq!(result, OwnershipResumeOutcomeV1::Activated);
        assert_eq!(
            client.methods,
            vec![
                OwnershipMethodV1::Query,
                OwnershipMethodV1::Begin,
                OwnershipMethodV1::CompleteOrResume,
            ]
        );
        assert_eq!(clock_calls, 1);

        drop(controller);
        let mut reopened = open_controller(&directory.journal());
        let mut replay_client = ScriptedClient::new(draft.ownership_authority().clone(), []);
        let replay = reopened
            .resume_ownership(
                plan.operation_id(),
                &mut replay_client,
                &verifier,
                &mut || panic!("activated replay sampled the clock"),
            )
            .unwrap();
        assert_eq!(replay, OwnershipResumeOutcomeV1::Replay);
        assert_eq!(replay_client.session_calls.get(), 0);
    }

    #[test]
    fn unavailable_leaves_gate_pending_and_retry_queries_first() {
        let (_directory, mut controller, plan, draft) = gated_controller();
        let (verifier, response) = completed_response(&draft);
        let authority = draft.ownership_authority().clone();
        let mut unavailable = ScriptedClient::new(
            authority.clone(),
            [Err(OwnershipSessionTransportError::Unavailable)],
        );
        assert_eq!(
            controller
                .resume_ownership(
                    plan.operation_id(),
                    &mut unavailable,
                    &verifier,
                    &mut || panic!("unavailable response sampled the clock"),
                )
                .unwrap(),
            OwnershipResumeOutcomeV1::Unavailable
        );

        let mut retry = ScriptedClient::new(
            authority,
            [status(OwnershipTransactionStatusV1::Completed(response))],
        );
        assert_eq!(
            controller
                .resume_ownership(plan.operation_id(), &mut retry, &verifier, &mut || Ok(
                    live_clock()
                ),)
                .unwrap(),
            OwnershipResumeOutcomeV1::Activated
        );
        assert_eq!(retry.methods, vec![OwnershipMethodV1::Query]);

        for responses in [
            vec![
                status(OwnershipTransactionStatusV1::Pending),
                Err(OwnershipSessionTransportError::Unavailable),
            ],
            vec![
                status(OwnershipTransactionStatusV1::Absent),
                Err(OwnershipSessionTransportError::Unavailable),
            ],
        ] {
            let (_directory, mut controller, plan, draft) = gated_controller();
            let (verifier, _) = completed_response(&draft);
            let mut client = ScriptedClient::new(draft.ownership_authority().clone(), responses);
            assert_eq!(
                controller
                    .resume_ownership(plan.operation_id(), &mut client, &verifier, &mut || panic!(
                        "unavailable response sampled the clock"
                    ),)
                    .unwrap(),
                OwnershipResumeOutcomeV1::Unavailable
            );
        }
    }

    #[test]
    fn hostile_response_binding_and_forged_artifacts_fail_closed() {
        let (directory, mut controller, plan, draft) = gated_controller();
        let (verifier, response) = completed_response(&draft);
        let authority = draft.ownership_authority().clone();
        let mut substituted = ScriptedClient::new(
            authority.clone(),
            [status(OwnershipTransactionStatusV1::Pending)],
        );
        substituted.substitute_binding = true;
        assert!(matches!(
            controller.resume_ownership(
                plan.operation_id(),
                &mut substituted,
                &verifier,
                &mut || panic!("substituted response sampled the clock"),
            ),
            Err(OwnershipResumeError::Protocol(
                OwnershipProtocolValidationError::SessionBindingMismatch
            ))
        ));

        for substitute_method in [true, false] {
            let (_directory, mut controller, plan, draft) = gated_controller();
            let (verifier, _) = completed_response(&draft);
            let mut substituted = ScriptedClient::new(
                draft.ownership_authority().clone(),
                [status(OwnershipTransactionStatusV1::Pending)],
            );
            substituted.substitute_method = substitute_method;
            substituted.substitute_transaction = !substitute_method;
            assert!(matches!(
                controller.resume_ownership(
                    plan.operation_id(),
                    &mut substituted,
                    &verifier,
                    &mut || panic!("substituted response sampled the clock"),
                ),
                Err(OwnershipResumeError::Protocol(
                    OwnershipProtocolValidationError::ResponseBindingMismatch
                ))
            ));
        }

        let forged = UnverifiedOwnershipLeaseResponse::from_transport(
            vec![0xff],
            response.signature().to_vec(),
            response.receipt().to_vec(),
            response.receipt_signature().to_vec(),
        )
        .unwrap();
        let mut malicious = ScriptedClient::new(
            authority,
            [status(OwnershipTransactionStatusV1::Completed(forged))],
        );
        assert!(matches!(
            controller.resume_ownership(
                plan.operation_id(),
                &mut malicious,
                &verifier,
                &mut || Ok(live_clock()),
            ),
            Err(OwnershipResumeError::InvalidArtifacts(_))
        ));

        let mut expired = ScriptedClient::new(
            draft.ownership_authority().clone(),
            [status(OwnershipTransactionStatusV1::Completed(response))],
        );
        let expired_clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([0x53; 16]).unwrap(),
            [0x54; 16],
            200,
            2_000,
        )
        .unwrap();
        assert!(matches!(
            controller.resume_ownership(plan.operation_id(), &mut expired, &verifier, &mut || Ok(
                expired_clock
            ),),
            Err(OwnershipResumeError::InvalidArtifacts(_))
        ));
        let sandbox = draft.manifest().manifest().sandbox();
        drop(controller);
        assert_pending_without_current(&directory.journal(), plan.operation_id(), sandbox);
    }

    #[test]
    fn authority_conflicts_require_replanning_without_sampling_clock() {
        for code in [
            OwnershipProtocolErrorCodeV1::AlreadyOwned,
            OwnershipProtocolErrorCodeV1::StaleExpectedPrior,
            OwnershipProtocolErrorCodeV1::WrongAuthorityEpoch,
        ] {
            let (_directory, mut controller, plan, draft) = gated_controller();
            let (verifier, _) = completed_response(&draft);
            let authority = draft.ownership_authority().clone();
            let responses = if code == OwnershipProtocolErrorCodeV1::WrongAuthorityEpoch {
                vec![Ok(OwnershipResponseOutcomeV1::Error(code))]
            } else {
                vec![
                    status(OwnershipTransactionStatusV1::Pending),
                    Ok(OwnershipResponseOutcomeV1::Error(code)),
                ]
            };
            let mut client = ScriptedClient::new(authority, responses);
            assert_eq!(
                controller
                    .resume_ownership(plan.operation_id(), &mut client, &verifier, &mut || panic!(
                        "conflict sampled the clock"
                    ),)
                    .unwrap(),
                OwnershipResumeOutcomeV1::RefreshAndReplan(code)
            );
        }
    }

    #[test]
    fn completion_pending_stays_pending_and_integrity_is_not_retryable() {
        let (_directory, mut controller, plan, draft) = gated_controller();
        let (verifier, _) = completed_response(&draft);
        let authority = draft.ownership_authority().clone();
        let mut pending = ScriptedClient::new(
            authority.clone(),
            [
                status(OwnershipTransactionStatusV1::Pending),
                status(OwnershipTransactionStatusV1::Pending),
            ],
        );
        assert_eq!(
            controller
                .resume_ownership(
                    plan.operation_id(),
                    &mut pending,
                    &verifier,
                    &mut || panic!("pending response sampled the clock"),
                )
                .unwrap(),
            OwnershipResumeOutcomeV1::Pending
        );

        let mut integrity = ScriptedClient::new(
            authority,
            [Err(OwnershipSessionTransportError::IntegrityFailure)],
        );
        assert!(matches!(
            controller.resume_ownership(
                plan.operation_id(),
                &mut integrity,
                &verifier,
                &mut || panic!("integrity failure sampled the clock"),
            ),
            Err(OwnershipResumeError::IntegrityFailure)
        ));
    }

    #[test]
    fn minimum_negotiated_response_bound_is_accepted() {
        let (_directory, mut controller, plan, draft) = gated_controller();
        let (verifier, _) = completed_response(&draft);
        let authority = draft.ownership_authority().clone();
        let hello = OwnershipClientHelloV1::new(
            [0x61; 32],
            ProtocolVersion::new(1, 0),
            authority.clone(),
            REQUIRED_METHODS.to_vec(),
            aos_sandbox_ownership_protocol::protocol::MINIMUM_OWNERSHIP_RESPONSE_BYTES,
        )
        .unwrap();
        let mut client = ScriptedClient::new(
            authority.clone(),
            [
                status(OwnershipTransactionStatusV1::Pending),
                status(OwnershipTransactionStatusV1::Pending),
            ],
        );
        client.session = NegotiatedOwnershipSessionV1::negotiate(
            &hello,
            [0x62; 32],
            authority,
            REQUIRED_METHODS.to_vec(),
        )
        .unwrap();
        assert_eq!(
            controller
                .resume_ownership(plan.operation_id(), &mut client, &verifier, &mut || panic!(
                    "pending response sampled the clock"
                ),)
                .unwrap(),
            OwnershipResumeOutcomeV1::Pending
        );
        assert_eq!(
            client.methods,
            vec![
                OwnershipMethodV1::Query,
                OwnershipMethodV1::CompleteOrResume,
            ]
        );
    }

    #[test]
    fn clock_observation_failure_is_non_authorizing_and_retry_queries_first() {
        let (directory, mut controller, plan, draft) = gated_controller();
        let (verifier, response) = completed_response(&draft);
        let mut first = ScriptedClient::new(
            draft.ownership_authority().clone(),
            [status(OwnershipTransactionStatusV1::Completed(
                response.clone(),
            ))],
        );
        assert!(matches!(
            controller.resume_ownership(plan.operation_id(), &mut first, &verifier, &mut || Err(
                OwnershipClockObservationError
            ),),
            Err(OwnershipResumeError::ClockObservationUnavailable(_))
        ));
        let sandbox = draft.manifest().manifest().sandbox();
        drop(controller);
        assert_pending_without_current(&directory.journal(), plan.operation_id(), sandbox);

        let mut reopened = open_controller(&directory.journal());
        let mut retry = ScriptedClient::new(
            draft.ownership_authority().clone(),
            [status(OwnershipTransactionStatusV1::Completed(response))],
        );
        assert_eq!(
            reopened
                .resume_ownership(plan.operation_id(), &mut retry, &verifier, &mut || Ok(
                    live_clock()
                ),)
                .unwrap(),
            OwnershipResumeOutcomeV1::Activated
        );
        assert_eq!(retry.methods, vec![OwnershipMethodV1::Query]);
    }

    #[test]
    fn wrong_session_or_verifier_fails_before_exchange() {
        let (_directory, mut controller, plan, draft) = gated_controller();
        let (verifier, _) = completed_response(&draft);
        let (wrong_key, wrong_authority) = {
            let key = SigningKey::from_bytes(&[42; 32]);
            let authority = KeyReference::new(
                StableKeyId::new("wrong-lease".to_owned()).unwrap(),
                1,
                ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
                KeyUsage::OwnershipLease,
            );
            (key, authority)
        };
        let mut wrong_session = ScriptedClient::new(wrong_authority.clone(), []);
        assert!(matches!(
            controller.resume_ownership(
                plan.operation_id(),
                &mut wrong_session,
                &verifier,
                &mut || panic!("wrong session sampled the clock"),
            ),
            Err(OwnershipResumeError::SessionContract)
        ));
        assert!(wrong_session.methods.is_empty());

        let (wrong_verifier, _, _) = trust_material(&wrong_key, &wrong_authority);
        let mut valid_session = ScriptedClient::new(draft.ownership_authority().clone(), []);
        assert!(matches!(
            controller.resume_ownership(
                plan.operation_id(),
                &mut valid_session,
                &wrong_verifier,
                &mut || panic!("wrong verifier sampled the clock"),
            ),
            Err(OwnershipResumeError::SessionContract)
        ));
        assert!(valid_session.methods.is_empty());
    }

    #[test]
    fn protocol_recovery_table_is_the_only_controller_mapping() {
        let representatives = [
            (
                OwnershipProtocolErrorCodeV1::InvalidRequest,
                OwnershipErrorRecoveryV1::CorrectRequest,
            ),
            (
                OwnershipProtocolErrorCodeV1::Unavailable,
                OwnershipErrorRecoveryV1::QueryThenRetryExact,
            ),
            (
                OwnershipProtocolErrorCodeV1::ResourceExhausted,
                OwnershipErrorRecoveryV1::AwaitStateChange,
            ),
            (
                OwnershipProtocolErrorCodeV1::WrongAuthorityEpoch,
                OwnershipErrorRecoveryV1::RefreshAndReplan,
            ),
            (
                OwnershipProtocolErrorCodeV1::IntegrityFailure,
                OwnershipErrorRecoveryV1::Quarantine,
            ),
        ];
        for (code, recovery) in representatives {
            assert_eq!(code.recovery(), recovery);
            match recovery {
                OwnershipErrorRecoveryV1::CorrectRequest => assert!(matches!(
                    map_protocol_error(code),
                    Err(OwnershipResumeError::AuthorityRejected(actual)) if actual == code
                )),
                OwnershipErrorRecoveryV1::QueryThenRetryExact => {
                    assert!(matches!(
                        map_protocol_error(code),
                        Ok(ExchangeStatus::Unavailable)
                    ));
                }
                OwnershipErrorRecoveryV1::AwaitStateChange => assert!(matches!(
                    map_protocol_error(code),
                    Ok(ExchangeStatus::AwaitStateChange(actual)) if actual == code
                )),
                OwnershipErrorRecoveryV1::RefreshAndReplan => assert!(matches!(
                    map_protocol_error(code),
                    Ok(ExchangeStatus::RefreshAndReplan(actual)) if actual == code
                )),
                OwnershipErrorRecoveryV1::Quarantine => assert!(matches!(
                    map_protocol_error(code),
                    Err(OwnershipResumeError::IntegrityFailure)
                )),
            }
        }
    }
}

//! Durable generic and authority-bound effect records.
//!
//! V2 records bind every dispatchable effect to one exact closed broker method.
//! Outer V1 records are rejected before semantic recovery or executor I/O.
//! Authority-bound dispatches retain the Host boot identity paired with their
//! BOOTTIME value.
//! V4 is the private, planned-only Controller Observe child; it has no dispatch
//! method and must match the retained AOSCOB01 reservation exactly.
//! V5 retains nonauthorizing project-admission history in the existing Create
//! Effect; V3 without that metadata remains valid but cannot retire Root history.
//! V6 appends an exact Applying-only Q04 policy-admission subgate. Ordinary
//! reconciliation cannot consume it as a completed public Create.

use aos_sandbox_api::aos::sandbox::local::v1::{
    ApplyAtomicStorageSnapshotRequest, ApplyMountRequest, ApplyNetworkRequest, ApplyRuntimeRequest,
    ApplyStorageRequest, Audience, BrokerMethod, BrokerRequestEnvelope, QueryRuntimeEffectRequest,
    QueryRuntimeEffectResponse, RequestHeader, RuntimeEffectStatus,
};
use aos_sandbox_model::{
    BrokerAudience, ObjectDigest, OperationId, PrincipalId, ProjectId, ProtocolVersion,
    RawPairedClockSample,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::public_api::public_mutation_context::{
    InvalidPublicMutationContext, PublicMutationContextV1,
};
use buffa::Message as _;
#[cfg(test)]
use sha2::{Digest as _, Sha256};

use super::ReconcilerError;
use crate::controller_execution_observe_reservation::ControllerExecutionObserveReservationV1;
use crate::BrokerDispatchAttemptV1;

use aos_sandbox_protocol::domain_ledger::effect_history::{
    BrokerDispatchAttemptHistoryV1, EffectDomain, EffectPlan, EffectReceipt,
    PreparedAuthorityEffectHistoryV1, PublicMutationEffectHistoryV1, MAXIMUM_REQUEST_BYTES,
    MAXIMUM_RECEIPT_BYTES, attempt_token_digest, effect_body_digest,
};

/// Carries authenticated admission identity with one exact public mutation.
///
/// The public envelope does not contain the mutually authenticated caller or
/// its project authority. Production lowering therefore persists those facts
/// beside the exact envelope instead of attempting to reconstruct them from a
/// target resource after admission.
/// Protocol owns its plain historical DATA and codec; this native wrapper
/// retains the original FUSE/Nix carrier selection and admission recipes.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicMutationEffectV1 {
    history: PublicMutationEffectHistoryV1,
}

impl std::fmt::Debug for PublicMutationEffectV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.history, formatter)
    }
}

fn invalid_public_mutation_context(error: InvalidPublicMutationContext) -> ReconcilerError {
    // Project before native callers retain or wrap the original Reconciler cause.
    ReconcilerError::InvalidPlan(error.reason())
}

impl PublicMutationEffectV1 {
    /// Binds authenticated request identity to exact canonical request bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for sentinel identities,
    /// nonpositive admission time, or an empty or oversized request.
    pub fn new(
        caller: PrincipalId,
        project: ProjectId,
        accepted_wall_seconds: i64,
        canonical_request: Vec<u8>,
    ) -> Result<Self, ReconcilerError> {
        let plain =
            PublicMutationContextV1::new(caller, project, accepted_wall_seconds, canonical_request)
                .map_err(invalid_public_mutation_context)?;
        Ok(Self {
            history: PublicMutationEffectHistoryV1::from_plain(plain),
        })
    }

    /// Returns the authenticated caller fixed at admission.
    #[must_use]
    pub const fn caller(&self) -> PrincipalId {
        self.history.plain().caller()
    }

    /// Returns the authenticated project fixed at admission.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.history.plain().project()
    }

    /// Returns the protected admission clock in Unix seconds.
    #[must_use]
    pub const fn accepted_wall_seconds(&self) -> i64 {
        self.history.plain().accepted_wall_seconds()
    }

    /// Returns the exact canonical public mutation envelope.
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        self.history.plain().canonical_request()
    }

    /// Decodes the exact public request through the established mutation validator.
    ///
    /// This preserves the authenticated caller and project carried by this
    /// effect while reusing the same canonical protobuf and field validation as
    /// initial public admission. Lowering code must not decode the retained body
    /// through a second, weaker request path.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when the retained envelope or
    /// method-selected protobuf is malformed, noncanonical, or semantically
    /// invalid.
    pub fn validated_request(
        &self,
    ) -> Result<
        aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
        ReconcilerError,
    > {
        self.history
            .plain()
            .validated_request()
            .map_err(invalid_public_mutation_context)
    }

    #[cfg(test)]
    fn encode(&self) -> Result<Vec<u8>, ReconcilerError> {
        self.history.encode().map_err(ReconcilerError::from)
    }

    pub(crate) fn encode_plain(&self) -> Result<Vec<u8>, ReconcilerError> {
        self.history.encode_plain().map_err(ReconcilerError::from)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_fuse_admission(
        mut self,
        carrier: crate::controller_fuse_admission::ControllerFuseAdmissionCarrierV1,
    ) -> Result<Self, ReconcilerError> {
        aos_sandbox_protocol::public_api::mutation_history::require_fuse_context(
            self.history.plain(),
            self.history.nix_start(),
            carrier.history(),
        )
        .map_err(|error| ReconcilerError::InvalidPlan(error.reason()))?;
        self.history.set_fuse_admission(carrier.into_history());
        Ok(self)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn fuse_admission(
        &self,
    ) -> Option<&aos_sandbox_protocol::public_api::mutation_history::ControllerFuseAdmissionCarrierV1>
    {
        self.history.fuse_admission()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_nix_start(
        mut self,
        carrier: crate::production_operation_compiler::NixStartAdmissionCarrierV2,
    ) -> Result<Self, ReconcilerError> {
        aos_sandbox_protocol::public_api::mutation_history::require_nix_context(
            self.history.plain(),
            self.history.fuse_admission(),
            &carrier,
        )
        .map_err(|error| ReconcilerError::InvalidPlan(error.reason()))?;
        self.history.set_nix_start(carrier);
        Ok(self)
    }

    /// Reports retained Nix continuation DATA, never build or floor readiness.
    #[cfg(target_os = "linux")]
    pub fn has_retained_nix_start(&self) -> bool {
        self.history.has_retained_nix_start()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn nix_start(
        &self,
    ) -> Option<&crate::production_operation_compiler::NixStartAdmissionCarrierV2> {
        self.history.nix_start()
    }
}

impl PublicMutationEffectV1 {
    /// Transfers checked fresh context into its sole historical DATA storage.
    pub(crate) fn into_history(self) -> PublicMutationEffectHistoryV1 {
        self.history
    }

    /// Consumes fresh Native context through the complete canonical plan validator.
    ///
    /// # Errors
    /// Returns the original Native encoding or method/request validation refusal.
    pub fn into_plan(
        self,
        method: aos_sandbox_protocol::public_api::PublicOperationMethodV1,
    ) -> Result<EffectPlan, ReconcilerError> {
        EffectPlan::from_public_mutation_context(method, self.history)
            .map_err(ReconcilerError::from)
    }
}

/// Supplies advisory clock facts used to attenuate one durable broker attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityEffectAttemptTimingV1 {
    clock: RawPairedClockSample,
    deadline_boottime_nanoseconds: u64,
}

impl AuthorityEffectAttemptTimingV1 {
    /// Constructs timing input checked against the selected signed authority.
    #[must_use]
    pub const fn new(clock: RawPairedClockSample, deadline_boottime_nanoseconds: u64) -> Self {
        Self {
            clock,
            deadline_boottime_nanoseconds,
        }
    }

    pub(crate) const fn clock(self) -> RawPairedClockSample {
        self.clock
    }

    pub(crate) const fn deadline(self) -> u64 {
        self.deadline_boottime_nanoseconds
    }
}

/// Retains the exact prepared history at the Native executor/session boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedAuthorityEffectV1 {
    history: PreparedAuthorityEffectHistoryV1,
}

impl std::fmt::Debug for PreparedAuthorityEffectV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.history, formatter)
    }
}

/// Carries one exact durable authority request into authenticated session custody.
///
/// This value can only be recovered from a reconciler-prepared effect. Its
/// request identity is therefore the identity made durable before transport,
/// rather than a caller-selected replacement generated at send time.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedAuthorityBrokerRequestV1 {
    envelope: BrokerRequestEnvelope,
    method: BrokerMethod,
    request_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    maximum_response_bytes: u32,
    protocol_version: ProtocolVersion,
    audience: Audience,
}

impl PreparedAuthorityBrokerRequestV1 {
    /// Returns the exact closed broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the exact durable request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the absolute durable attempt deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the request-specific response ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the exact protocol version carried by the method body.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the exact session audience carried by the method body.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }

    /// Consumes the binding and returns its canonical unsigned envelope.
    #[must_use]
    pub fn into_envelope(self) -> BrokerRequestEnvelope {
        self.envelope
    }
}

impl PreparedAuthorityEffectV1 {
    pub(crate) fn new(
        binding_digest: ObjectDigest,
        publication_digest: ObjectDigest,
        preparation_clock: RawPairedClockSample,
        attempt: BrokerDispatchAttemptV1,
    ) -> Self {
        Self {
            history: PreparedAuthorityEffectHistoryV1::from_durable_parts(
                binding_digest,
                publication_digest,
                preparation_clock.wall_seconds(),
                preparation_clock.boottime_nanoseconds(),
                preparation_clock.host_boot_id(),
                attempt.into_history(),
            ),
        }
    }

    /// Validates a Host completion body against this exact persisted Apply.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] when the receipt is
    /// malformed or does not name the Apply request's exact fence and handle.
    pub fn validate_host_receipt(
        &self,
        bytes: Vec<u8>,
    ) -> Result<ValidatedHostEffectReceiptV1, ReconcilerError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid Host effect receipt length",
            ));
        }
        aos_sandbox_protocol::validate_runtime_effect_receipt_for_apply(
            &bytes,
            self.history.attempt().body(),
        )
        .map_err(|_| ReconcilerError::InvalidExecutorOutput("invalid Host effect receipt"))?;
        Ok(ValidatedAuthorityEffectReceiptV1 {
            bytes,
            binding_digest: self.history.binding_digest(),
            attempt_digest: attempt_token_digest(self.history.attempt()),
        })
    }

    /// Extracts one method-specific success body from an authenticated outcome.
    ///
    /// The authenticated protocol layer has already decoded and correlated the
    /// method-specific result. This final bridge additionally binds it to this
    /// reconciler's exact durable method and request body before the receipt can
    /// be committed.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] for a different
    /// method or request, a signed broker error, or an oversized success body.
    pub fn validate_authenticated_outcome(
        &self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, ReconcilerError> {
        let method = authority_attempt_method(self.history.attempt())?;
        if outcome.method() != method
            || outcome.request().exact_body() != self.history.attempt().body()
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect outcome belongs to another durable attempt",
            ));
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect returned a terminal broker error",
            ));
        };
        if exact_body.is_empty() || exact_body.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid authority effect receipt length",
            ));
        }

        Ok(ValidatedAuthorityEffectReceiptV1 {
            bytes: exact_body.clone(),
            binding_digest: self.history.binding_digest(),
            attempt_digest: attempt_token_digest(self.history.attempt()),
        })
    }

    /// Validates a protected terminal exchange recovered from session history.
    ///
    /// The broker-session owner has already authenticated and cross-linked the
    /// retained request and outcome packets. This final bridge prevents a
    /// terminal result for another Apply from satisfying this reconciler
    /// attempt and re-applies the Host receipt's method-specific validation.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] when the recovered
    /// method, request identifier, request body, or receipt does not belong to
    /// this exact durable attempt.
    pub fn validate_protected_terminal_receipt(
        &self,
        method: BrokerMethod,
        request_id: [u8; 16],
        request_body: &[u8],
        receipt: Vec<u8>,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, ReconcilerError> {
        let request = self.broker_request()?;
        if method != request.method()
            || request_id != request.request_id()
            || request_body != self.history.attempt().body()
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "protected terminal exchange belongs to another durable attempt",
            ));
        }
        if receipt.is_empty() || receipt.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid protected terminal receipt length",
            ));
        }
        if method == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            return self.validate_host_receipt(receipt);
        }

        Ok(ValidatedAuthorityEffectReceiptV1 {
            bytes: receipt,
            binding_digest: self.history.binding_digest(),
            attempt_digest: attempt_token_digest(self.history.attempt()),
        })
    }

    /// Validates one authenticated Host query for this exact durable Apply.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] when the query does
    /// not embed this exact Apply, when the broker reports an invalid terminal
    /// body, or when a completed receipt does not match the original request.
    pub fn validate_authenticated_host_observation(
        &self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<AuthorityEffectObservationV1, ReconcilerError> {
        let original = self.broker_request()?;
        if original.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query selected the wrong method",
            ));
        }
        let query = QueryRuntimeEffectRequest::decode_from_slice(outcome.request().exact_body())
            .map_err(|_| {
                ReconcilerError::InvalidExecutorOutput("authority effect query is malformed")
            })?;
        let header = query
            .header
            .as_option()
            .ok_or(ReconcilerError::InvalidExecutorOutput(
                "authority effect query header is missing",
            ))?;
        if !query.__buffa_unknown_fields.is_empty()
            || query.encode_to_vec() != outcome.request().exact_body()
            || header.request_id.as_slice() != original.request_id()
            || query.original_apply_request.as_slice() != self.history.attempt().body()
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query does not name the durable Apply",
            ));
        }

        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query returned a terminal broker error",
            ));
        };
        let response = QueryRuntimeEffectResponse::decode_from_slice(exact_body).map_err(|_| {
            ReconcilerError::InvalidExecutorOutput("authority effect query response is malformed")
        })?;
        if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != *exact_body {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query response is not canonical",
            ));
        }

        match response.status.as_known() {
            Some(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_ABSENT)
                if response.receipt.is_empty() =>
            {
                Ok(AuthorityEffectObservationV1::Absent)
            }
            Some(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_PENDING)
                if response.receipt.is_empty() =>
            {
                Ok(AuthorityEffectObservationV1::Pending)
            }
            Some(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE) => self
                .validate_host_receipt(response.receipt)
                .map(AuthorityEffectObservationV1::Applied),
            _ => Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query response has an invalid status",
            )),
        }
    }

    /// Recovers the exact durable request for authenticated session admission.
    ///
    /// The returned envelope still lacks its session authentication carrier.
    /// Session custody may add that carrier, but it must preserve the exact
    /// method body and all request coordinates exposed by the returned value.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] when the durable
    /// envelope or method body is noncanonical, incomplete, or inconsistent
    /// with the attempt deadline.
    pub fn broker_request(&self) -> Result<PreparedAuthorityBrokerRequestV1, ReconcilerError> {
        let envelope = decode_authority_attempt_envelope(self.history.attempt())?;
        let method = envelope
            .method
            .as_known()
            .ok_or(ReconcilerError::InvalidExecutorOutput(
                "authority effect method is unknown",
            ))?;
        let header = decode_authority_apply_header(method, self.history.attempt().body())?;
        let request_id: [u8; 16] = header.request_id.as_slice().try_into().map_err(|_| {
            ReconcilerError::InvalidExecutorOutput("authority effect request ID is invalid")
        })?;
        let protocol_major = u16::try_from(header.protocol_major).map_err(|_| {
            ReconcilerError::InvalidExecutorOutput("authority effect protocol version is invalid")
        })?;
        let protocol_minor = u16::try_from(header.protocol_minor).map_err(|_| {
            ReconcilerError::InvalidExecutorOutput("authority effect protocol version is invalid")
        })?;
        let audience = header
            .audience
            .as_known()
            .ok_or(ReconcilerError::InvalidExecutorOutput(
                "authority effect audience is unknown",
            ))?;
        if request_id == [0; 16]
            || header.deadline_boottime_nanoseconds
                != self.history.attempt().deadline_boottime_nanoseconds()
            || !(aos_sandbox_protocol::MINIMUM_RESPONSE_BYTES
                ..=aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES)
                .contains(&header.maximum_response_bytes)
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect request coordinates are invalid",
            ));
        }

        Ok(PreparedAuthorityBrokerRequestV1 {
            envelope,
            method,
            request_id,
            deadline_boottime_nanoseconds: header.deadline_boottime_nanoseconds,
            maximum_response_bytes: header.maximum_response_bytes,
            protocol_version: ProtocolVersion::new(protocol_major, protocol_minor),
            audience,
        })
    }

    pub(crate) const fn binding_digest(&self) -> ObjectDigest {
        self.history.binding_digest()
    }

    /// Returns the exact current publication selected for this attempt.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.history.publication_digest()
    }

    /// Returns the byte-exact deadline-bearing broker attempt.
    ///
    /// Its packet is the original Apply carrier retained for either direct
    /// transmission or construction of an authenticated effect query after a
    /// crash or ambiguous response.
    #[must_use]
    pub const fn attempt(&self) -> &BrokerDispatchAttemptHistoryV1 {
        self.history.attempt()
    }

    pub(crate) const fn preparation_wall_seconds(&self) -> i64 {
        self.history.preparation_wall_seconds()
    }

    /// Returns the monotonic clock value at which this attempt became durable.
    #[must_use]
    pub const fn preparation_boottime_nanoseconds(&self) -> u64 {
        self.history.preparation_boottime_nanoseconds()
    }

    /// Returns the host boot in which this attempt became durable.
    #[must_use]
    pub const fn preparation_host_boot_id(&self) -> [u8; 16] {
        self.history.preparation_host_boot_id()
    }
}

impl PreparedAuthorityEffectV1 {
    pub(super) const fn from_history(history: PreparedAuthorityEffectHistoryV1) -> Self {
        Self { history }
    }

    pub(super) const fn history(&self) -> &PreparedAuthorityEffectHistoryV1 {
        &self.history
    }

    pub(super) fn into_history(self) -> PreparedAuthorityEffectHistoryV1 {
        self.history
    }
}

pub(super) fn decode_authority_attempt_envelope(
    attempt: &BrokerDispatchAttemptHistoryV1,
) -> Result<BrokerRequestEnvelope, ReconcilerError> {
    let packet = BrokerRequestEnvelope::decode_from_slice(attempt.packet()).map_err(|_| {
        ReconcilerError::InvalidExecutorOutput("authority effect request is malformed")
    })?;
    if !packet.__buffa_unknown_fields.is_empty()
        || packet.encode_to_vec() != attempt.packet()
        || packet.body.as_slice() != attempt.body()
    {
        return Err(ReconcilerError::InvalidExecutorOutput(
            "authority effect request is not canonical",
        ));
    }

    Ok(packet)
}

fn authority_attempt_method(
    attempt: &BrokerDispatchAttemptHistoryV1,
) -> Result<BrokerMethod, ReconcilerError> {
    decode_authority_attempt_envelope(attempt)?
        .method
        .as_known()
        .ok_or(ReconcilerError::InvalidExecutorOutput(
            "authority effect method is unknown",
        ))
}

pub(super) fn validate_durable_receipt_history(
    prepared: &PreparedAuthorityEffectHistoryV1,
    bytes: &[u8],
) -> Result<(), ReconcilerError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_RECEIPT_BYTES {
        return Err(ReconcilerError::InvalidExecutorOutput(
            "invalid authority effect receipt length",
        ));
    }
    if authority_attempt_method(prepared.attempt())?
        == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
    {
        aos_sandbox_protocol::validate_runtime_effect_receipt_for_apply(
            bytes,
            prepared.attempt().body(),
        )
        .map_err(|_| ReconcilerError::InvalidExecutorOutput("invalid Host effect receipt"))?;
    }

    Ok(())
}

fn decode_authority_apply_header(
    method: BrokerMethod,
    body: &[u8],
) -> Result<RequestHeader, ReconcilerError> {
    macro_rules! decode_header {
        ($message:ty) => {{
            let request = <$message>::decode_from_slice(body).map_err(|_| {
                ReconcilerError::InvalidExecutorOutput("authority effect body is malformed")
            })?;
            if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
                return Err(ReconcilerError::InvalidExecutorOutput(
                    "authority effect body is not canonical",
                ));
            }
            request
                .header
                .as_option()
                .cloned()
                .ok_or(ReconcilerError::InvalidExecutorOutput(
                    "authority effect header is missing",
                ))
        }};
    }

    let header = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => decode_header!(ApplyRuntimeRequest),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => decode_header!(ApplyStorageRequest),
        BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
            decode_header!(ApplyAtomicStorageSnapshotRequest)
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => decode_header!(ApplyMountRequest),
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => decode_header!(ApplyNetworkRequest),
        _ => Err(ReconcilerError::InvalidExecutorOutput(
            "authority effect method is not an Apply method",
        )),
    }?;
    if !header.__buffa_unknown_fields.is_empty() {
        return Err(ReconcilerError::InvalidExecutorOutput(
            "authority effect header is not canonical",
        ));
    }

    Ok(header)
}

/// Carries a broker completion receipt validated against one exact persisted Apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAuthorityEffectReceiptV1 {
    bytes: Vec<u8>,
    binding_digest: ObjectDigest,
    attempt_digest: ObjectDigest,
}

impl ValidatedAuthorityEffectReceiptV1 {
    pub(super) fn into_effect_receipt_for(
        self,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<EffectReceipt, ReconcilerError> {
        if self.binding_digest != prepared.history.binding_digest()
            || self.attempt_digest != attempt_token_digest(prepared.attempt())
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect receipt belongs to another durable attempt",
            ));
        }
        Ok(EffectReceipt::from_bytes_unchecked(self.bytes))
    }
}

/// Preserves the original Host-specific receipt name for compatible callers.
pub type ValidatedHostEffectReceiptV1 = ValidatedAuthorityEffectReceiptV1;

/// Reports authenticated broker observation for one exact persisted Apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityEffectObservationV1 {
    /// The broker durably proves the exact request is absent.
    Absent,
    /// The broker has admitted the exact request but has not completed it.
    Pending,
    /// The broker completed the exact request with validated receipt bytes.
    Applied(ValidatedAuthorityEffectReceiptV1),
}

#[cfg(test)]
const PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.public-mutation-effect.v1\0";

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use aos_sandbox_api::aos::sandbox::v1::AttenuateCapabilityRequest;
    use aos_sandbox_model::{BrokerArgumentCommitment, BrokerGrantTarget, BrokerVerb};
    use aos_sandbox_protocol::domain_ledger::effect_history::{
        EffectLedgerRecord, EffectState, decode_effect, encode_effect,
    };
    use buffa::Message as _;

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_public_effect_retains_exact_original_time_without_nix_data() {
        let context = PublicMutationEffectV1::new(
            PrincipalId::from_bytes([1; 16]),
            ProjectId::from_bytes([2; 16]),
            123,
            b"historical-request-data".to_vec(),
        )
        .unwrap();
        let mut expected = b"AOSPME01".to_vec();
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&[0; 6]);
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&123_i64.to_be_bytes());
        expected.extend_from_slice(&23_u32.to_be_bytes());
        expected.extend_from_slice(b"historical-request-data");
        let digest = Sha256::new()
            .chain_update(PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN)
            .chain_update(&expected)
            .finalize();
        expected.extend_from_slice(&digest);

        let retained = PublicMutationEffectHistoryV1::decode(&context.encode().unwrap())
            .map_err(ReconcilerError::from)
            .unwrap()
            .unwrap();
        assert_eq!(context.encode().unwrap(), expected);
        assert_eq!(retained, context.history);
        assert_eq!(retained.accepted_wall_seconds(), 123);
        assert!(!retained.has_retained_nix_start());
        assert!(retained.fuse_admission().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_recognized_nix_carrier_never_falls_back_to_ordinary_effect() {
        assert!(
            PublicMutationEffectHistoryV1::decode(b"AOSNCA02")
                .map_err(ReconcilerError::from)
                .is_err()
        );
        assert_eq!(
            PublicMutationEffectHistoryV1::decode(b"unrelated-format")
                .map_err(ReconcilerError::from)
                .unwrap(),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_effect_debug_keeps_original_flat_fields() {
        let context = PublicMutationEffectV1::new(
            PrincipalId::from_bytes([1; 16]),
            ProjectId::from_bytes([2; 16]),
            123,
            vec![7, 8],
        )
        .unwrap();
        let expected = format!(
            "PublicMutationEffectV1 {{ caller: {:?}, project: {:?}, accepted_wall_seconds: 123, canonical_request: [7, 8], fuse_admission: None, nix_start: None }}",
            context.caller(),
            context.project(),
        );

        assert_eq!(format!("{context:?}"), expected);
        assert!(!format!("{context:#?}").contains("plain:"));
    }

    #[test]
    fn retained_capability_effect_requires_context_and_checks_method_without_resource_uid() {
        let body = AttenuateCapabilityRequest {
            parent_capability_handle: vec![7; 32],
            attenuation: b"{}".to_vec(),
            holder_channel_binding: vec![8; 32],
            idempotency_key: vec![9],
            expected_parent_resource_version: vec![10],
            ..Default::default()
        }
        .encode_to_vec();
        let request = crate::cli_model::PublicMutationRequestV1::new(
            crate::cli_model::PublicApiAuditMethodV1::AttenuateCapability,
            &body,
        )
        .unwrap();

        let method = aos_sandbox_protocol::public_api::PublicOperationMethodV1::AttenuateCapability;
        let context = PublicMutationEffectV1::new(
            PrincipalId::from_bytes([1; 16]),
            ProjectId::from_bytes([2; 16]),
            123,
            request.encode(),
        )
        .unwrap();
        let plan = {
            let selected_method = method;
            (context.clone()).into_plan(selected_method)
        }
        .unwrap();
        assert_eq!(
            plan.public_mutation_context()
                .map_err(ReconcilerError::from)
                .unwrap(),
            Some(context.into_history())
        );
        let record = EffectLedgerRecord::from_parts((plan, EffectState::Planned, None, None));
        assert_eq!(
            decode_effect(&encode_effect(&record).unwrap()).unwrap(),
            record
        );

        assert!(matches!(
            EffectPlan::from_public_mutation_bytes(method, request.encode())
                .map_err(ReconcilerError::from),
            Err(ReconcilerError::InvalidPlan(
                "controller effect lacks authenticated admission context"
            ))
        ));
        let mut bare = record;
        bare = {
            let canonical_request = request.encode();
            let mut parts = bare.into_parts();
            let mut plan = parts.0.into_parts();
            plan.3 = canonical_request;
            parts.0 = EffectPlan::from_parts(plan);
            EffectLedgerRecord::from_parts(parts)
        };
        assert!(matches!(
            encode_effect(&bare).map_err(ReconcilerError::from),
            Err(ReconcilerError::InvalidPlan(
                "controller effect lacks authenticated admission context"
            ))
        ));
    }
}

impl From<aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError>
    for ReconcilerError
{
    fn from(
        error: aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError,
    ) -> Self {
        use aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError;

        match error {
            EffectHistoryDataError::InvalidPlan(reason) => Self::InvalidPlan(reason),
            EffectHistoryDataError::CorruptLedger(reason) => Self::CorruptLedger(reason),
            EffectHistoryDataError::InvalidExecutorOutput(reason) => Self::InvalidExecutorOutput(reason),
        }
    }
}

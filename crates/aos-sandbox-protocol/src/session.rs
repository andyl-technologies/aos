//! Negotiated node-local broker sessions and packet envelopes.
//!
//! A connection exchanges exactly one client hello and one server hello before
//! dispatch. Subsequent sequence packets use a closed method tag, a bounded
//! protobuf body, and an exact table describing ancillary descriptors. Packet
//! parsing validates table structure; each method dispatcher separately checks
//! its exact role sequence before using any descriptor.
//!
//! The local socket's [`ProtocolId`] is the protected broker audience: method
//! tags cannot cross Host, Mount, Storage, or Network domains. A future remote
//! wrapper must carry that audience in its authenticated transcript and replace
//! SCM_RIGHTS roles with a separately versioned remote object-carrier profile;
//! descriptor integers and local carrier assumptions are never portable.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerAuthorizationArtifactsV1, BrokerClientHello, BrokerDescriptorDisposition,
    BrokerDescriptorDispositionEntry, BrokerDescriptorEntry, BrokerDescriptorRole, BrokerError,
    BrokerErrorCode, BrokerMethod, BrokerRequestEnvelope, BrokerResponseEnvelope,
    BrokerServerHello, QueryRuntimeEffectResponse, RuntimeEffectStatus, RuntimeObservation,
    RuntimeState,
};
use aos_sandbox_core::format::{
    decode_broker_authorization_plan, decode_ownership_lease, decode_signature,
};
use aos_sandbox_core::{
    DecodeLimits, FeatureRef, ProtocolId, ProtocolVersion, RegistryError, negotiate_protocol,
    validate_required_features,
};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, MINIMUM_RESPONSE_BYTES, PeerCredentials,
    PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero, validate_feature_set,
    validate_peer_audience,
};

/// Maximum encoded handshake packet accepted before protobuf decoding.
pub const MAXIMUM_HANDSHAKE_BYTES: usize = 64 * 1024;
/// Maximum number of descriptors accepted in one ancillary descriptor table.
pub const MAXIMUM_PACKET_DESCRIPTORS: usize = 16;
/// Feature that makes signed plan and lease artifacts mandatory for effects.
pub const SIGNED_PLAN_LEASE_FEATURE_NAMESPACE: &str = "aos.sandbox.authorization.signed-plan-lease";
/// Maximum canonical broker-plan bytes carried in one local request.
pub const MAXIMUM_BROKER_PLAN_BYTES: usize = 768 * 1024;
/// Maximum canonical ownership-lease bytes carried in one local request.
pub const MAXIMUM_OWNERSHIP_LEASE_BYTES: usize = 64 * 1024;
/// Maximum canonical detached-signature bytes carried in one local request.
pub const MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES: usize = 64 * 1024;
/// Maximum protobuf growth when an exact Host Apply is wrapped by a 1.2 query.
pub const HOST_QUERY_WRAPPER_OVERHEAD_BYTES: usize = 64;
/// Maximum encoded Host 1.2 query packet accepted before protobuf decoding.
pub const MAXIMUM_HOST_QUERY_PACKET_BYTES: usize =
    MAXIMUM_REQUEST_BYTES + HOST_QUERY_WRAPPER_OVERHEAD_BYTES;
/// Maximum exact completed Host Apply receipt carried by an effect query.
pub const MAXIMUM_RUNTIME_EFFECT_RECEIPT_BYTES: usize = 1024 * 1024;
const MAXIMUM_AUTHORIZATION_ARTIFACT_BYTES: usize = 960 * 1024;
const MAXIMUM_BROKER_METHODS: usize = 16;
const MAXIMUM_REQUIRED_FEATURES: usize = 64;
const MAXIMUM_SAFE_ERROR_MESSAGE_BYTES: usize = 1024;

/// Records one negotiated local-broker connection contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedBrokerSession {
    protocol: ProtocolId,
    version: ProtocolVersion,
    audience: Audience,
    required_features: Vec<FeatureRef>,
    advertised_features: Vec<FeatureRef>,
    required_methods: Vec<BrokerMethod>,
    advertised_methods: Vec<BrokerMethod>,
    maximum_request_bytes: usize,
    maximum_response_bytes: u32,
}

impl NegotiatedBrokerSession {
    /// Returns the independently versioned broker protocol domain.
    #[must_use]
    pub const fn protocol(&self) -> ProtocolId {
        self.protocol
    }

    /// Returns the exact selected major/minor version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the peer audience bound to kernel credentials by negotiation.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }

    /// Returns the canonical required feature set admitted for this connection.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }

    /// Returns the canonical feature set advertised by the broker.
    #[must_use]
    pub fn advertised_features(&self) -> &[FeatureRef] {
        &self.advertised_features
    }

    /// Returns the canonical method set required by the client.
    #[must_use]
    pub fn required_methods(&self) -> &[BrokerMethod] {
        &self.required_methods
    }

    /// Returns the canonical method set advertised by the broker.
    #[must_use]
    pub fn advertised_methods(&self) -> &[BrokerMethod] {
        &self.advertised_methods
    }

    /// Returns the response ceiling selected for every subsequent exchange.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the exact packet ceiling negotiated for this broker session.
    #[must_use]
    pub const fn maximum_request_bytes(&self) -> usize {
        self.maximum_request_bytes
    }

    /// Builds the sole successful server handshake packet.
    #[must_use]
    pub fn server_hello(&self) -> BrokerServerHello {
        BrokerServerHello {
            protocol_major: u32::from(self.version.major()),
            protocol_minor: u32::from(self.version.minor()),
            features: self.advertised_features.iter().map(proto_feature).collect(),
            maximum_request_bytes: u32::try_from(self.maximum_request_bytes()).unwrap_or(u32::MAX),
            maximum_response_bytes: self.maximum_response_bytes,
            methods: self
                .advertised_methods
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            ..Default::default()
        }
    }

    /// Decodes a request envelope under this negotiated method set.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolValidationError`] when the packet is malformed, its
    /// descriptor table is inexact, or its method was not advertised on this
    /// connection.
    pub fn decode_request(
        &self,
        bytes: &[u8],
        ancillary_descriptor_count: usize,
    ) -> Result<ValidatedBrokerRequestEnvelope, ProtocolValidationError> {
        let request = decode_request_envelope(bytes, self.protocol, ancillary_descriptor_count)?;
        validate_session_role_and_carriers(self.audience, &request)?;
        if !self.advertised_methods.contains(&request.method) {
            return Err(ProtocolValidationError::MethodMismatch);
        }
        validate_authorization_profile(self.version, &self.required_features, &request)?;
        Ok(request)
    }

    /// Binds a validated method-body header to this negotiated session.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolValidationError`] unless version and audience exactly
    /// match the hello exchange and the body response ceiling fits the
    /// negotiated connection ceiling.
    pub fn validate_header(&self, header: &ValidatedHeader) -> Result<(), ProtocolValidationError> {
        if header.protocol_version() != self.version || header.audience() != self.audience {
            return Err(ProtocolValidationError::MethodMismatch);
        }
        if header.maximum_response_bytes() > self.maximum_response_bytes {
            return Err(ProtocolValidationError::InvalidResponseBound);
        }
        Ok(())
    }
}

/// Carries one validated ancillary descriptor-table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedDescriptorEntry {
    role: BrokerDescriptorRole,
}

impl ValidatedDescriptorEntry {
    /// Returns the semantic descriptor role at this ancillary array index.
    #[must_use]
    pub const fn role(self) -> BrokerDescriptorRole {
        self.role
    }
}

/// Records the terminal ownership of one request descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedDescriptorDisposition {
    role: BrokerDescriptorRole,
    disposition: BrokerDescriptorDisposition,
}

impl ValidatedDescriptorDisposition {
    /// Returns the original request descriptor role.
    #[must_use]
    pub const fn role(self) -> BrokerDescriptorRole {
        self.role
    }

    /// Returns the broker's terminal ownership decision.
    #[must_use]
    pub const fn disposition(self) -> BrokerDescriptorDisposition {
        self.disposition
    }
}

/// Carries one validated, closed-method request packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBrokerRequestEnvelope {
    method: BrokerMethod,
    body: Vec<u8>,
    descriptors: Vec<ValidatedDescriptorEntry>,
    authorization: Option<ValidatedUntrustedAuthorizationArtifacts>,
}

impl ValidatedBrokerRequestEnvelope {
    /// Returns the closed dispatch method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the bounded method-specific protobuf body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the exact role table in ancillary descriptor order.
    #[must_use]
    pub fn descriptors(&self) -> &[ValidatedDescriptorEntry] {
        &self.descriptors
    }

    /// Returns exact canonical artifacts that still carry no authority.
    #[must_use]
    pub const fn authorization(&self) -> Option<&ValidatedUntrustedAuthorizationArtifacts> {
        self.authorization.as_ref()
    }
}

/// Preserves one structurally valid but explicitly untrusted artifact quartet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedUntrustedAuthorizationArtifacts {
    broker_plan: Vec<u8>,
    broker_plan_signature: Vec<u8>,
    ownership_lease: Vec<u8>,
    ownership_lease_signature: Vec<u8>,
}

/// Borrows the exact signed artifact bytes for one outbound effect request.
///
/// Construction performs no trust decision. [`encode_authorized_request_envelope`]
/// validates each canonical object and all transport bounds before copying the
/// bytes into the protobuf packet.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationArtifactBytes<'a> {
    /// Canonical `BrokerAuthorizationPlan` CBOR bytes.
    pub broker_plan: &'a [u8],
    /// Canonical detached broker-plan `Signature` CBOR bytes.
    pub broker_plan_signature: &'a [u8],
    /// Canonical `OwnershipLease` CBOR bytes.
    pub ownership_lease: &'a [u8],
    /// Canonical detached ownership-lease `Signature` CBOR bytes.
    pub ownership_lease_signature: &'a [u8],
}

impl ValidatedUntrustedAuthorizationArtifacts {
    /// Returns the exact received canonical broker-plan bytes.
    #[must_use]
    pub fn broker_plan(&self) -> &[u8] {
        &self.broker_plan
    }

    /// Returns the exact received canonical detached plan signature bytes.
    #[must_use]
    pub fn broker_plan_signature(&self) -> &[u8] {
        &self.broker_plan_signature
    }

    /// Returns the exact received canonical ownership-lease bytes.
    #[must_use]
    pub fn ownership_lease(&self) -> &[u8] {
        &self.ownership_lease
    }

    /// Returns the exact received canonical detached lease signature bytes.
    #[must_use]
    pub fn ownership_lease_signature(&self) -> &[u8] {
        &self.ownership_lease_signature
    }
}

/// Carries one validated response packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBrokerResponseEnvelope {
    request_id: [u8; 16],
    method: BrokerMethod,
    body: Vec<u8>,
    descriptors: Vec<ValidatedDescriptorEntry>,
    request_descriptor_dispositions: Vec<ValidatedDescriptorDisposition>,
    error: Option<ValidatedBrokerError>,
}

/// Reports one structurally validated Host Apply effect status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatedRuntimeEffectStatus {
    /// No exact durable request exists.
    Absent,
    /// The exact durable request remains pending.
    Pending,
    /// The exact durable request completed with these response bytes.
    Complete(Vec<u8>),
}

impl ValidatedBrokerResponseEnvelope {
    /// Returns the request identifier echoed by the broker.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Returns the closed method whose result is carried in the body.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the bounded method-specific protobuf response.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the exact response descriptor table.
    #[must_use]
    pub fn descriptors(&self) -> &[ValidatedDescriptorEntry] {
        &self.descriptors
    }

    /// Returns ownership accounting for every original request descriptor.
    #[must_use]
    pub fn request_descriptor_dispositions(&self) -> &[ValidatedDescriptorDisposition] {
        &self.request_descriptor_dispositions
    }

    /// Returns the validated transport-level broker error, when present.
    #[must_use]
    pub const fn error(&self) -> Option<&ValidatedBrokerError> {
        self.error.as_ref()
    }
}

/// Carries one validated transport-level broker error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBrokerError {
    code: BrokerErrorCode,
    safe_message: String,
    retryable: bool,
    missing_feature: Option<FeatureRef>,
}

impl ValidatedBrokerError {
    /// Returns the closed error code.
    #[must_use]
    pub const fn code(&self) -> BrokerErrorCode {
        self.code
    }

    /// Returns the bounded non-sensitive diagnostic message.
    #[must_use]
    pub fn safe_message(&self) -> &str {
        &self.safe_message
    }

    /// Reports whether retry can succeed without changing request semantics.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// Returns the unavailable required feature only for its matching code.
    #[must_use]
    pub const fn missing_feature(&self) -> Option<&FeatureRef> {
        self.missing_feature.as_ref()
    }
}

/// Negotiates the client and server hello packets before request dispatch.
///
/// The caller receives this hello as the first packet and sends
/// [`NegotiatedBrokerSession::server_hello`] as the second. No request is valid
/// before this function succeeds.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed or incompatible offers,
/// peer/audience mismatch, invalid bounds, or unavailable required semantics.
pub fn negotiate_client_hello(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol: ProtocolId,
    advertised_features: &[FeatureRef],
    advertised_methods: &[BrokerMethod],
) -> Result<NegotiatedBrokerSession, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HANDSHAKE_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let hello = BrokerClientHello::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !hello.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    validate_peer_audience(peer, policy, hello.audience.as_known())?;

    let major = u16::try_from(hello.protocol_major)
        .map_err(|_| incompatible_protocol(protocol, hello.protocol_major, hello.protocol_minor))?;
    let minor = u16::try_from(hello.protocol_minor)
        .map_err(|_| incompatible_protocol(protocol, hello.protocol_major, hello.protocol_minor))?;
    let version = negotiate_protocol(protocol, ProtocolVersion::new(major, minor))?;
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&hello.maximum_response_bytes) {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }

    validate_canonical_feature_refs(advertised_features)?;
    validate_canonical_methods(advertised_methods, protocol, "advertised_methods")?;
    let advertised_methods = advertised_methods
        .iter()
        .copied()
        .filter(|method| method_available_in_version(*method, version))
        .collect::<Vec<_>>();
    let required_features =
        validate_feature_set(&hello.required_features, "hello.required_features")?;
    ensure_feature_subset(&required_features, advertised_features)?;
    let required_methods =
        validate_proto_methods(&hello.required_methods, protocol, "hello.required_methods")?;
    validate_role_methods(policy.audience, &required_methods)?;
    ensure_method_subset(&required_methods, &advertised_methods)?;
    validate_negotiated_authorization_profile(version, &required_features, &required_methods)?;

    Ok(NegotiatedBrokerSession {
        protocol,
        version,
        audience: policy.audience,
        required_features,
        advertised_features: advertised_features.to_vec(),
        required_methods,
        advertised_methods,
        maximum_request_bytes: maximum_request_bytes(protocol, version),
        maximum_response_bytes: hello.maximum_response_bytes,
    })
}

/// Validates the broker's sole hello response on the untrusted client side.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed packets, an inexact
/// version, invalid ceilings, noncanonical capability sets, or a rejection.
#[allow(clippy::too_many_arguments)]
pub fn decode_server_hello(
    bytes: &[u8],
    protocol: ProtocolId,
    audience: Audience,
    offered_version: ProtocolVersion,
    required_features: &[FeatureRef],
    required_methods: &[BrokerMethod],
    offered_maximum_response_bytes: u32,
) -> Result<NegotiatedBrokerSession, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HANDSHAKE_BYTES {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    let hello = BrokerServerHello::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !hello.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }

    let error = hello
        .error
        .as_option()
        .map(validate_broker_error)
        .transpose()?;
    if let Some(error) = error {
        validate_failed_server_hello(&hello)?;
        return Err(ProtocolValidationError::BrokerRejected(error.code()));
    }

    if audience == Audience::AUDIENCE_UNSPECIFIED
        || hello.protocol_major != u32::from(offered_version.major())
        || hello.protocol_minor != u32::from(offered_version.minor())
    {
        return Err(ProtocolValidationError::Protocol(incompatible_protocol(
            protocol,
            hello.protocol_major,
            hello.protocol_minor,
        )));
    }
    negotiate_protocol(protocol, offered_version)?;
    validate_server_bounds(
        &hello,
        protocol,
        offered_version,
        offered_maximum_response_bytes,
    )?;

    validate_canonical_feature_refs(required_features)?;
    let advertised_features = validate_feature_set(&hello.features, "server_hello.features")?;
    ensure_feature_subset(required_features, &advertised_features)?;
    validate_canonical_methods(required_methods, protocol, "required_methods")?;
    validate_role_methods(audience, required_methods)?;
    let advertised_methods =
        validate_proto_methods(&hello.methods, protocol, "server_hello.methods")?;
    validate_methods_available(&advertised_methods, offered_version)?;
    ensure_method_subset(required_methods, &advertised_methods)?;
    validate_negotiated_authorization_profile(
        offered_version,
        required_features,
        required_methods,
    )?;

    Ok(NegotiatedBrokerSession {
        protocol,
        version: offered_version,
        audience,
        required_features: required_features.to_vec(),
        advertised_features,
        required_methods: required_methods.to_vec(),
        advertised_methods,
        maximum_request_bytes: usize::try_from(hello.maximum_request_bytes)
            .map_err(|_| ProtocolValidationError::InvalidResponseBound)?,
        maximum_response_bytes: hello.maximum_response_bytes,
    })
}

/// Decodes one bounded request envelope after successful negotiation.
///
/// This validates structure and protocol scope, not the role sequence for an
/// action inside the body. Dispatchers must subsequently call
/// [`validate_request_descriptor_roles`].
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed packets, cross-protocol
/// methods, empty bodies, or noncanonical descriptor tables.
pub fn decode_request_envelope(
    bytes: &[u8],
    protocol: ProtocolId,
    ancillary_descriptor_count: usize,
) -> Result<ValidatedBrokerRequestEnvelope, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HOST_QUERY_PACKET_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let envelope = BrokerRequestEnvelope::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !envelope.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let method = validate_method(envelope.method.as_known(), protocol)?;
    if bytes.len() > MAXIMUM_REQUEST_BYTES
        && method != BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
    {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    if envelope.body.is_empty() {
        return Err(ProtocolValidationError::InvalidField("envelope.body"));
    }
    let descriptors = validate_descriptor_table(&envelope.descriptors, ancillary_descriptor_count)?;
    // The new roles are response-only and cannot widen any existing method's
    // descriptor vocabulary merely by becoming known enum values.
    if (matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
    ) && !descriptors.is_empty())
        || descriptors
            .iter()
            .any(|entry| crate::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES.contains(&entry.role))
    {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    let authorization = envelope
        .authorization
        .as_option()
        .map(validate_authorization_artifacts)
        .transpose()?;
    Ok(ValidatedBrokerRequestEnvelope {
        method,
        body: envelope.body,
        descriptors,
        authorization,
    })
}

/// Encodes one authority-bearing effect request under the fixed packet bounds.
///
/// The descriptor roles become the canonical contiguous descriptor table in
/// ancillary-descriptor order. Artifact bytes are structurally validated but
/// remain untrusted; the receiving broker must still verify signatures, trust,
/// clocks, request semantics, and durable fences.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an empty or oversized body, an
/// invalid method/protocol pairing, a non-effect method, an invalid descriptor
/// table, malformed or oversized authorization artifacts, or an encoded packet
/// exceeding [`crate::MAXIMUM_REQUEST_BYTES`].
pub fn encode_authorized_request_envelope(
    protocol: ProtocolId,
    method: BrokerMethod,
    body: &[u8],
    descriptor_roles: &[BrokerDescriptorRole],
    authorization: AuthorizationArtifactBytes<'_>,
) -> Result<Vec<u8>, ProtocolValidationError> {
    let method = validate_method(Some(method), protocol)?;
    validate_outbound_carriers(method, descriptor_roles)?;
    if !method_requires_authorization(method) {
        return Err(ProtocolValidationError::InvalidField(
            "envelope.authorization profile",
        ));
    }
    if body.is_empty() {
        return Err(ProtocolValidationError::InvalidField("envelope.body"));
    }
    if body.len() > MAXIMUM_HOST_QUERY_PACKET_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }

    validate_authorization_artifact_bytes(authorization)?;
    let descriptors = outbound_descriptor_table(descriptor_roles)?;
    let envelope = BrokerRequestEnvelope {
        method: method.into(),
        body: body.to_vec(),
        descriptors,
        authorization: Some(BrokerAuthorizationArtifactsV1 {
            broker_plan: authorization.broker_plan.to_vec(),
            broker_plan_signature: authorization.broker_plan_signature.to_vec(),
            ownership_lease: authorization.ownership_lease.to_vec(),
            ownership_lease_signature: authorization.ownership_lease_signature.to_vec(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let encoded = envelope.encode_to_vec();
    let maximum = if method == BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT {
        MAXIMUM_HOST_QUERY_PACKET_BYTES
    } else {
        MAXIMUM_REQUEST_BYTES
    };
    if encoded.len() > maximum {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    Ok(encoded)
}

/// Decodes a hostile Host effect-query body and validates its exact receipt.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed or oversized bytes,
/// unknown status or fields, an invalid status/receipt shape, or a completed
/// observation whose assignment fence differs from the original Apply.
pub fn decode_query_runtime_effect_response(
    bytes: &[u8],
    original_request: &crate::ValidatedRuntimeRequest,
) -> Result<ValidatedRuntimeEffectStatus, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_RESPONSE_BYTES as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = QueryRuntimeEffectResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    match response.status.as_known() {
        Some(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_ABSENT) if response.receipt.is_empty() => {
            Ok(ValidatedRuntimeEffectStatus::Absent)
        }
        Some(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_PENDING) if response.receipt.is_empty() => {
            Ok(ValidatedRuntimeEffectStatus::Pending)
        }
        Some(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE)
            if !response.receipt.is_empty()
                && response.receipt.len() <= MAXIMUM_RUNTIME_EFFECT_RECEIPT_BYTES =>
        {
            validate_runtime_effect_receipt(&response.receipt, original_request)?;
            Ok(ValidatedRuntimeEffectStatus::Complete(response.receipt))
        }
        _ => Err(ProtocolValidationError::InvalidField(
            "query response status/receipt",
        )),
    }
}

/// Validates a stored Host completion receipt against its exact Apply body.
///
/// This recovery-oriented path deliberately does not re-evaluate the expired
/// request deadline. It decodes the original body only to recover the exact
/// assignment fence that the receipt must name.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] when either object is malformed, has
/// unknown fields, or the receipt's runtime handle and fence do not match the
/// original Apply request.
pub fn validate_runtime_effect_receipt_for_apply(
    receipt: &[u8],
    original_apply_body: &[u8],
) -> Result<(), ProtocolValidationError> {
    use aos_proto::aos::sandbox::local::v1::ApplyRuntimeRequest;

    if original_apply_body.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyRuntimeRequest::decode_from_slice(original_apply_body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let fence = request
        .fence
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("fence"))?;
    let expected_fence = crate::validate_fence(fence)?;
    validate_runtime_effect_receipt_against_fence(receipt, &expected_fence)
}

fn validate_runtime_effect_receipt(
    bytes: &[u8],
    original_request: &crate::ValidatedRuntimeRequest,
) -> Result<(), ProtocolValidationError> {
    validate_runtime_effect_receipt_against_fence(bytes, original_request.fence())
}

fn validate_runtime_effect_receipt_against_fence(
    bytes: &[u8],
    expected_fence: &crate::ValidatedAssignmentFence,
) -> Result<(), ProtocolValidationError> {
    let observation = RuntimeObservation::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !observation.__buffa_unknown_fields.is_empty()
        || observation.error.as_option().is_some()
        || observation.observation_sequence == 0
        || observation
            .state
            .as_known()
            .is_none_or(|state| state == RuntimeState::RUNTIME_STATE_UNSPECIFIED)
    {
        return Err(ProtocolValidationError::InvalidField(
            "query response receipt",
        ));
    }
    let runtime_handle =
        exact_nonzero::<32>(&observation.runtime_handle, "receipt.runtime_handle")?;
    let expected_handle = crate::semantics::host::runtime_handle_v1(
        expected_fence.incarnation_id(),
        expected_fence.assignment_epoch(),
        expected_fence.assignment_digest(),
    );
    if runtime_handle != expected_handle {
        return Err(ProtocolValidationError::InvalidField(
            "receipt.runtime_handle",
        ));
    }
    if !observation.leader_handle.is_empty() {
        exact_nonzero::<32>(&observation.leader_handle, "receipt.leader_handle")?;
    }
    let fence = observation
        .fence
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("receipt.fence"))?;
    if !fence.__buffa_unknown_fields.is_empty() || crate::validate_fence(fence)? != *expected_fence
    {
        return Err(ProtocolValidationError::InvalidField("receipt.fence"));
    }
    Ok(())
}

fn validate_authorization_artifacts(
    artifacts: &BrokerAuthorizationArtifactsV1,
) -> Result<ValidatedUntrustedAuthorizationArtifacts, ProtocolValidationError> {
    if !artifacts.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::InvalidField(
            "envelope.authorization",
        ));
    }
    validate_authorization_artifact_bytes(AuthorizationArtifactBytes {
        broker_plan: &artifacts.broker_plan,
        broker_plan_signature: &artifacts.broker_plan_signature,
        ownership_lease: &artifacts.ownership_lease,
        ownership_lease_signature: &artifacts.ownership_lease_signature,
    })?;

    Ok(ValidatedUntrustedAuthorizationArtifacts {
        broker_plan: artifacts.broker_plan.clone(),
        broker_plan_signature: artifacts.broker_plan_signature.clone(),
        ownership_lease: artifacts.ownership_lease.clone(),
        ownership_lease_signature: artifacts.ownership_lease_signature.clone(),
    })
}

fn validate_authorization_artifact_bytes(
    artifacts: AuthorizationArtifactBytes<'_>,
) -> Result<(), ProtocolValidationError> {
    if artifacts.broker_plan.is_empty()
        || artifacts.broker_plan.len() > MAXIMUM_BROKER_PLAN_BYTES
        || artifacts.broker_plan_signature.is_empty()
        || artifacts.broker_plan_signature.len() > MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES
        || artifacts.ownership_lease.is_empty()
        || artifacts.ownership_lease.len() > MAXIMUM_OWNERSHIP_LEASE_BYTES
        || artifacts.ownership_lease_signature.is_empty()
        || artifacts.ownership_lease_signature.len() > MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES
    {
        return Err(ProtocolValidationError::InvalidField(
            "envelope.authorization",
        ));
    }
    let aggregate = artifacts
        .broker_plan
        .len()
        .checked_add(artifacts.broker_plan_signature.len())
        .and_then(|size| size.checked_add(artifacts.ownership_lease.len()))
        .and_then(|size| size.checked_add(artifacts.ownership_lease_signature.len()))
        .ok_or(ProtocolValidationError::RequestTooLarge)?;
    if aggregate > MAXIMUM_AUTHORIZATION_ARTIFACT_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }

    decode_broker_authorization_plan(
        artifacts.broker_plan,
        authorization_decode_limits(MAXIMUM_BROKER_PLAN_BYTES),
    )
    .map_err(|_| ProtocolValidationError::InvalidField("envelope.authorization.plan"))?;
    decode_signature(
        artifacts.broker_plan_signature,
        authorization_decode_limits(MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES),
    )
    .map_err(|_| ProtocolValidationError::InvalidField("envelope.authorization.plan_signature"))?;
    decode_ownership_lease(
        artifacts.ownership_lease,
        authorization_decode_limits(MAXIMUM_OWNERSHIP_LEASE_BYTES),
    )
    .map_err(|_| ProtocolValidationError::InvalidField("envelope.authorization.lease"))?;
    decode_signature(
        artifacts.ownership_lease_signature,
        authorization_decode_limits(MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES),
    )
    .map_err(|_| ProtocolValidationError::InvalidField("envelope.authorization.lease_signature"))?;
    Ok(())
}

fn outbound_descriptor_table(
    roles: &[BrokerDescriptorRole],
) -> Result<Vec<BrokerDescriptorEntry>, ProtocolValidationError> {
    if roles.len() > MAXIMUM_PACKET_DESCRIPTORS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "envelope.descriptors",
            maximum: MAXIMUM_PACKET_DESCRIPTORS,
        });
    }
    let mut descriptors = Vec::with_capacity(roles.len());
    for (index, role) in roles.iter().copied().enumerate() {
        if role == BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED
            || roles[..index].contains(&role)
        {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
        descriptors.push(BrokerDescriptorEntry {
            index: u32::try_from(index)
                .map_err(|_| ProtocolValidationError::DescriptorTableMismatch)?,
            role: role.into(),
            ..Default::default()
        });
    }
    Ok(descriptors)
}

const fn authorization_decode_limits(maximum_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes,
        maximum_collection_items: 2_048,
        maximum_total_items: 65_536,
        maximum_byte_string_bytes: maximum_bytes,
        maximum_text_bytes: 64 * 1024,
        maximum_depth: 128,
    }
}

fn validate_negotiated_authorization_profile(
    version: ProtocolVersion,
    required_features: &[FeatureRef],
    required_methods: &[BrokerMethod],
) -> Result<(), ProtocolValidationError> {
    let requires_effect_authority = required_methods
        .iter()
        .copied()
        .any(method_requires_authorization);
    let feature_required = required_features.iter().any(is_signed_plan_lease_feature);
    if version.minor() == 0 {
        if feature_required || requires_effect_authority {
            return Err(ProtocolValidationError::RequiredFeatureUnavailable(
                SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(),
            ));
        }
        return Ok(());
    }
    if requires_effect_authority && !feature_required {
        return Err(ProtocolValidationError::RequiredFeatureUnavailable(
            SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(),
        ));
    }
    Ok(())
}

fn validate_authorization_profile(
    version: ProtocolVersion,
    required_features: &[FeatureRef],
    request: &ValidatedBrokerRequestEnvelope,
) -> Result<(), ProtocolValidationError> {
    if method_requires_authorization(request.method) {
        if version.minor() < 1 || !required_features.iter().any(is_signed_plan_lease_feature) {
            return Err(ProtocolValidationError::RequiredFeatureUnavailable(
                SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(),
            ));
        }
        if request.authorization.is_none() {
            return Err(ProtocolValidationError::InvalidField(
                "envelope.authorization profile",
            ));
        }
    } else if request.authorization.is_some() {
        return Err(ProtocolValidationError::InvalidField(
            "envelope.authorization profile",
        ));
    }
    Ok(())
}

const fn method_requires_authorization(method: BrokerMethod) -> bool {
    matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
            | BrokerMethod::BROKER_METHOD_MOUNT_APPLY
            | BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            | BrokerMethod::BROKER_METHOD_NETWORK_APPLY
    )
}

fn validate_session_role_and_carriers(
    audience: Audience,
    request: &ValidatedBrokerRequestEnvelope,
) -> Result<(), ProtocolValidationError> {
    validate_role_methods(audience, &[request.method])?;
    let roles = request
        .descriptors
        .iter()
        .map(|descriptor| descriptor.role)
        .collect::<Vec<_>>();
    validate_outbound_carriers(request.method, &roles)
}

fn validate_role_methods(
    audience: Audience,
    methods: &[BrokerMethod],
) -> Result<(), ProtocolValidationError> {
    let valid = !methods.is_empty()
        && match audience {
            Audience::AUDIENCE_NODE_CONTROLLER => methods
                .iter()
                .all(|method| *method != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE),
            Audience::AUDIENCE_ROOT_MOUNT => methods
                .iter()
                .all(|method| *method == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE),
            _ => false,
        };
    if valid {
        Ok(())
    } else {
        Err(ProtocolValidationError::MethodMismatch)
    }
}

fn validate_outbound_carriers(
    method: BrokerMethod,
    roles: &[BrokerDescriptorRole],
) -> Result<(), ProtocolValidationError> {
    let valid = match method {
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => roles.iter().all(|role| {
            matches!(
                role,
                BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_MOUNT_NAMESPACE
                    | BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT
                    | BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_MOUNT_SOURCE
                    | BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_DETACHED_MOUNT
                    | BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE
                    | BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT
            )
        }),
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY
        | BrokerMethod::BROKER_METHOD_NETWORK_APPLY
        | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY => roles.is_empty(),
        BrokerMethod::BROKER_METHOD_UNSPECIFIED => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ProtocolValidationError::DescriptorTableMismatch)
    }
}

fn is_signed_plan_lease_feature(feature: &FeatureRef) -> bool {
    feature.namespace() == SIGNED_PLAN_LEASE_FEATURE_NAMESPACE
        && feature.major() == 1
        && feature.minor() == 0
}

/// Validates the exact descriptor role sequence selected by a fixed method.
///
/// # Errors
///
/// Returns [`ProtocolValidationError::DescriptorTableMismatch`] unless the
/// structurally validated table exactly equals `expected_roles`.
pub fn validate_request_descriptor_roles(
    request: &ValidatedBrokerRequestEnvelope,
    expected_roles: &[BrokerDescriptorRole],
) -> Result<(), ProtocolValidationError> {
    if request.descriptors.len() != expected_roles.len()
        || request
            .descriptors
            .iter()
            .zip(expected_roles)
            .any(|(actual, expected)| actual.role != *expected)
    {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    Ok(())
}

/// Encodes one successful broker response under the admitted packet ceiling.
///
/// Descriptor role arrays are converted to canonical contiguous tables. Each
/// request descriptor must have exactly one terminal disposition.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for empty bodies, malformed descriptor
/// accounting, sentinel request IDs, or an encoded packet over `maximum_bytes`.
pub fn encode_success_response_envelope(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    body: Vec<u8>,
    response_descriptor_roles: &[BrokerDescriptorRole],
    request_descriptor_dispositions: &[BrokerDescriptorDisposition],
    maximum_bytes: u32,
) -> Result<Vec<u8>, ProtocolValidationError> {
    encode_response_envelope(
        request_id,
        request,
        body,
        None,
        response_descriptor_roles,
        request_descriptor_dispositions,
        maximum_bytes,
    )
}

/// Encodes one safe broker error under the admitted packet ceiling.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed error semantics,
/// descriptor accounting, sentinel request IDs, or an oversized packet.
#[allow(clippy::too_many_arguments)]
pub fn encode_error_response_envelope(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    code: BrokerErrorCode,
    safe_message: &str,
    retryable: bool,
    missing_feature: Option<&FeatureRef>,
    request_descriptor_dispositions: &[BrokerDescriptorDisposition],
    maximum_bytes: u32,
) -> Result<Vec<u8>, ProtocolValidationError> {
    let error = BrokerError {
        code: code.into(),
        safe_message: safe_message.to_owned(),
        retryable,
        missing_feature: missing_feature.map(proto_feature).into(),
        ..Default::default()
    };
    validate_broker_error(&error)?;
    encode_response_envelope(
        request_id,
        request,
        Vec::new(),
        Some(error),
        &[],
        request_descriptor_dispositions,
        maximum_bytes,
    )
}

/// Constructs the only valid failed server-hello shape.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] unless the error code, safe message,
/// and optional missing feature form a valid closed broker error.
pub fn failed_server_hello(
    code: BrokerErrorCode,
    safe_message: &str,
    retryable: bool,
    missing_feature: Option<&FeatureRef>,
) -> Result<BrokerServerHello, ProtocolValidationError> {
    let error = BrokerError {
        code: code.into(),
        safe_message: safe_message.to_owned(),
        retryable,
        missing_feature: missing_feature.map(proto_feature).into(),
        ..Default::default()
    };
    validate_broker_error(&error)?;
    Ok(BrokerServerHello {
        error: Some(error).into(),
        ..Default::default()
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_response_envelope(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    body: Vec<u8>,
    error: Option<BrokerError>,
    response_descriptor_roles: &[BrokerDescriptorRole],
    request_descriptor_dispositions: &[BrokerDescriptorDisposition],
    maximum_bytes: u32,
) -> Result<Vec<u8>, ProtocolValidationError> {
    exact_nonzero::<16>(request_id, "envelope.request_id")?;
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&maximum_bytes) {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    if !valid_response_body_shape(request.method, body.is_empty(), error.is_some()) {
        return Err(ProtocolValidationError::InvalidField(
            "response body/error shape",
        ));
    }
    if request_descriptor_dispositions.len() != request.descriptors.len() {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    let descriptors = descriptor_entries(response_descriptor_roles)?;
    let dispositions = request
        .descriptors
        .iter()
        .zip(request_descriptor_dispositions)
        .enumerate()
        .map(
            |(index, (descriptor, disposition))| BrokerDescriptorDispositionEntry {
                request_index: u32::try_from(index).unwrap_or(u32::MAX),
                role: descriptor.role.into(),
                disposition: (*disposition).into(),
                ..Default::default()
            },
        )
        .collect();
    let envelope = BrokerResponseEnvelope {
        request_id: request_id.to_vec(),
        method: request.method.into(),
        body,
        descriptors,
        error: error.into(),
        request_descriptor_dispositions: dispositions,
        ..Default::default()
    };
    let bytes = envelope.encode_to_vec();
    decode_response_envelope(
        &bytes,
        request_id,
        request.method,
        &request.descriptors,
        response_descriptor_roles.len(),
        maximum_bytes,
        maximum_bytes,
    )?;
    Ok(bytes)
}

fn descriptor_entries(
    roles: &[BrokerDescriptorRole],
) -> Result<Vec<BrokerDescriptorEntry>, ProtocolValidationError> {
    if roles.len() > MAXIMUM_PACKET_DESCRIPTORS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "envelope.descriptors",
            maximum: MAXIMUM_PACKET_DESCRIPTORS,
        });
    }
    let entries = roles
        .iter()
        .copied()
        .enumerate()
        .map(|(index, role)| BrokerDescriptorEntry {
            index: u32::try_from(index).unwrap_or(u32::MAX),
            role: role.into(),
            ..Default::default()
        })
        .collect::<Vec<_>>();
    validate_descriptor_table(&entries, roles.len())?;
    Ok(entries)
}

/// Decodes one response under negotiated and per-request allocation bounds.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for malformed or oversized packets,
/// request/method mismatch, invalid error shape, or inexact descriptor tables.
#[allow(clippy::too_many_arguments)]
pub fn decode_response_envelope(
    bytes: &[u8],
    expected_request_id: &[u8; 16],
    expected_method: BrokerMethod,
    request_descriptors: &[ValidatedDescriptorEntry],
    ancillary_descriptor_count: usize,
    negotiated_maximum_response_bytes: u32,
    request_maximum_response_bytes: u32,
) -> Result<ValidatedBrokerResponseEnvelope, ProtocolValidationError> {
    let maximum = negotiated_maximum_response_bytes.min(request_maximum_response_bytes);
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&maximum)
        || bytes.len() > maximum as usize
    {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    let envelope = BrokerResponseEnvelope::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !envelope.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let request_id = exact_nonzero::<16>(&envelope.request_id, "envelope.request_id")?;
    if &request_id != expected_request_id || envelope.method.as_known() != Some(expected_method) {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    if !valid_response_body_shape(
        expected_method,
        envelope.body.is_empty(),
        envelope.error.as_option().is_some(),
    ) {
        return Err(ProtocolValidationError::InvalidField(
            "response body/error shape",
        ));
    }
    let error = envelope
        .error
        .as_option()
        .map(validate_broker_error)
        .transpose()?;
    let descriptors = validate_descriptor_table(&envelope.descriptors, ancillary_descriptor_count)?;
    if matches!(
        expected_method,
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
    ) {
        let expected_roles: &[BrokerDescriptorRole] = if error.is_some() {
            &[]
        } else if expected_method == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE {
            &crate::mount_scope::MOUNT_SCOPE_DESCRIPTOR_ROLES
        } else {
            &crate::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES
        };
        if !request_descriptors.is_empty()
            || descriptors.len() != expected_roles.len()
            || descriptors
                .iter()
                .zip(expected_roles)
                .any(|(actual, expected)| actual.role != *expected)
        {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
    } else if descriptors
        .iter()
        .any(|entry| crate::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES.contains(&entry.role))
    {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    let request_descriptor_dispositions = validate_descriptor_dispositions(
        &envelope.request_descriptor_dispositions,
        request_descriptors,
    )?;
    Ok(ValidatedBrokerResponseEnvelope {
        request_id,
        method: expected_method,
        body: envelope.body,
        descriptors,
        request_descriptor_dispositions,
        error,
    })
}

fn valid_response_body_shape(
    method: BrokerMethod,
    body_is_empty: bool,
    error_is_present: bool,
) -> bool {
    if error_is_present {
        body_is_empty
    } else if matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
            | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY
            | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
    ) {
        true
    } else {
        !body_is_empty
    }
}

fn validate_failed_server_hello(hello: &BrokerServerHello) -> Result<(), ProtocolValidationError> {
    if hello.protocol_major != 0
        || hello.protocol_minor != 0
        || !hello.features.is_empty()
        || !hello.methods.is_empty()
        || hello.maximum_request_bytes != 0
        || hello.maximum_response_bytes != 0
    {
        return Err(ProtocolValidationError::InvalidField(
            "server hello failure shape",
        ));
    }
    Ok(())
}

fn validate_server_bounds(
    hello: &BrokerServerHello,
    protocol: ProtocolId,
    version: ProtocolVersion,
    offered_maximum_response_bytes: u32,
) -> Result<(), ProtocolValidationError> {
    let maximum_request_bytes = maximum_request_bytes(protocol, version);
    if hello.maximum_request_bytes == 0
        || usize::try_from(hello.maximum_request_bytes)
            .map_or(true, |maximum| maximum > maximum_request_bytes)
        || !(MINIMUM_RESPONSE_BYTES..=offered_maximum_response_bytes)
            .contains(&hello.maximum_response_bytes)
        || hello.maximum_response_bytes > MAXIMUM_RESPONSE_BYTES
    {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    Ok(())
}

fn incompatible_protocol(protocol: ProtocolId, major: u32, minor: u32) -> RegistryError {
    RegistryError::IncompatibleProtocol {
        protocol,
        offered_major: u16::try_from(major).unwrap_or(u16::MAX),
        offered_minor: u16::try_from(minor).unwrap_or(u16::MAX),
        local_major: 1,
        local_minor: 0,
    }
}

fn validate_method(
    method: Option<BrokerMethod>,
    protocol: ProtocolId,
) -> Result<BrokerMethod, ProtocolValidationError> {
    let method = method
        .filter(|method| *method != BrokerMethod::BROKER_METHOD_UNSPECIFIED)
        .ok_or(ProtocolValidationError::UnknownAction)?;
    let valid = matches!(
        (protocol, method),
        (
            ProtocolId::HostBroker,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
        ) | (
            ProtocolId::MountBroker,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY
                | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY
                | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
        ) | (
            ProtocolId::StorageBroker,
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY
        ) | (
            ProtocolId::NetworkBroker,
            BrokerMethod::BROKER_METHOD_NETWORK_APPLY
                | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
        )
    );
    if !valid {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    Ok(method)
}

fn method_available_in_version(method: BrokerMethod, version: ProtocolVersion) -> bool {
    if method == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE {
        return version.minor() >= 3;
    }
    !matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
    ) || version.minor() >= 2
}

const fn maximum_request_bytes(protocol: ProtocolId, version: ProtocolVersion) -> usize {
    if matches!(protocol, ProtocolId::HostBroker) && version.minor() >= 2 {
        MAXIMUM_HOST_QUERY_PACKET_BYTES
    } else {
        MAXIMUM_REQUEST_BYTES
    }
}

fn validate_methods_available(
    methods: &[BrokerMethod],
    version: ProtocolVersion,
) -> Result<(), ProtocolValidationError> {
    if methods
        .iter()
        .all(|method| method_available_in_version(*method, version))
    {
        Ok(())
    } else {
        Err(ProtocolValidationError::MethodMismatch)
    }
}

fn validate_proto_methods(
    source: &[buffa::EnumValue<BrokerMethod>],
    protocol: ProtocolId,
    field: &'static str,
) -> Result<Vec<BrokerMethod>, ProtocolValidationError> {
    if source.len() > MAXIMUM_BROKER_METHODS {
        return Err(ProtocolValidationError::TooManyEntries {
            field,
            maximum: MAXIMUM_BROKER_METHODS,
        });
    }
    let methods = source
        .iter()
        .map(|value| validate_method(value.as_known(), protocol))
        .collect::<Result<Vec<_>, _>>()?;
    validate_canonical_methods(&methods, protocol, field)?;
    Ok(methods)
}

fn validate_canonical_methods(
    methods: &[BrokerMethod],
    protocol: ProtocolId,
    field: &'static str,
) -> Result<(), ProtocolValidationError> {
    if methods.is_empty() {
        return Err(ProtocolValidationError::InvalidField(field));
    }
    if methods.len() > MAXIMUM_BROKER_METHODS {
        return Err(ProtocolValidationError::TooManyEntries {
            field,
            maximum: MAXIMUM_BROKER_METHODS,
        });
    }
    for method in methods {
        validate_method(Some(*method), protocol)?;
    }
    if methods
        .windows(2)
        .any(|window| method_number(window[0]) >= method_number(window[1]))
    {
        return Err(ProtocolValidationError::InvalidField(field));
    }
    Ok(())
}

const fn method_number(method: BrokerMethod) -> i32 {
    method as i32
}

fn ensure_method_subset(
    required: &[BrokerMethod],
    advertised: &[BrokerMethod],
) -> Result<(), ProtocolValidationError> {
    if required
        .iter()
        .any(|required| !advertised.contains(required))
    {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    Ok(())
}

fn ensure_feature_subset(
    required: &[FeatureRef],
    advertised: &[FeatureRef],
) -> Result<(), ProtocolValidationError> {
    for required in required {
        if advertised.binary_search(required).is_err() {
            return Err(ProtocolValidationError::RequiredFeatureUnavailable(
                required.namespace().to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_broker_error(
    error: &BrokerError,
) -> Result<ValidatedBrokerError, ProtocolValidationError> {
    if !error.__buffa_unknown_fields.is_empty()
        || error.safe_message.is_empty()
        || error.safe_message.len() > MAXIMUM_SAFE_ERROR_MESSAGE_BYTES
        || error.safe_message.chars().any(char::is_control)
    {
        return Err(ProtocolValidationError::InvalidBrokerError);
    }
    let code = error
        .code
        .as_known()
        .filter(|code| *code != BrokerErrorCode::BROKER_ERROR_CODE_UNSPECIFIED)
        .ok_or(ProtocolValidationError::InvalidBrokerError)?;
    let missing_feature = error
        .missing_feature
        .as_option()
        .map(validate_error_feature)
        .transpose()?;
    if (code == BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE)
        != missing_feature.is_some()
    {
        return Err(ProtocolValidationError::InvalidBrokerError);
    }
    Ok(ValidatedBrokerError {
        code,
        safe_message: error.safe_message.clone(),
        retryable: error.retryable,
        missing_feature,
    })
}

fn validate_error_feature(
    feature: &aos_proto::aos::sandbox::local::v1::Feature,
) -> Result<FeatureRef, ProtocolValidationError> {
    if !feature.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::InvalidBrokerError);
    }
    FeatureRef::new(feature.namespace.clone(), feature.major, feature.minor)
        .map_err(|_| ProtocolValidationError::InvalidBrokerError)
}

fn validate_descriptor_table(
    source: &[BrokerDescriptorEntry],
    ancillary_descriptor_count: usize,
) -> Result<Vec<ValidatedDescriptorEntry>, ProtocolValidationError> {
    if source.len() > MAXIMUM_PACKET_DESCRIPTORS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "envelope.descriptors",
            maximum: MAXIMUM_PACKET_DESCRIPTORS,
        });
    }
    if source.len() != ancillary_descriptor_count {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    let mut roles = Vec::with_capacity(source.len());
    let mut descriptors = Vec::with_capacity(source.len());
    for (index, entry) in source.iter().enumerate() {
        if !entry.__buffa_unknown_fields.is_empty() || usize::try_from(entry.index) != Ok(index) {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
        let role = entry
            .role
            .as_known()
            .filter(|role| *role != BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED)
            .ok_or(ProtocolValidationError::DescriptorTableMismatch)?;
        if roles.contains(&role) {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
        roles.push(role);
        descriptors.push(ValidatedDescriptorEntry { role });
    }
    Ok(descriptors)
}

fn validate_descriptor_dispositions(
    source: &[BrokerDescriptorDispositionEntry],
    request_descriptors: &[ValidatedDescriptorEntry],
) -> Result<Vec<ValidatedDescriptorDisposition>, ProtocolValidationError> {
    if source.len() != request_descriptors.len() {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    let mut dispositions = Vec::with_capacity(source.len());
    for (index, (entry, request)) in source.iter().zip(request_descriptors).enumerate() {
        let disposition = entry.disposition.as_known().filter(|value| {
            *value != BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_UNSPECIFIED
        });
        if !entry.__buffa_unknown_fields.is_empty()
            || usize::try_from(entry.request_index) != Ok(index)
            || entry.role.as_known() != Some(request.role)
            || disposition.is_none()
        {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
        dispositions.push(ValidatedDescriptorDisposition {
            role: request.role,
            disposition: disposition.ok_or(ProtocolValidationError::DescriptorTableMismatch)?,
        });
    }
    Ok(dispositions)
}

fn validate_canonical_feature_refs(features: &[FeatureRef]) -> Result<(), ProtocolValidationError> {
    if features.len() > MAXIMUM_REQUIRED_FEATURES {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "advertised_features",
            maximum: MAXIMUM_REQUIRED_FEATURES,
        });
    }
    if features.windows(2).any(|window| window[0] >= window[1]) {
        return Err(ProtocolValidationError::InvalidField("advertised_features"));
    }
    validate_required_features(features)?;
    Ok(())
}

fn proto_feature(feature: &FeatureRef) -> aos_proto::aos::sandbox::local::v1::Feature {
    aos_proto::aos::sandbox::local::v1::Feature {
        namespace: feature.namespace().to_owned(),
        major: feature.major(),
        minor: feature.minor(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::format::{
        descriptor_for_bytes, encode_broker_authorization_plan, encode_ownership_lease,
        encode_signature,
    };
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, Signature, SignatureBytes, SignaturePurpose, SignatureStatement,
        StableKeyId,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment, BrokerAudience,
        BrokerAuthorizationPlan, BrokerGrant, BrokerGrantTarget, BrokerVerb, DesiredGeneration,
        IncarnationId, LeaseAssignment, MediaType, NodeId, ObjectDescriptor, ObjectDigest,
        OwnershipLease, PortableMediaType, RevocationScopeId, SandboxId, TrustScopeId,
    };

    use super::*;

    fn feature(namespace: &str) -> FeatureRef {
        FeatureRef::new(namespace, 1, 0)
            .unwrap_or_else(|error| panic!("test feature is invalid: {error}"))
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn client_features() -> Vec<FeatureRef> {
        let mut features = vec![
            feature("aos.sandbox.enforcement.broker-ledger"),
            feature(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE),
        ];
        features.sort();
        features
    }

    #[test]
    fn payload_scope_requires_authority_new_carrier_and_exact_response_roles() {
        assert_scope_response_profile(
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE,
            2,
            &crate::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES,
        );
        assert_scope_response_profile(
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE,
            3,
            &crate::mount_scope::MOUNT_SCOPE_DESCRIPTOR_ROLES,
        );
    }

    fn assert_scope_response_profile(
        method: BrokerMethod,
        minimum_minor: u16,
        roles: &[BrokerDescriptorRole],
    ) {
        assert!(method_requires_authorization(method));
        assert!(!method_available_in_version(
            method,
            ProtocolVersion::new(1, minimum_minor - 1)
        ));
        assert!(method_available_in_version(
            method,
            ProtocolVersion::new(1, minimum_minor)
        ));

        let version = ProtocolVersion::new(1, minimum_minor);
        assert!(validate_negotiated_authorization_profile(version, &[], &[method]).is_err());
        assert!(
            validate_negotiated_authorization_profile(version, &client_features(), &[method])
                .is_ok()
        );

        let unauthenticated = ValidatedBrokerRequestEnvelope {
            method,
            body: vec![1],
            descriptors: vec![],
            authorization: None,
        };
        assert!(
            validate_authorization_profile(version, &client_features(), &unauthenticated).is_err()
        );
        assert!(
            validate_outbound_carriers(
                method,
                &crate::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES
            )
            .is_err()
        );

        let decode = |roles: &[BrokerDescriptorRole], error: bool| {
            let envelope = BrokerResponseEnvelope {
                request_id: vec![1; 16],
                method: method.into(),
                body: if error { vec![] } else { vec![1] },
                descriptors: descriptor_entries(roles).unwrap(),
                error: if error {
                    Some(BrokerError {
                        code: BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST.into(),
                        safe_message: "denied".to_owned(),
                        ..Default::default()
                    })
                } else {
                    None
                }
                .into(),
                ..Default::default()
            };

            decode_response_envelope(
                &envelope.encode_to_vec(),
                &[1; 16],
                method,
                &[],
                roles.len(),
                8192,
                8192,
            )
        };

        assert!(decode(roles, false).is_ok());
        assert!(decode(&[], false).is_err());
        assert!(decode(&roles[..1], false).is_err());
        assert!(decode(&[roles[1], roles[0]], false).is_err());
        assert!(decode(roles, true).is_err());
        assert!(decode(&[], true).is_ok());
    }

    #[test]
    fn root_mount_session_cannot_negotiate_controller_methods_or_transfer_request_fds() {
        let mount = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE;
        let controller = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE;

        assert!(validate_role_methods(Audience::AUDIENCE_ROOT_MOUNT, &[mount]).is_ok());
        assert!(validate_role_methods(Audience::AUDIENCE_NODE_CONTROLLER, &[mount]).is_err());
        assert!(validate_role_methods(Audience::AUDIENCE_ROOT_MOUNT, &[controller]).is_err());
        assert!(
            validate_role_methods(Audience::AUDIENCE_ROOT_MOUNT, &[mount, controller]).is_err()
        );
        assert!(validate_role_methods(Audience::AUDIENCE_ROOT_MOUNT, &[]).is_err());

        assert!(validate_outbound_carriers(mount, &[]).is_ok());
        for role in crate::mount_scope::MOUNT_SCOPE_DESCRIPTOR_ROLES {
            assert!(validate_outbound_carriers(mount, &[role]).is_err());
        }
    }

    fn client_hello() -> BrokerClientHello {
        let features = client_features();
        BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 1,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: features.iter().map(proto_feature).collect(),
            maximum_response_bytes: 8192,
            required_methods: vec![BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into()],
            ..Default::default()
        }
    }

    fn descriptor(kind: PortableMediaType, bytes: &[u8]) -> ObjectDescriptor {
        descriptor_for_bytes(
            MediaType::new(kind.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            bytes,
        )
    }

    fn key(name: &str, usage: KeyUsage, byte: u8) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            1,
            ObjectDigest::from_bytes([byte; 32]),
            usage,
        )
    }

    fn signature(
        subject: ObjectDescriptor,
        signer: KeyReference,
        purpose: SignaturePurpose,
        policy_byte: u8,
    ) -> Vec<u8> {
        let policy = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([policy_byte; 32]),
            1,
        );
        let statement = SignatureStatement::new(
            subject,
            TrustScopeId::from_bytes([21; 16]),
            signer,
            purpose,
            100,
            Some(200),
            policy,
        )
        .unwrap_or_else(|error| panic!("test signature statement failed: {error}"));
        encode_signature(&Signature::new(statement, SignatureBytes::new([22; 64])))
    }

    fn authorization_artifacts() -> BrokerAuthorizationArtifactsV1 {
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
        let authority = key("ownership-authority", KeyUsage::OwnershipLease, 6);
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            ProtocolVersion::new(1, 1),
            assignment,
            NodeId::from_bytes([7; 16]),
            authority.clone(),
            vec![
                BrokerGrant::new(
                    BrokerVerb::MountCreate,
                    BrokerGrantTarget::Assignment,
                    BrokerArgumentCommitment::for_canonical_bytes(b"mount create"),
                    4096,
                    0,
                )
                .unwrap_or_else(|error| panic!("test grant failed: {error}")),
            ],
            ObjectDigest::from_bytes([8; 32]),
            RevocationScopeId::from_bytes([9; 16]),
            100,
            200,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test plan failed: {error}"));
        let broker_plan = encode_broker_authorization_plan(&plan);
        let broker_plan_signature = signature(
            descriptor(PortableMediaType::BrokerAuthorizationPlan, &broker_plan),
            key("broker-controller", KeyUsage::BrokerAuthorization, 10),
            SignaturePurpose::BrokerAuthorization,
            11,
        );

        let lease = OwnershipLease::new(
            LeaseAssignment::new(
                assignment.sandbox(),
                assignment.incarnation(),
                assignment.epoch(),
                assignment.digest(),
            )
            .unwrap_or_else(|error| panic!("test lease assignment failed: {error}")),
            NodeId::from_bytes([7; 16]),
            1,
            100,
            200,
            10,
            [12; 16],
        )
        .unwrap_or_else(|error| panic!("test lease failed: {error}"));
        let ownership_lease = encode_ownership_lease(&lease);
        let ownership_lease_signature = signature(
            descriptor(PortableMediaType::OwnershipLease, &ownership_lease),
            authority,
            SignaturePurpose::OwnershipLease,
            13,
        );

        BrokerAuthorizationArtifactsV1 {
            broker_plan,
            broker_plan_signature,
            ownership_lease,
            ownership_lease_signature,
            ..Default::default()
        }
    }

    fn borrowed_artifacts(
        artifacts: &BrokerAuthorizationArtifactsV1,
    ) -> AuthorizationArtifactBytes<'_> {
        AuthorizationArtifactBytes {
            broker_plan: &artifacts.broker_plan,
            broker_plan_signature: &artifacts.broker_plan_signature,
            ownership_lease: &artifacts.ownership_lease,
            ownership_lease_signature: &artifacts.ownership_lease_signature,
        }
    }

    #[test]
    fn outbound_authorized_envelope_round_trips_exact_artifact_bytes() {
        let artifacts = authorization_artifacts();
        let roles = [
            BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE,
            BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT,
        ];
        let encoded = encode_authorized_request_envelope(
            ProtocolId::MountBroker,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            b"exact method body",
            &roles,
            borrowed_artifacts(&artifacts),
        )
        .unwrap_or_else(|error| panic!("outbound envelope failed: {error}"));
        let decoded = decode_request_envelope(&encoded, ProtocolId::MountBroker, roles.len())
            .unwrap_or_else(|error| panic!("outbound envelope did not round trip: {error}"));
        assert_eq!(decoded.method(), BrokerMethod::BROKER_METHOD_MOUNT_APPLY);
        assert_eq!(decoded.body(), b"exact method body");
        assert_eq!(
            decoded
                .descriptors()
                .iter()
                .map(|entry| entry.role())
                .collect::<Vec<_>>(),
            roles
        );
        let decoded_artifacts = decoded
            .authorization()
            .unwrap_or_else(|| panic!("round trip lost authorization artifacts"));
        assert_eq!(decoded_artifacts.broker_plan(), artifacts.broker_plan);
        assert_eq!(
            decoded_artifacts.broker_plan_signature(),
            artifacts.broker_plan_signature
        );
        assert_eq!(
            decoded_artifacts.ownership_lease(),
            artifacts.ownership_lease
        );
        assert_eq!(
            decoded_artifacts.ownership_lease_signature(),
            artifacts.ownership_lease_signature
        );
    }

    #[test]
    fn outbound_authorized_envelope_rejects_body_method_and_descriptor_boundaries() {
        let artifacts = authorization_artifacts();
        let encode = |protocol, method, body: &[u8], roles: &[BrokerDescriptorRole]| {
            encode_authorized_request_envelope(
                protocol,
                method,
                body,
                roles,
                borrowed_artifacts(&artifacts),
            )
        };

        assert_eq!(
            encode(
                ProtocolId::MountBroker,
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                &[],
                &[],
            ),
            Err(ProtocolValidationError::InvalidField("envelope.body"))
        );
        assert_eq!(
            encode(
                ProtocolId::MountBroker,
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                &vec![0; MAXIMUM_REQUEST_BYTES + 1],
                &[],
            ),
            Err(ProtocolValidationError::RequestTooLarge)
        );
        assert_eq!(
            encode(
                ProtocolId::HostBroker,
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                b"body",
                &[],
            ),
            Err(ProtocolValidationError::MethodMismatch)
        );
        assert_eq!(
            encode(
                ProtocolId::MountBroker,
                BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY,
                b"body",
                &[],
            ),
            Err(ProtocolValidationError::InvalidField(
                "envelope.authorization profile"
            ))
        );
        assert_eq!(
            encode(
                ProtocolId::MountBroker,
                BrokerMethod::BROKER_METHOD_UNSPECIFIED,
                b"body",
                &[],
            ),
            Err(ProtocolValidationError::UnknownAction)
        );

        let too_many = vec![
            BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT;
            MAXIMUM_PACKET_DESCRIPTORS + 1
        ];
        assert_eq!(
            encode(
                ProtocolId::MountBroker,
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                b"body",
                &too_many,
            ),
            Err(ProtocolValidationError::TooManyEntries {
                field: "envelope.descriptors",
                maximum: MAXIMUM_PACKET_DESCRIPTORS,
            })
        );
        assert_eq!(
            encode(
                ProtocolId::MountBroker,
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                b"body",
                &[
                    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT,
                    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT,
                ],
            ),
            Err(ProtocolValidationError::DescriptorTableMismatch)
        );
        assert_eq!(
            encode(
                ProtocolId::MountBroker,
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                b"body",
                &[BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED],
            ),
            Err(ProtocolValidationError::DescriptorTableMismatch)
        );
    }

    #[test]
    fn outbound_authorized_envelope_rejects_every_artifact_boundary() {
        let artifacts = authorization_artifacts();
        let valid = borrowed_artifacts(&artifacts);
        let encode = |authorization| {
            encode_authorized_request_envelope(
                ProtocolId::MountBroker,
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                b"body",
                &[],
                authorization,
            )
        };

        for empty in [
            AuthorizationArtifactBytes {
                broker_plan: &[],
                ..valid
            },
            AuthorizationArtifactBytes {
                broker_plan_signature: &[],
                ..valid
            },
            AuthorizationArtifactBytes {
                ownership_lease: &[],
                ..valid
            },
            AuthorizationArtifactBytes {
                ownership_lease_signature: &[],
                ..valid
            },
        ] {
            assert_eq!(
                encode(empty),
                Err(ProtocolValidationError::InvalidField(
                    "envelope.authorization"
                ))
            );
        }

        let oversized_plan = vec![0; MAXIMUM_BROKER_PLAN_BYTES + 1];
        let oversized_signature = vec![0; MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES + 1];
        let oversized_lease = vec![0; MAXIMUM_OWNERSHIP_LEASE_BYTES + 1];
        for oversized in [
            AuthorizationArtifactBytes {
                broker_plan: &oversized_plan,
                ..valid
            },
            AuthorizationArtifactBytes {
                broker_plan_signature: &oversized_signature,
                ..valid
            },
            AuthorizationArtifactBytes {
                ownership_lease: &oversized_lease,
                ..valid
            },
            AuthorizationArtifactBytes {
                ownership_lease_signature: &oversized_signature,
                ..valid
            },
        ] {
            assert_eq!(
                encode(oversized),
                Err(ProtocolValidationError::InvalidField(
                    "envelope.authorization"
                ))
            );
        }

        // The aggregate ceiling is exactly the sum of the four individual
        // ceilings. Therefore its first impossible byte is necessarily also an
        // individual-bound violation, covered above.
        assert_eq!(
            MAXIMUM_AUTHORIZATION_ARTIFACT_BYTES,
            MAXIMUM_BROKER_PLAN_BYTES
                + MAXIMUM_OWNERSHIP_LEASE_BYTES
                + 2 * MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES
        );

        for (malformed, expected) in [
            (
                AuthorizationArtifactBytes {
                    broker_plan: &[0xff],
                    ..valid
                },
                "envelope.authorization.plan",
            ),
            (
                AuthorizationArtifactBytes {
                    broker_plan_signature: &[0xff],
                    ..valid
                },
                "envelope.authorization.plan_signature",
            ),
            (
                AuthorizationArtifactBytes {
                    ownership_lease: &[0xff],
                    ..valid
                },
                "envelope.authorization.lease",
            ),
            (
                AuthorizationArtifactBytes {
                    ownership_lease_signature: &[0xff],
                    ..valid
                },
                "envelope.authorization.lease_signature",
            ),
        ] {
            assert_eq!(
                encode(malformed),
                Err(ProtocolValidationError::InvalidField(expected))
            );
        }
    }

    #[test]
    fn outbound_authorized_envelope_enforces_the_encoded_packet_boundary() {
        let artifacts = authorization_artifacts();
        let encode_body = |size| {
            let body = vec![0; size];
            encode_authorized_request_envelope(
                ProtocolId::MountBroker,
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                &body,
                &[],
                borrowed_artifacts(&artifacts),
            )
        };
        let mut low = 1;
        let mut high = MAXIMUM_REQUEST_BYTES;
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if encode_body(middle).is_ok() {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        let largest_body = low;
        let packet = encode_body(largest_body)
            .unwrap_or_else(|error| panic!("largest bounded packet failed: {error}"));
        assert!(packet.len() <= MAXIMUM_REQUEST_BYTES);
        assert!(largest_body < MAXIMUM_REQUEST_BYTES);
        assert_eq!(
            encode_body(largest_body + 1),
            Err(ProtocolValidationError::RequestTooLarge)
        );
    }

    #[test]
    fn host_query_adds_bounded_headroom_without_narrowing_apply() {
        use aos_proto::aos::sandbox::local::v1::{QueryRuntimeEffectRequest, RequestHeader};

        let artifacts = authorization_artifacts();
        let encode_body = |size| {
            let body = vec![0; size];
            encode_authorized_request_envelope(
                ProtocolId::HostBroker,
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                &body,
                &[],
                borrowed_artifacts(&artifacts),
            )
        };
        let mut low = 1;
        let mut high = MAXIMUM_REQUEST_BYTES;
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if encode_body(middle).is_ok() {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        let largest_body = low;
        let apply_packet = encode_body(largest_body).unwrap();
        assert!(apply_packet.len() <= MAXIMUM_REQUEST_BYTES);
        assert_eq!(
            encode_body(largest_body + 1),
            Err(ProtocolValidationError::RequestTooLarge)
        );
        assert!(decode_request_envelope(&apply_packet, ProtocolId::HostBroker, 0).is_ok());
        let oversized_apply = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME.into(),
            body: vec![0; largest_body + 1],
            authorization: Some(artifacts.clone()).into(),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(
            decode_request_envelope(&oversized_apply, ProtocolId::HostBroker, 0),
            Err(ProtocolValidationError::RequestTooLarge)
        );

        let query_body = QueryRuntimeEffectRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 2,
                request_id: vec![0xff; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: u64::MAX,
                maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
                ..Default::default()
            })
            .into(),
            original_apply_request: vec![0; largest_body],
            ..Default::default()
        }
        .encode_to_vec();
        let query_packet = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT.into(),
            body: query_body,
            authorization: Some(artifacts).into(),
            ..Default::default()
        }
        .encode_to_vec();
        assert!(query_packet.len() <= MAXIMUM_HOST_QUERY_PACKET_BYTES);
        assert!(query_packet.len() - apply_packet.len() <= HOST_QUERY_WRAPPER_OVERHEAD_BYTES);
    }

    #[test]
    fn protocol_1_1_effects_require_exact_untrusted_authorization_artifacts() {
        let mut features = vec![
            feature(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE),
            feature("aos.sandbox.enforcement.broker-ledger"),
        ];
        features.sort();
        let methods = [
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY,
        ];
        let hello = BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 1,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: features.iter().map(proto_feature).collect(),
            maximum_response_bytes: 8192,
            required_methods: methods.iter().copied().map(Into::into).collect(),
            ..Default::default()
        };
        let session = negotiate_client_hello(
            &hello.encode_to_vec(),
            peer(),
            policy(),
            ProtocolId::MountBroker,
            &features,
            &methods,
        )
        .unwrap_or_else(|error| panic!("valid 1.1 hello failed: {error}"));

        let artifacts = authorization_artifacts();
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
            body: vec![1],
            authorization: Some(artifacts.clone()).into(),
            ..Default::default()
        };
        let request = session
            .decode_request(&envelope.encode_to_vec(), 0)
            .unwrap_or_else(|error| panic!("valid authorized request failed: {error}"));
        let preserved = request
            .authorization()
            .unwrap_or_else(|| panic!("authorization artifacts missing"));
        assert_eq!(preserved.broker_plan(), artifacts.broker_plan);
        assert_eq!(
            preserved.ownership_lease_signature(),
            artifacts.ownership_lease_signature
        );

        let missing = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
            body: vec![1],
            ..Default::default()
        };
        assert!(matches!(
            session.decode_request(&missing.encode_to_vec(), 0),
            Err(ProtocolValidationError::InvalidField(
                "envelope.authorization profile"
            ))
        ));

        let inventory = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY.into(),
            body: vec![1],
            ..Default::default()
        };
        session
            .decode_request(&inventory.encode_to_vec(), 0)
            .unwrap_or_else(|error| panic!("inventory must not require authority: {error}"));
    }

    #[test]
    fn authorization_carrier_rejects_noncanonical_and_legacy_smuggling() {
        let mut artifacts = authorization_artifacts();
        artifacts.broker_plan.push(0);
        let malformed = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
            body: vec![1],
            authorization: Some(artifacts).into(),
            ..Default::default()
        };
        assert!(matches!(
            decode_request_envelope(&malformed.encode_to_vec(), ProtocolId::MountBroker, 0),
            Err(ProtocolValidationError::InvalidField(
                "envelope.authorization.plan"
            ))
        ));

        let features = [feature("aos.sandbox.enforcement.broker-ledger")];
        let methods = [BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY];
        let legacy_hello = BrokerClientHello {
            protocol_major: 1,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: features.iter().map(proto_feature).collect(),
            maximum_response_bytes: 8192,
            required_methods: methods.iter().copied().map(Into::into).collect(),
            ..Default::default()
        };
        let session = negotiate_client_hello(
            &legacy_hello.encode_to_vec(),
            peer(),
            policy(),
            ProtocolId::MountBroker,
            &features,
            &methods,
        )
        .unwrap_or_else(|error| panic!("valid legacy hello failed: {error}"));
        let smuggled = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY.into(),
            body: vec![1],
            authorization: Some(authorization_artifacts()).into(),
            ..Default::default()
        };
        assert_eq!(
            session.decode_request(&smuggled.encode_to_vec(), 0),
            Err(ProtocolValidationError::InvalidField(
                "envelope.authorization profile"
            ))
        );
    }

    #[test]
    fn current_host_observation_methods_reject_authorization_carriers() {
        let features = [feature(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE)];
        let methods = [
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
        ];
        let hello = BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 1,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            maximum_response_bytes: 8_192,
            required_methods: methods.iter().copied().map(Into::into).collect(),
            ..Default::default()
        };
        let session = negotiate_client_hello(
            &hello.encode_to_vec(),
            peer(),
            policy(),
            ProtocolId::HostBroker,
            &features,
            &methods,
        )
        .unwrap_or_else(|error| panic!("valid host observation hello failed: {error}"));

        for method in methods {
            let smuggled = BrokerRequestEnvelope {
                method: method.into(),
                body: vec![1],
                authorization: Some(authorization_artifacts()).into(),
                ..Default::default()
            };
            assert_eq!(
                session.decode_request(&smuggled.encode_to_vec(), 0),
                Err(ProtocolValidationError::InvalidField(
                    "envelope.authorization profile"
                ))
            );
        }
    }

    #[test]
    fn inventory_only_negotiation_cannot_smuggle_a_later_effect() {
        let features = [feature("aos.sandbox.enforcement.broker-ledger")];
        let methods = [
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY,
        ];
        let hello = BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 1,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: features.iter().map(proto_feature).collect(),
            maximum_response_bytes: 8192,
            required_methods: vec![BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY.into()],
            ..Default::default()
        };
        let session = negotiate_client_hello(
            &hello.encode_to_vec(),
            peer(),
            policy(),
            ProtocolId::MountBroker,
            &features,
            &methods,
        )
        .unwrap_or_else(|error| panic!("valid inventory-only hello failed: {error}"));
        let effect = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
            body: vec![1],
            authorization: Some(authorization_artifacts()).into(),
            ..Default::default()
        };
        assert_eq!(
            session.decode_request(&effect.encode_to_vec(), 0),
            Err(ProtocolValidationError::RequiredFeatureUnavailable(
                SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned()
            ))
        );

        let legacy_effect = BrokerClientHello {
            protocol_major: 1,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: features.iter().map(proto_feature).collect(),
            maximum_response_bytes: 8192,
            required_methods: vec![BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into()],
            ..Default::default()
        };
        assert_eq!(
            negotiate_client_hello(
                &legacy_effect.encode_to_vec(),
                peer(),
                policy(),
                ProtocolId::MountBroker,
                &features,
                &methods,
            ),
            Err(ProtocolValidationError::RequiredFeatureUnavailable(
                SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned()
            ))
        );
    }

    #[test]
    fn hello_round_trip_negotiates_exact_capabilities() {
        let features = client_features();
        let methods = [
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY,
        ];
        let session = negotiate_client_hello(
            &client_hello().encode_to_vec(),
            peer(),
            policy(),
            ProtocolId::MountBroker,
            &features,
            &methods,
        )
        .unwrap_or_else(|error| panic!("valid client hello failed: {error}"));
        let decoded = decode_server_hello(
            &session.server_hello().encode_to_vec(),
            ProtocolId::MountBroker,
            Audience::AUDIENCE_NODE_CONTROLLER,
            ProtocolVersion::new(1, 1),
            session.required_features(),
            session.required_methods(),
            8192,
        )
        .unwrap_or_else(|error| panic!("valid server hello failed: {error}"));
        assert_eq!(decoded.advertised_methods(), methods);
        assert_eq!(decoded.maximum_response_bytes(), 8192);
    }

    #[test]
    fn hello_rejects_cross_protocol_and_noncanonical_methods() {
        let features = client_features();
        let methods = [BrokerMethod::BROKER_METHOD_MOUNT_APPLY];
        let mut hello = client_hello();
        hello.required_methods = vec![BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME.into()];
        assert_eq!(
            negotiate_client_hello(
                &hello.encode_to_vec(),
                peer(),
                policy(),
                ProtocolId::MountBroker,
                &features,
                &methods,
            ),
            Err(ProtocolValidationError::MethodMismatch)
        );

        let mut server = BrokerServerHello {
            protocol_major: 1,
            protocol_minor: 1,
            maximum_request_bytes: 4096,
            maximum_response_bytes: 4096,
            features: features.iter().map(proto_feature).collect(),
            methods: vec![
                BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY.into(),
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
            ],
            ..Default::default()
        };
        assert!(matches!(
            decode_server_hello(
                &server.encode_to_vec(),
                ProtocolId::MountBroker,
                Audience::AUDIENCE_NODE_CONTROLLER,
                ProtocolVersion::new(1, 1),
                &features,
                &methods,
                4096,
            ),
            Err(ProtocolValidationError::InvalidField(
                "server_hello.methods"
            ))
        ));
        server.maximum_response_bytes = 8192;
        assert_eq!(
            decode_server_hello(
                &server.encode_to_vec(),
                ProtocolId::MountBroker,
                Audience::AUDIENCE_NODE_CONTROLLER,
                ProtocolVersion::new(1, 1),
                &features,
                &methods,
                4096,
            ),
            Err(ProtocolValidationError::InvalidResponseBound)
        );
    }

    #[test]
    fn request_roles_have_structural_and_method_specific_checks() {
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
            body: vec![1],
            descriptors: vec![
                BrokerDescriptorEntry {
                    role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE
                        .into(),
                    ..Default::default()
                },
                BrokerDescriptorEntry {
                    index: 1,
                    role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT.into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let request =
            decode_request_envelope(&envelope.encode_to_vec(), ProtocolId::MountBroker, 2)
                .unwrap_or_else(|error| panic!("valid envelope failed: {error}"));
        validate_request_descriptor_roles(
            &request,
            &[
                BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE,
                BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT,
            ],
        )
        .unwrap_or_else(|error| panic!("valid role sequence failed: {error}"));
        assert_eq!(
            validate_request_descriptor_roles(
                &request,
                &[BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT],
            ),
            Err(ProtocolValidationError::DescriptorTableMismatch)
        );
    }

    #[test]
    fn session_rejects_a_registered_but_unadvertised_method() {
        let features = client_features();
        let methods = [BrokerMethod::BROKER_METHOD_MOUNT_APPLY];
        let session = negotiate_client_hello(
            &client_hello().encode_to_vec(),
            peer(),
            policy(),
            ProtocolId::MountBroker,
            &features,
            &methods,
        )
        .unwrap_or_else(|error| panic!("valid client hello failed: {error}"));
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY.into(),
            body: vec![1],
            ..Default::default()
        };
        assert_eq!(
            session.decode_request(&envelope.encode_to_vec(), 0),
            Err(ProtocolValidationError::MethodMismatch)
        );
    }

    #[test]
    fn response_builders_enforce_ownership_and_packet_ceiling() {
        let request_id = [9; 16];
        let request = decode_request_envelope(
            &BrokerRequestEnvelope {
                method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
                body: vec![1],
                descriptors: vec![BrokerDescriptorEntry {
                    role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
            ProtocolId::MountBroker,
            1,
        )
        .unwrap_or_else(|error| panic!("valid envelope failed: {error}"));
        let dispositions = [BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED];
        let encoded = encode_success_response_envelope(
            &request_id,
            &request,
            vec![1],
            &[],
            &dispositions,
            4096,
        )
        .unwrap_or_else(|error| panic!("valid response failed: {error}"));
        assert!(encoded.len() < 4096);
        assert_eq!(
            encode_success_response_envelope(&request_id, &request, vec![1], &[], &[], 4096,),
            Err(ProtocolValidationError::DescriptorTableMismatch)
        );

        let error = failed_server_hello(
            BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
            "backend failed",
            true,
            None,
        )
        .unwrap_or_else(|failure| panic!("valid failed hello failed: {failure}"));
        validate_failed_server_hello(&error)
            .unwrap_or_else(|failure| panic!("failed hello shape failed: {failure}"));
    }

    #[test]
    fn empty_success_body_is_canonical_only_for_explicit_empty_inventories() {
        let request_id = [9; 16];
        let inventory = decode_request_envelope(
            &BrokerRequestEnvelope {
                method: BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME.into(),
                body: vec![1],
                ..Default::default()
            }
            .encode_to_vec(),
            ProtocolId::HostBroker,
            0,
        )
        .unwrap_or_else(|error| panic!("valid inventory envelope failed: {error}"));
        let encoded =
            encode_success_response_envelope(&request_id, &inventory, Vec::new(), &[], &[], 4_096)
                .unwrap_or_else(|error| panic!("empty inventory response failed: {error}"));
        let decoded = decode_response_envelope(
            &encoded,
            &request_id,
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            &[],
            0,
            4_096,
            4_096,
        )
        .unwrap_or_else(|error| panic!("empty inventory response did not decode: {error}"));
        assert!(decoded.body().is_empty());

        for (protocol, method) in [
            (
                ProtocolId::StorageBroker,
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY,
            ),
            (
                ProtocolId::NetworkBroker,
                BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY,
            ),
        ] {
            let inventory = decode_request_envelope(
                &BrokerRequestEnvelope {
                    method: method.into(),
                    body: vec![1],
                    ..Default::default()
                }
                .encode_to_vec(),
                protocol,
                0,
            )
            .unwrap_or_else(|error| panic!("valid inventory envelope failed: {error}"));
            encode_success_response_envelope(&request_id, &inventory, Vec::new(), &[], &[], 4_096)
                .unwrap_or_else(|error| panic!("empty inventory response failed: {error}"));
        }

        let observe = decode_request_envelope(
            &BrokerRequestEnvelope {
                method: BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME.into(),
                body: vec![1],
                ..Default::default()
            }
            .encode_to_vec(),
            ProtocolId::HostBroker,
            0,
        )
        .unwrap_or_else(|error| panic!("valid observe envelope failed: {error}"));
        assert_eq!(
            encode_success_response_envelope(&request_id, &observe, Vec::new(), &[], &[], 4_096,),
            Err(ProtocolValidationError::InvalidField(
                "response body/error shape"
            ))
        );
    }

    #[test]
    fn response_requires_one_payload_and_exact_ownership() {
        let request_id = [9; 16];
        let request_descriptors = [ValidatedDescriptorEntry {
            role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT,
        }];
        let response = BrokerResponseEnvelope {
            request_id: request_id.to_vec(),
            method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
            body: vec![1],
            request_descriptor_dispositions: vec![BrokerDescriptorDispositionEntry {
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT.into(),
                disposition: BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED
                    .into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        decode_response_envelope(
            &response.encode_to_vec(),
            &request_id,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            &request_descriptors,
            0,
            8192,
            4096,
        )
        .unwrap_or_else(|error| panic!("valid response failed: {error}"));

        let mut empty = response;
        empty.body.clear();
        assert!(matches!(
            decode_response_envelope(
                &empty.encode_to_vec(),
                &request_id,
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                &request_descriptors,
                0,
                8192,
                4096,
            ),
            Err(ProtocolValidationError::InvalidField(
                "response body/error shape"
            ))
        ));
    }

    #[test]
    fn broker_errors_are_closed_bounded_and_feature_specific() {
        let mut response = BrokerResponseEnvelope {
            request_id: vec![9; 16],
            method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
            ..Default::default()
        };
        let error = response.error.get_or_insert_default();
        error.code = BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE.into();
        assert_eq!(
            decode_response_envelope(
                &response.encode_to_vec(),
                &[9; 16],
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                &[],
                0,
                4096,
                4096,
            ),
            Err(ProtocolValidationError::InvalidBrokerError)
        );
        let error = response.error.get_or_insert_default();
        error.safe_message = "failed".to_owned();
        error.missing_feature.get_or_insert_default().namespace = "aos.future".to_owned();
        assert_eq!(
            decode_response_envelope(
                &response.encode_to_vec(),
                &[9; 16],
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                &[],
                0,
                4096,
                4096,
            ),
            Err(ProtocolValidationError::InvalidBrokerError)
        );

        let error = response.error.get_or_insert_default();
        error.missing_feature = buffa::MessageField::default();
        error.safe_message = "forged\nlog line".to_owned();
        assert_eq!(
            decode_response_envelope(
                &response.encode_to_vec(),
                &[9; 16],
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                &[],
                0,
                4096,
                4096,
            ),
            Err(ProtocolValidationError::InvalidBrokerError)
        );
    }

    #[test]
    fn storage_and_network_methods_are_domain_separated_and_authority_bearing() {
        let artifacts = authorization_artifacts();
        for (protocol, apply, inventory) in [
            (
                ProtocolId::StorageBroker,
                BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY,
            ),
            (
                ProtocolId::NetworkBroker,
                BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
                BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY,
            ),
        ] {
            let packet = encode_authorized_request_envelope(
                protocol,
                apply,
                b"typed body",
                &[],
                borrowed_artifacts(&artifacts),
            )
            .unwrap_or_else(|error| panic!("effect encode failed: {error}"));
            assert_eq!(
                decode_request_envelope(&packet, protocol, 0)
                    .unwrap_or_else(|error| panic!("effect decode failed: {error}"))
                    .method(),
                apply
            );
            let wrong_protocol = if protocol == ProtocolId::StorageBroker {
                ProtocolId::NetworkBroker
            } else {
                ProtocolId::StorageBroker
            };
            assert_eq!(
                decode_request_envelope(&packet, wrong_protocol, 0),
                Err(ProtocolValidationError::MethodMismatch)
            );
            assert_eq!(
                encode_authorized_request_envelope(
                    protocol,
                    inventory,
                    b"inventory",
                    &[],
                    borrowed_artifacts(&artifacts),
                ),
                Err(ProtocolValidationError::InvalidField(
                    "envelope.authorization profile"
                ))
            );
        }
    }

    #[test]
    fn host_query_is_available_only_in_protocol_1_2_and_requires_authorization() {
        use aos_proto::aos::sandbox::local::v1::RuntimeEffectStatus;

        assert_eq!(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_ABSENT as i32, 1);
        assert_eq!(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_PENDING as i32, 2);
        assert_eq!(
            RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE as i32,
            3
        );
        let features = client_features();
        let methods = [
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
            BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
        ];
        let hello = BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 2,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: features.iter().map(proto_feature).collect(),
            maximum_response_bytes: 8192,
            required_methods: vec![BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT.into()],
            ..Default::default()
        };
        let session = negotiate_client_hello(
            &hello.encode_to_vec(),
            peer(),
            policy(),
            ProtocolId::HostBroker,
            &features,
            &methods,
        )
        .unwrap_or_else(|error| panic!("valid host 1.2 query hello failed: {error}"));
        assert_eq!(session.version(), ProtocolVersion::new(1, 2));
        assert_eq!(
            session.maximum_request_bytes(),
            MAXIMUM_HOST_QUERY_PACKET_BYTES
        );

        let unauthorized = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT.into(),
            body: vec![1],
            ..Default::default()
        };
        assert!(matches!(
            session.decode_request(&unauthorized.encode_to_vec(), 0),
            Err(ProtocolValidationError::InvalidField(
                "envelope.authorization profile"
            ))
        ));
        let authorized = BrokerRequestEnvelope {
            authorization: Some(authorization_artifacts()).into(),
            ..unauthorized
        };
        assert!(
            session
                .decode_request(&authorized.encode_to_vec(), 0)
                .is_ok()
        );
        assert!(
            session
                .decode_request(&authorized.encode_to_vec(), 1)
                .is_err()
        );

        let mut legacy = hello;
        legacy.protocol_minor = 1;
        assert_eq!(
            negotiate_client_hello(
                &legacy.encode_to_vec(),
                peer(),
                policy(),
                ProtocolId::HostBroker,
                &features,
                &methods,
            ),
            Err(ProtocolValidationError::MethodMismatch)
        );

        legacy.required_methods = vec![BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME.into()];
        let legacy_session = negotiate_client_hello(
            &legacy.encode_to_vec(),
            peer(),
            policy(),
            ProtocolId::HostBroker,
            &features,
            &methods,
        )
        .unwrap_or_else(|error| panic!("valid host 1.1 hello failed: {error}"));
        assert_eq!(
            legacy_session.advertised_methods(),
            [BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME]
        );
        assert_eq!(
            legacy_session.maximum_request_bytes(),
            MAXIMUM_REQUEST_BYTES
        );
        let mut invalid_server = legacy_session.server_hello();
        invalid_server
            .methods
            .push(BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT.into());
        assert_eq!(
            decode_server_hello(
                &invalid_server.encode_to_vec(),
                ProtocolId::HostBroker,
                Audience::AUDIENCE_NODE_CONTROLLER,
                ProtocolVersion::new(1, 1),
                legacy_session.required_features(),
                legacy_session.required_methods(),
                8192,
            ),
            Err(ProtocolValidationError::MethodMismatch)
        );
        let mut invalid_bound = legacy_session.server_hello();
        invalid_bound.maximum_request_bytes =
            u32::try_from(MAXIMUM_HOST_QUERY_PACKET_BYTES).unwrap();
        assert_eq!(
            decode_server_hello(
                &invalid_bound.encode_to_vec(),
                ProtocolId::HostBroker,
                Audience::AUDIENCE_NODE_CONTROLLER,
                ProtocolVersion::new(1, 1),
                legacy_session.required_features(),
                legacy_session.required_methods(),
                8192,
            ),
            Err(ProtocolValidationError::InvalidResponseBound)
        );
    }

    #[test]
    fn storage_and_network_reject_descriptor_carriers_and_cross_role_sessions() {
        let artifacts = authorization_artifacts();
        for (protocol, method) in [
            (
                ProtocolId::StorageBroker,
                BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            ),
            (
                ProtocolId::NetworkBroker,
                BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            ),
        ] {
            assert_eq!(
                encode_authorized_request_envelope(
                    protocol,
                    method,
                    b"typed body",
                    &[BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT],
                    borrowed_artifacts(&artifacts),
                ),
                Err(ProtocolValidationError::DescriptorTableMismatch)
            );

            let features = client_features();
            let hello = BrokerClientHello {
                protocol_major: 1,
                protocol_minor: 1,
                audience: Audience::AUDIENCE_MOUNT_WORKER.into(),
                required_features: features.iter().map(proto_feature).collect(),
                maximum_response_bytes: 8192,
                required_methods: vec![method.into()],
                ..Default::default()
            };
            let wrong_role_policy = PeerPolicy {
                audience: Audience::AUDIENCE_MOUNT_WORKER,
                ..policy()
            };
            assert_eq!(
                negotiate_client_hello(
                    &hello.encode_to_vec(),
                    peer(),
                    wrong_role_policy,
                    protocol,
                    &features,
                    &[method],
                ),
                Err(ProtocolValidationError::MethodMismatch)
            );
        }
    }
}

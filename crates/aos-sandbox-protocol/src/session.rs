//! Negotiated node-local broker sessions and packet envelopes.
//!
//! A connection exchanges exactly one client hello and one server hello before
//! dispatch. Subsequent sequence packets use a closed method tag, a bounded
//! protobuf body, and an exact table describing ancillary descriptors. Packet
//! parsing validates table structure; each method dispatcher separately checks
//! its exact role sequence before using any descriptor.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerDescriptorDisposition, BrokerDescriptorDispositionEntry,
    BrokerDescriptorEntry, BrokerDescriptorRole, BrokerError, BrokerErrorCode, BrokerMethod,
    BrokerRequestEnvelope, BrokerResponseEnvelope, BrokerServerHello,
};
use aos_sandbox_core::{
    FeatureRef, ProtocolId, ProtocolVersion, RegistryError, negotiate_protocol,
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

    /// Builds the sole successful server handshake packet.
    #[must_use]
    pub fn server_hello(&self) -> BrokerServerHello {
        BrokerServerHello {
            protocol_major: u32::from(self.version.major()),
            protocol_minor: u32::from(self.version.minor()),
            features: self.advertised_features.iter().map(proto_feature).collect(),
            maximum_request_bytes: u32::try_from(MAXIMUM_REQUEST_BYTES).unwrap_or(u32::MAX),
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
        if !self.advertised_methods.contains(&request.method) {
            return Err(ProtocolValidationError::MethodMismatch);
        }
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
    let required_features =
        validate_feature_set(&hello.required_features, "hello.required_features")?;
    ensure_feature_subset(&required_features, advertised_features)?;
    let required_methods =
        validate_proto_methods(&hello.required_methods, protocol, "hello.required_methods")?;
    ensure_method_subset(&required_methods, advertised_methods)?;

    Ok(NegotiatedBrokerSession {
        protocol,
        version,
        audience: policy.audience,
        required_features,
        advertised_features: advertised_features.to_vec(),
        required_methods,
        advertised_methods: advertised_methods.to_vec(),
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
    validate_server_bounds(&hello, offered_maximum_response_bytes)?;

    validate_canonical_feature_refs(required_features)?;
    let advertised_features = validate_feature_set(&hello.features, "server_hello.features")?;
    ensure_feature_subset(required_features, &advertised_features)?;
    validate_canonical_methods(required_methods, protocol, "required_methods")?;
    let advertised_methods =
        validate_proto_methods(&hello.methods, protocol, "server_hello.methods")?;
    ensure_method_subset(required_methods, &advertised_methods)?;

    Ok(NegotiatedBrokerSession {
        protocol,
        version: offered_version,
        audience,
        required_features: required_features.to_vec(),
        advertised_features,
        required_methods: required_methods.to_vec(),
        advertised_methods,
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
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let envelope = BrokerRequestEnvelope::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !envelope.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let method = validate_method(envelope.method.as_known(), protocol)?;
    if envelope.body.is_empty() {
        return Err(ProtocolValidationError::InvalidField("envelope.body"));
    }
    let descriptors = validate_descriptor_table(&envelope.descriptors, ancillary_descriptor_count)?;
    Ok(ValidatedBrokerRequestEnvelope {
        method,
        body: envelope.body,
        descriptors,
    })
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
    if body.is_empty() == error.is_none() {
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
    if envelope.body.is_empty() == envelope.error.as_option().is_none() {
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
    offered_maximum_response_bytes: u32,
) -> Result<(), ProtocolValidationError> {
    if hello.maximum_request_bytes == 0
        || usize::try_from(hello.maximum_request_bytes)
            .map_or(true, |maximum| maximum > MAXIMUM_REQUEST_BYTES)
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
        ) | (
            ProtocolId::MountBroker,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY
        )
    );
    if !valid {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    Ok(method)
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

    fn client_hello() -> BrokerClientHello {
        BrokerClientHello {
            protocol_major: 1,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: vec![proto_feature(&feature(
                "aos.sandbox.enforcement.broker-ledger",
            ))],
            maximum_response_bytes: 8192,
            required_methods: vec![BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into()],
            ..Default::default()
        }
    }

    #[test]
    fn hello_round_trip_negotiates_exact_capabilities() {
        let features = [feature("aos.sandbox.enforcement.broker-ledger")];
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
            ProtocolVersion::new(1, 0),
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
        let features = [feature("aos.sandbox.enforcement.broker-ledger")];
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
                ProtocolVersion::new(1, 0),
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
                ProtocolVersion::new(1, 0),
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
        let features = [feature("aos.sandbox.enforcement.broker-ledger")];
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
}

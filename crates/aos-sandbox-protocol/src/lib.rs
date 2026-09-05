//! Validates hostile node-local sandbox protocol messages.
//!
//! Unix transports obtain peer credentials from the accepted socket and pass
//! them here as values. This crate binds those credentials to a single broker
//! audience, rejects unknown protobuf fields and enums, applies message and
//! response bounds, validates assignment fences, and resolves portable
//! descriptors through the closed role registry before privileged code sees a
//! request. [`semantics`] contains pure portable authority compilers;
//! [`fencing`], [`inventory`], and [`session`] own their respective validated
//! protocol state and envelopes.

pub mod fencing;
pub mod inventory;
pub mod mount_catalog;
pub mod mount_scope;
pub mod payload_scope;
pub mod semantics;
pub mod session;

pub use inventory::{
    MAXIMUM_MOUNT_INVENTORY_RECORDS, ValidatedMountAssignmentBinding,
    ValidatedMountFaultCorrelation, ValidatedMountInventory, ValidatedMountInventoryRecord,
    ValidatedMountKernelObservation, ValidatedMountOperationCorrelation,
    ValidatedMountPublicationCorrelation, ValidatedMountRecipe, decode_mount_inventory_request,
    decode_mount_inventory_response,
};

mod runtime_template;
pub use runtime_template::{ValidatedRuntimeTemplateV1, decode_runtime_template_v1};

pub use session::{
    AuthorizationArtifactBytes, MAXIMUM_HANDSHAKE_BYTES, MAXIMUM_PACKET_DESCRIPTORS,
    NegotiatedBrokerSession, ValidatedBrokerError, ValidatedBrokerRequestEnvelope,
    ValidatedBrokerResponseEnvelope, ValidatedDescriptorDisposition, ValidatedDescriptorEntry,
    ValidatedRuntimeEffectStatus, decode_query_runtime_effect_response, decode_request_envelope,
    decode_response_envelope, decode_server_hello, encode_authorized_request_envelope,
    encode_error_response_envelope, encode_success_response_envelope,
    encode_unauthed_request_envelope, failed_server_hello, negotiate_client_hello,
    validate_request_descriptor_roles, validate_runtime_effect_receipt_for_apply,
};

use aos_proto::aos::sandbox::local::v1::{
    ApplyGuardianRequest, ApplyGuestExecutionRequest, ApplyMountRequest, ApplyNetworkRequest,
    ApplyRuntimeRequest, ApplyStorageRequest, AssignmentFence, Audience, BrokerClientHello,
    BrokerErrorCode, BrokerRequestEnvelope, BrokerResponseEnvelope, Descriptor, MountAction,
    RequestHeader, RuntimeAction, RuntimePlan,
};
use aos_sandbox_core::{
    DescriptorRole, FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, ProtocolId,
    ProtocolVersion, RegistryError, negotiate_protocol, validate_descriptor_role,
    validate_required_features,
};
use buffa::Message as _;

/// Default maximum encoded local request accepted before protobuf decoding.
pub const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024;
/// Default maximum response allocation a request may ask a broker to produce.
pub const MAXIMUM_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;
/// Minimum response budget that can carry every fixed broker observation.
pub const MINIMUM_RESPONSE_BYTES: u32 = 4 * 1024;
const OPAQUE_HANDLE_BYTES: usize = 32;
const MAXIMUM_ATTACHMENTS: usize = 256;
const MAXIMUM_RESOURCE_LIMITS: usize = 16;
const MAXIMUM_REQUIRED_FEATURES: usize = 64;
/// Carries credentials obtained from the accepted Unix socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    /// Effective peer user ID reported by the kernel.
    pub uid: u32,
    /// Effective peer group ID reported by the kernel.
    pub gid: u32,
    /// Peer process ID reported by the kernel, used only for audit correlation.
    pub pid: Option<u32>,
}

/// Defines the single identity and audience accepted by one broker socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerPolicy {
    /// Required peer user ID.
    pub uid: u32,
    /// Required peer group ID, when the socket contract binds both values.
    pub gid: Option<u32>,
    /// Sole protocol audience served by this socket.
    pub audience: Audience,
}

/// Carries an accepted request header after peer and bound validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHeader {
    protocol_version: ProtocolVersion,
    audience: Audience,
    request_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    maximum_response_bytes: u32,
}

impl ValidatedHeader {
    /// Returns the exact protocol version carried by the request body.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the exact audience carried by the request body.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }

    /// Returns the nonzero request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Returns the absolute `CLOCK_BOOTTIME` request deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the admitted response-byte ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }
}

/// Carries a complete assignment fence after fixed-width and monotonic checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedAssignmentFence {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
}

impl ValidatedAssignmentFence {
    /// Returns the logical sandbox identifier.
    #[must_use]
    pub const fn sandbox_id(&self) -> &[u8; 16] {
        &self.sandbox_id
    }

    /// Returns the runtime incarnation identifier.
    #[must_use]
    pub const fn incarnation_id(&self) -> &[u8; 16] {
        &self.incarnation_id
    }

    /// Returns the monotonically increasing assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }

    /// Returns the desired-state generation within the assignment.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.desired_generation
    }

    /// Returns the digest of immutable assignment semantics.
    #[must_use]
    pub const fn assignment_digest(&self) -> &[u8; 32] {
        &self.assignment_digest
    }
}

/// Carries one canonical closed-dimension resource limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedResourceLimit {
    dimension: u8,
    value: u64,
}

impl ValidatedResourceLimit {
    /// Returns the registered portable resource dimension in `0..=15`.
    #[must_use]
    pub const fn dimension(self) -> u8 {
        self.dimension
    }

    /// Returns the resolved finite limit value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }
}

/// Carries a launch plan after nested hostile-input validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRuntimePlan {
    root_image: ObjectDescriptor,
    workspace_handle: [u8; OPAQUE_HANDLE_BYTES],
    network_handle: [u8; OPAQUE_HANDLE_BYTES],
    uid_range_start: u32,
    uid_range_size: u32,
    limits: Vec<ValidatedResourceLimit>,
    attachment_handles: Vec<[u8; OPAQUE_HANDLE_BYTES]>,
    required_features: Vec<FeatureRef>,
}

impl ValidatedRuntimePlan {
    /// Returns the immutable root filesystem-view descriptor.
    #[must_use]
    pub const fn root_image(&self) -> &ObjectDescriptor {
        &self.root_image
    }

    /// Returns the broker-minted private workspace handle.
    #[must_use]
    pub const fn workspace_handle(&self) -> &[u8; OPAQUE_HANDLE_BYTES] {
        &self.workspace_handle
    }

    /// Returns the broker-minted prepared network handle.
    #[must_use]
    pub const fn network_handle(&self) -> &[u8; OPAQUE_HANDLE_BYTES] {
        &self.network_handle
    }

    /// Returns the first host UID in the private user-namespace allocation.
    #[must_use]
    pub const fn uid_range_start(&self) -> u32 {
        self.uid_range_start
    }

    /// Returns the number of IDs in the private user-namespace allocation.
    #[must_use]
    pub const fn uid_range_size(&self) -> u32 {
        self.uid_range_size
    }

    /// Returns resource limits in strict dimension order.
    #[must_use]
    pub fn limits(&self) -> &[ValidatedResourceLimit] {
        &self.limits
    }

    /// Returns the broker-minted attachment handles in canonical byte order.
    #[must_use]
    pub fn attachment_handles(&self) -> &[[u8; OPAQUE_HANDLE_BYTES]] {
        &self.attachment_handles
    }

    /// Returns the exact validated and registered required feature set.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
}

/// Carries a host-broker request only after all nested fields are validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRuntimeRequest {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    action: RuntimeAction,
    launch_plan: Option<ValidatedRuntimePlan>,
}

impl ValidatedRuntimeRequest {
    /// Returns the validated common header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the validated assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the closed runtime action.
    #[must_use]
    pub const fn action(&self) -> RuntimeAction {
        self.action
    }

    /// Returns the validated launch plan, present only for launch.
    #[must_use]
    pub const fn launch_plan(&self) -> Option<&ValidatedRuntimePlan> {
        self.launch_plan.as_ref()
    }
}

/// Carries a mount request only after all common and descriptor checks pass.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedMountRequest {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    action: MountAction,
    attachment_id: [u8; 16],
    destination_slot_id: [u8; 16],
    view_revision: Option<ObjectDescriptor>,
    detached_mount_handle: Option<[u8; 32]>,
    replacement_mount_handle: Option<[u8; 32]>,
    attributes: Option<ValidatedMountAttributes>,
    source_generation: u64,
    namespace_generation: u64,
}

impl ValidatedMountRequest {
    /// Returns the validated common header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the closed mount action.
    #[must_use]
    pub const fn action(&self) -> MountAction {
        self.action
    }

    /// Returns the attachment resource identifier.
    #[must_use]
    pub const fn attachment_id(&self) -> &[u8; 16] {
        &self.attachment_id
    }

    /// Returns the broker-owned destination-slot identifier.
    #[must_use]
    pub const fn destination_slot_id(&self) -> &[u8; 16] {
        &self.destination_slot_id
    }

    /// Returns the validated view descriptor when the action supplies one.
    #[must_use]
    pub const fn view_revision(&self) -> Option<&ObjectDescriptor> {
        self.view_revision.as_ref()
    }

    /// Returns the action-dependent detached or installed mount handle.
    #[must_use]
    pub const fn detached_mount_handle(&self) -> Option<&[u8; 32]> {
        self.detached_mount_handle.as_ref()
    }

    /// Returns the installed handle being replaced, only for replace.
    #[must_use]
    pub const fn replacement_mount_handle(&self) -> Option<&[u8; 32]> {
        self.replacement_mount_handle.as_ref()
    }

    /// Returns closed mount attributes for prepare/install operations.
    #[must_use]
    pub const fn attributes(&self) -> Option<ValidatedMountAttributes> {
        self.attributes
    }

    /// Returns the nonzero immutable source generation.
    #[must_use]
    pub const fn source_generation(&self) -> u64 {
        self.source_generation
    }

    /// Returns the nonzero payload mount-namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }
}

/// Carries a closed mount-attribute request after enum validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedMountAttributes {
    bits: u8,
    mutation_mode: u32,
}

impl ValidatedMountAttributes {
    const READ_ONLY: u8 = 1 << 0;
    const NO_EXEC: u8 = 1 << 1;
    const NO_SUID: u8 = 1 << 2;
    const NO_DEVICE: u8 = 1 << 3;
    const NO_ATIME: u8 = 1 << 4;

    /// Reports whether the mount is VFS read-only.
    #[must_use]
    pub const fn read_only(self) -> bool {
        self.bits & Self::READ_ONLY != 0
    }

    /// Reports whether execution through the mount is denied.
    #[must_use]
    pub const fn no_exec(self) -> bool {
        self.bits & Self::NO_EXEC != 0
    }

    /// Reports whether set-ID mode bits are ineffective.
    #[must_use]
    pub const fn no_suid(self) -> bool {
        self.bits & Self::NO_SUID != 0
    }

    /// Reports whether device nodes are ineffective.
    #[must_use]
    pub const fn no_device(self) -> bool {
        self.bits & Self::NO_DEVICE != 0
    }

    /// Reports whether access-time updates are disabled.
    #[must_use]
    pub const fn no_atime(self) -> bool {
        self.bits & Self::NO_ATIME != 0
    }

    /// Returns the closed view mutation mode `0..=4`.
    #[must_use]
    pub const fn mutation_mode(self) -> u32 {
        self.mutation_mode
    }
}

/// Reports a malformed or unauthorized local broker request.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolValidationError {
    /// The encoded request exceeds the broker's pre-decode byte ceiling.
    #[error("local request exceeds the maximum encoded byte length")]
    RequestTooLarge,
    /// Protobuf wire decoding failed before semantic validation.
    #[error("malformed local protobuf request: {0}")]
    MalformedWire(String),
    /// A required message field is absent.
    #[error("required local protocol field {0} is absent")]
    MissingField(&'static str),
    /// An ID or digest has another byte length or is the all-zero sentinel.
    #[error("local protocol field {field} is not an exact nonzero {bytes}-byte value")]
    InvalidFixedBytes {
        /// Field whose value failed validation.
        field: &'static str,
        /// Required byte length.
        bytes: usize,
    },
    /// The accepted socket peer does not match the fixed broker policy.
    #[error("Unix peer credentials do not match the broker socket policy")]
    PeerCredentialMismatch,
    /// The request targets another broker audience or an unknown enum value.
    #[error("local request audience is unknown or does not match the broker socket")]
    AudienceMismatch,
    /// The request protocol version cannot be negotiated by this broker.
    #[error("local protocol version is incompatible: {0}")]
    Protocol(#[from] RegistryError),
    /// The request deadline is absent or already expired.
    #[error("local request deadline is absent or expired")]
    DeadlineExpired,
    /// The response ceiling is zero or exceeds the broker bound.
    #[error("local request response-byte ceiling is invalid")]
    InvalidResponseBound,
    /// An encoded response exceeds the response-byte ceiling negotiated by the client.
    #[error("local response exceeds the negotiated encoded byte length")]
    ResponseTooLarge,
    /// An authority-bearing local message contains unregistered fields.
    #[error("authority-bearing local message contains unknown protobuf fields")]
    UnknownFields,
    /// A closed action is absent or unknown.
    #[error("local request action is unspecified or unknown")]
    UnknownAction,
    /// A closed observation lifecycle is absent or unknown.
    #[error("local response lifecycle is unspecified or unknown")]
    UnknownState,
    /// A field combination violates the selected closed operation contract.
    #[error("invalid local request field {0}")]
    InvalidField(&'static str),
    /// A bounded repeated field exceeds its fixed protocol ceiling.
    #[error("local request collection {field} exceeds {maximum} entries")]
    TooManyEntries {
        /// Repeated field whose count exceeded its ceiling.
        field: &'static str,
        /// Maximum accepted element count.
        maximum: usize,
    },
    /// A descriptor is malformed or appears in the wrong semantic role.
    #[error("invalid local descriptor: {0}")]
    InvalidDescriptor(String),
    /// The ancillary descriptor count or role table is not exact.
    #[error("local ancillary descriptor table does not match the packet")]
    DescriptorTableMismatch,
    /// The closed method is not part of the negotiated broker domain.
    #[error("local broker method is invalid for the negotiated protocol")]
    MethodMismatch,
    /// The peer requires a known feature this broker did not advertise.
    #[error("required local broker feature is unavailable: {0}")]
    RequiredFeatureUnavailable(String),
    /// A syntactically valid server hello rejected negotiation.
    #[error("local broker rejected negotiation with {0:?}")]
    BrokerRejected(BrokerErrorCode),
    /// A broker error violates its closed code, message, or feature contract.
    #[error("local broker error is malformed")]
    InvalidBrokerError,
}

/// Decodes and validates one host-broker runtime request from hostile bytes.
///
/// The returned value contains no caller-selected command, path, systemd
/// property, or untyped resource dimension. Launch handles remain opaque and
/// must be resolved through the host broker's trusted catalog.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for size/wire failures, unknown nested
/// fields or enums, peer/audience mismatch, stale deadlines, malformed fences,
/// noncanonical bounded collections, invalid descriptors, or a launch plan
/// whose presence does not exactly match the selected action.
pub fn decode_runtime_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedRuntimeRequest, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyRuntimeRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    let template = runtime_template::validate_runtime_body(&request)?;

    Ok(ValidatedRuntimeRequest {
        header,
        fence: template.fence,
        action: template.action,
        launch_plan: template.launch_plan,
    })
}

/// Decodes and validates one mount-broker request from hostile wire bytes.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for size/wire failures, unknown fields
/// or enums, peer/audience mismatch, stale deadline, invalid assignment fence,
/// or a view descriptor with an unregistered media type or role.
pub fn decode_mount_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedMountRequest, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyMountRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = request
        .header
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    let header = validate_request_header(
        header,
        peer,
        policy,
        ProtocolId::MountBroker,
        now_boottime_nanoseconds,
    )?;
    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let action = request
        .action
        .as_known()
        .filter(|action| *action != MountAction::MOUNT_ACTION_UNSPECIFIED)
        .ok_or(ProtocolValidationError::UnknownAction)?;
    let view_revision = match request.view_revision.as_option() {
        Some(descriptor) => Some(validate_descriptor(
            descriptor,
            DescriptorRole::FilesystemViewRevision,
        )?),
        None if matches!(
            action,
            MountAction::MOUNT_ACTION_CREATE_DETACHED
                | MountAction::MOUNT_ACTION_INSTALL
                | MountAction::MOUNT_ACTION_REPLACE
        ) =>
        {
            return Err(ProtocolValidationError::MissingField("view_revision"));
        }
        None => None,
    };

    let attachment_id = exact_nonzero::<16>(&request.attachment_id, "attachment_id")?;
    let destination_slot_id =
        exact_nonzero::<16>(&request.destination_slot_id, "destination_slot_id")?;
    if request.source_generation == 0 || request.namespace_generation == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "source or namespace generation",
        ));
    }
    let detached_mount_handle =
        optional_exact_nonzero::<32>(&request.detached_mount_handle, "detached_mount_handle")?;
    let replacement_mount_handle = optional_exact_nonzero::<32>(
        &request.replacement_mount_handle,
        "replacement_mount_handle",
    )?;
    let attributes = request
        .attributes
        .as_option()
        .map(validate_mount_attributes)
        .transpose()?;
    validate_mount_shape(
        action,
        view_revision.is_some(),
        detached_mount_handle,
        replacement_mount_handle,
        attributes,
    )?;

    Ok(ValidatedMountRequest {
        header,
        fence,
        action,
        attachment_id,
        destination_slot_id,
        view_revision,
        detached_mount_handle,
        replacement_mount_handle,
        attributes,
        source_generation: request.source_generation,
        namespace_generation: request.namespace_generation,
    })
}

pub(crate) fn validate_mount_attributes(
    attributes: &aos_proto::aos::sandbox::local::v1::MountAttributes,
) -> Result<ValidatedMountAttributes, ProtocolValidationError> {
    if !attributes.__buffa_unknown_fields.is_empty()
        || attributes.mutation_mode > 4
        || !attributes.no_suid
        || !attributes.no_device
        || attributes.read_only != (attributes.mutation_mode == 0)
    {
        return Err(ProtocolValidationError::InvalidField("attributes"));
    }
    let mut bits = 0;
    for (enabled, bit) in [
        (attributes.read_only, ValidatedMountAttributes::READ_ONLY),
        (attributes.no_exec, ValidatedMountAttributes::NO_EXEC),
        (attributes.no_suid, ValidatedMountAttributes::NO_SUID),
        (attributes.no_device, ValidatedMountAttributes::NO_DEVICE),
        (attributes.no_atime, ValidatedMountAttributes::NO_ATIME),
    ] {
        if enabled {
            bits |= bit;
        }
    }

    Ok(ValidatedMountAttributes {
        bits,
        mutation_mode: attributes.mutation_mode,
    })
}

fn validate_mount_shape(
    action: MountAction,
    has_view_revision: bool,
    detached: Option<[u8; 32]>,
    replacement: Option<[u8; 32]>,
    attributes: Option<ValidatedMountAttributes>,
) -> Result<(), ProtocolValidationError> {
    let valid = match action {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => {
            has_view_revision && detached.is_none() && replacement.is_none() && attributes.is_some()
        }
        MountAction::MOUNT_ACTION_INSTALL => {
            has_view_revision && detached.is_some() && replacement.is_none() && attributes.is_some()
        }
        MountAction::MOUNT_ACTION_REPLACE => {
            has_view_revision
                && detached.is_some()
                && replacement.is_some()
                && detached != replacement
                && attributes.is_some()
        }
        MountAction::MOUNT_ACTION_DETACH | MountAction::MOUNT_ACTION_RELEASE => {
            !has_view_revision
                && detached.is_some()
                && replacement.is_none()
                && attributes.is_none()
        }
        MountAction::MOUNT_ACTION_UNSPECIFIED => false,
    };
    if !valid {
        return Err(ProtocolValidationError::InvalidField(
            "mount action field shape",
        ));
    }
    Ok(())
}

/// Validates one broker header against kernel-supplied peer credentials.
///
/// Broker frontends call this immediately after bounded wire decoding and
/// before dispatching a fixed verb. The selected [`ProtocolId`] keeps local
/// compatibility domains independent.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for unknown fields, peer or audience
/// mismatch, incompatible versions, invalid request IDs, expired deadlines,
/// or response allocations outside the fixed bound.
pub fn validate_request_header(
    header: &RequestHeader,
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol: ProtocolId,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if !header.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    validate_peer_audience(peer, policy, header.audience.as_known())?;
    let protocol_version = validate_header_protocol(header, protocol)?;
    let request_id = exact_nonzero::<16>(&header.request_id, "header.request_id")?;
    if header.deadline_boottime_nanoseconds <= now_boottime_nanoseconds {
        return Err(ProtocolValidationError::DeadlineExpired);
    }
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&header.maximum_response_bytes) {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    Ok(ValidatedHeader {
        protocol_version,
        audience: policy.audience,
        request_id,
        deadline_boottime_nanoseconds: header.deadline_boottime_nanoseconds,
        maximum_response_bytes: header.maximum_response_bytes,
    })
}

fn validate_header_protocol(
    header: &RequestHeader,
    protocol: ProtocolId,
) -> Result<ProtocolVersion, ProtocolValidationError> {
    Ok(negotiate_protocol(
        protocol,
        ProtocolVersion::new(
            u16::try_from(header.protocol_major).map_err(|_| {
                RegistryError::IncompatibleProtocol {
                    protocol,
                    offered_major: u16::MAX,
                    offered_minor: u16::MAX,
                    local_major: 1,
                    local_minor: 0,
                }
            })?,
            u16::try_from(header.protocol_minor).map_err(|_| {
                RegistryError::IncompatibleProtocol {
                    protocol,
                    offered_major: u16::MAX,
                    offered_minor: u16::MAX,
                    local_major: 1,
                    local_minor: 0,
                }
            })?,
        ),
    )?)
}

pub(crate) fn validate_fence(
    fence: &AssignmentFence,
) -> Result<ValidatedAssignmentFence, ProtocolValidationError> {
    if !fence.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if fence.assignment_epoch == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "fence.assignment_epoch",
        ));
    }
    if fence.desired_generation == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "fence.desired_generation",
        ));
    }
    Ok(ValidatedAssignmentFence {
        sandbox_id: exact_nonzero::<16>(&fence.sandbox_id, "fence.sandbox_id")?,
        incarnation_id: exact_nonzero::<16>(&fence.incarnation_id, "fence.incarnation_id")?,
        assignment_epoch: fence.assignment_epoch,
        desired_generation: fence.desired_generation,
        assignment_digest: exact_nonzero::<32>(
            &fence.assignment_digest,
            "fence.assignment_digest",
        )?,
    })
}

fn validate_runtime_plan(
    plan: &RuntimePlan,
) -> Result<ValidatedRuntimePlan, ProtocolValidationError> {
    if !plan.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let root_image = validate_descriptor(
        plan.root_image
            .as_option()
            .ok_or(ProtocolValidationError::MissingField(
                "launch_plan.root_image",
            ))?,
        DescriptorRole::SandboxRootView,
    )?;
    let workspace_handle = exact_nonzero::<OPAQUE_HANDLE_BYTES>(
        &plan.workspace_handle,
        "launch_plan.workspace_handle",
    )?;
    let network_handle =
        exact_nonzero::<OPAQUE_HANDLE_BYTES>(&plan.network_handle, "launch_plan.network_handle")?;
    if plan.uid_range_size == 0
        || plan
            .uid_range_start
            .checked_add(plan.uid_range_size)
            .is_none()
    {
        return Err(ProtocolValidationError::InvalidField(
            "launch_plan.uid_range",
        ));
    }
    let limits = validate_resource_limits(&plan.limits)?;
    let attachment_handles = validate_attachment_handles(&plan.attachment_handles)?;
    let required_features = validate_features(&plan.required_features)?;

    Ok(ValidatedRuntimePlan {
        root_image,
        workspace_handle,
        network_handle,
        uid_range_start: plan.uid_range_start,
        uid_range_size: plan.uid_range_size,
        limits,
        attachment_handles,
        required_features,
    })
}

fn validate_resource_limits(
    source: &[aos_proto::aos::sandbox::local::v1::ResourceLimit],
) -> Result<Vec<ValidatedResourceLimit>, ProtocolValidationError> {
    if source.len() > MAXIMUM_RESOURCE_LIMITS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "launch_plan.limits",
            maximum: MAXIMUM_RESOURCE_LIMITS,
        });
    }
    let mut limits = Vec::with_capacity(source.len());
    for limit in source {
        if !limit.__buffa_unknown_fields.is_empty() {
            return Err(ProtocolValidationError::UnknownFields);
        }
        let dimension = u8::try_from(limit.dimension)
            .ok()
            .filter(|dimension| *dimension < 16)
            .ok_or(ProtocolValidationError::InvalidField(
                "launch_plan.limits.dimension",
            ))?;
        if limits
            .last()
            .is_some_and(|previous: &ValidatedResourceLimit| previous.dimension >= dimension)
        {
            return Err(ProtocolValidationError::InvalidField("launch_plan.limits"));
        }
        limits.push(ValidatedResourceLimit {
            dimension,
            value: limit.value,
        });
    }
    Ok(limits)
}

fn validate_attachment_handles(
    source: &[Vec<u8>],
) -> Result<Vec<[u8; OPAQUE_HANDLE_BYTES]>, ProtocolValidationError> {
    if source.len() > MAXIMUM_ATTACHMENTS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "launch_plan.attachment_handles",
            maximum: MAXIMUM_ATTACHMENTS,
        });
    }
    let mut handles = Vec::with_capacity(source.len());
    for handle in source {
        let handle =
            exact_nonzero::<OPAQUE_HANDLE_BYTES>(handle, "launch_plan.attachment_handles")?;
        if handles.last().is_some_and(|previous| previous >= &handle) {
            return Err(ProtocolValidationError::InvalidField(
                "launch_plan.attachment_handles",
            ));
        }
        handles.push(handle);
    }
    Ok(handles)
}

pub(crate) fn validate_peer_audience(
    peer: PeerCredentials,
    policy: PeerPolicy,
    offered_audience: Option<Audience>,
) -> Result<(), ProtocolValidationError> {
    if peer.uid != policy.uid || policy.gid.is_some_and(|gid| peer.gid != gid) {
        return Err(ProtocolValidationError::PeerCredentialMismatch);
    }
    if offered_audience != Some(policy.audience)
        || policy.audience == Audience::AUDIENCE_UNSPECIFIED
    {
        return Err(ProtocolValidationError::AudienceMismatch);
    }
    Ok(())
}

fn validate_features(
    source: &[aos_proto::aos::sandbox::local::v1::Feature],
) -> Result<Vec<FeatureRef>, ProtocolValidationError> {
    validate_feature_set(source, "launch_plan.required_features")
}

pub(crate) fn validate_feature_set(
    source: &[aos_proto::aos::sandbox::local::v1::Feature],
    field: &'static str,
) -> Result<Vec<FeatureRef>, ProtocolValidationError> {
    if source.len() > MAXIMUM_REQUIRED_FEATURES {
        return Err(ProtocolValidationError::TooManyEntries {
            field,
            maximum: MAXIMUM_REQUIRED_FEATURES,
        });
    }
    let mut features = Vec::with_capacity(source.len());
    for feature in source {
        if !feature.__buffa_unknown_fields.is_empty() {
            return Err(ProtocolValidationError::UnknownFields);
        }
        let feature = FeatureRef::new(feature.namespace.clone(), feature.major, feature.minor)
            .map_err(|error| ProtocolValidationError::InvalidDescriptor(error.to_string()))?;
        if features.last().is_some_and(|previous| previous >= &feature) {
            return Err(ProtocolValidationError::InvalidField(field));
        }
        features.push(feature);
    }
    validate_required_features(&features)?;
    Ok(features)
}

pub(crate) fn validate_descriptor(
    descriptor: &Descriptor,
    role: DescriptorRole,
) -> Result<ObjectDescriptor, ProtocolValidationError> {
    if !descriptor.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let media_type = MediaType::new(descriptor.media_type.clone())
        .map_err(|error| ProtocolValidationError::InvalidDescriptor(error.to_string()))?;
    let digest = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &descriptor.sha256,
        "descriptor.sha256",
    )?);
    let descriptor = ObjectDescriptor::new(media_type, digest, descriptor.encoded_size);
    validate_descriptor_role(role, &descriptor)
        .map_err(|error| ProtocolValidationError::InvalidDescriptor(error.to_string()))?;
    Ok(descriptor)
}

pub(crate) fn exact_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], ProtocolValidationError> {
    let exact: [u8; N] = bytes
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidFixedBytes { field, bytes: N })?;
    if exact.iter().all(|byte| *byte == 0) {
        Err(ProtocolValidationError::InvalidFixedBytes { field, bytes: N })
    } else {
        Ok(exact)
    }
}

fn optional_exact_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<Option<[u8; N]>, ProtocolValidationError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        exact_nonzero(bytes, field).map(Some)
    }
}

/// Exercises every privileged request decoder with arbitrary input bytes.
///
/// This entry point performs no effects and is intended for deterministic test
/// corpora and external coverage-guided fuzz engines. Successful protobuf
/// decoding is deliberately discarded; semantic entry points validate the
/// corresponding message before use.
pub fn exercise_malformed_request_decoders(bytes: &[u8]) {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return;
    }
    let _ = ApplyRuntimeRequest::decode_from_slice(bytes);
    let _ = ApplyStorageRequest::decode_from_slice(bytes);
    let _ = ApplyMountRequest::decode_from_slice(bytes);
    let _ = ApplyNetworkRequest::decode_from_slice(bytes);
    let _ = ApplyGuardianRequest::decode_from_slice(bytes);
    let _ = aos_proto::aos::sandbox::local::v1::GuestHandshakeRequest::decode_from_slice(bytes);
    let _ = ApplyGuestExecutionRequest::decode_from_slice(bytes);
    let _ = BrokerClientHello::decode_from_slice(bytes);
    let _ = BrokerRequestEnvelope::decode_from_slice(bytes);
    let _ = BrokerResponseEnvelope::decode_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inert_runtime_templates_share_semantics_but_not_live_request_validation() {
        use crate::semantics::host::{
            canonical_host_semantics_v1, canonical_host_template_semantics_v1,
        };
        for action in [
            RuntimeAction::RUNTIME_ACTION_LAUNCH,
            RuntimeAction::RUNTIME_ACTION_STOP,
            RuntimeAction::RUNTIME_ACTION_FREEZE,
            RuntimeAction::RUNTIME_ACTION_THAW,
            RuntimeAction::RUNTIME_ACTION_KILL,
        ] {
            let mut request = valid_runtime_request();
            request.action = action.into();
            if action != RuntimeAction::RUNTIME_ACTION_LAUNCH {
                request.launch_plan = None.into();
            }
            let live = decode_runtime_request(&request.encode_to_vec(), peer(), policy(), 100)
                .unwrap_or_else(|error| panic!("live fixture failed: {error}"));
            assert!(decode_runtime_template_v1(&request.encode_to_vec()).is_err());
            request
                .header
                .get_or_insert_default()
                .deadline_boottime_nanoseconds = 0;
            let bytes = request.encode_to_vec();
            let template = decode_runtime_template_v1(&bytes)
                .unwrap_or_else(|error| panic!("template fixture failed: {error}"));
            assert_eq!(
                canonical_host_template_semantics_v1(&template),
                canonical_host_semantics_v1(&live)
            );
            assert_eq!(template.action(), action);
            assert!(matches!(
                decode_runtime_request(&bytes, peer(), policy(), 0),
                Err(ProtocolValidationError::DeadlineExpired)
            ));
        }
    }

    #[test]
    fn runtime_template_rejects_unknown_fields_and_malformed_nested_inputs() {
        let mut base = valid_runtime_request();
        base.header
            .get_or_insert_default()
            .deadline_boottime_nanoseconds = 0;
        type Mutation = (&'static str, fn(&mut ApplyRuntimeRequest));
        let mutations: [Mutation; 7] = [
            ("audience", |request| {
                request.header.get_or_insert_default().audience =
                    Audience::AUDIENCE_UNSPECIFIED.into()
            }),
            ("version", |request| {
                request.header.get_or_insert_default().protocol_major = 99
            }),
            ("request id", |request| {
                request.header.get_or_insert_default().request_id.clear()
            }),
            ("response bound", |request| {
                request
                    .header
                    .get_or_insert_default()
                    .maximum_response_bytes = 0
            }),
            ("fence", |request| {
                request.fence.get_or_insert_default().desired_generation = 0
            }),
            ("stop with launch plan", |request| {
                request.action = RuntimeAction::RUNTIME_ACTION_STOP.into()
            }),
            ("launch without plan", |request| {
                request.launch_plan = None.into()
            }),
        ];
        for (name, mutate) in mutations {
            let mut request = base.clone();
            mutate(&mut request);
            assert!(
                decode_runtime_template_v1(&request.encode_to_vec()).is_err(),
                "{name}"
            );
        }
        let mut unknown = base.encode_to_vec();
        unknown.extend_from_slice(&[0xf8, 0x07, 0x01]);
        assert!(matches!(
            decode_runtime_template_v1(&unknown),
            Err(ProtocolValidationError::UnknownFields)
        ));
        assert!(matches!(
            decode_runtime_template_v1(&vec![0; MAXIMUM_REQUEST_BYTES + 1]),
            Err(ProtocolValidationError::RequestTooLarge)
        ));
    }

    fn valid_runtime_request() -> ApplyRuntimeRequest {
        let mut request = ApplyRuntimeRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 101;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 1;
        fence.desired_generation = 2;
        fence.assignment_digest = vec![4; 32];
        request.action = RuntimeAction::RUNTIME_ACTION_LAUNCH.into();
        let plan = request.launch_plan.get_or_insert_default();
        let root = plan.root_image.get_or_insert_default();
        root.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
        root.sha256 = vec![5; 32];
        root.encoded_size = 10;
        plan.workspace_handle = vec![6; OPAQUE_HANDLE_BYTES];
        plan.network_handle = vec![7; OPAQUE_HANDLE_BYTES];
        plan.uid_range_start = 65_536;
        plan.uid_range_size = 65_536;
        for (dimension, value) in [(2, 128), (3, 1 << 30), (4, 100)] {
            plan.limits
                .push(aos_proto::aos::sandbox::local::v1::ResourceLimit {
                    dimension,
                    value,
                    ..Default::default()
                });
        }
        plan.attachment_handles.push(vec![8; OPAQUE_HANDLE_BYTES]);
        plan.required_features
            .push(aos_proto::aos::sandbox::local::v1::Feature {
                namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
                major: 1,
                minor: 0,
                ..Default::default()
            });
        request
    }

    fn valid_mount_request() -> Vec<u8> {
        let mut request = ApplyMountRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 101;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 1;
        fence.desired_generation = 1;
        fence.assignment_digest = vec![4; 32];
        request.action = MountAction::MOUNT_ACTION_CREATE_DETACHED.into();
        request.attachment_id = vec![5; 16];
        request.destination_slot_id = vec![6; 16];
        request.source_generation = 1;
        request.namespace_generation = 1;
        let attributes = request.attributes.get_or_insert_default();
        attributes.read_only = true;
        attributes.no_suid = true;
        attributes.no_device = true;
        attributes.mutation_mode = 0;
        let descriptor = request.view_revision.get_or_insert_default();
        descriptor.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
        descriptor.sha256 = vec![7; 32];
        descriptor.encoded_size = 1;
        request.encode_to_vec()
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

    #[test]
    fn mount_validation_binds_peer_audience_fence_and_descriptor_role() {
        let encoded = valid_mount_request();
        let validated = decode_mount_request(&encoded, peer(), policy(), 100)
            .unwrap_or_else(|error| panic!("valid request failed: {error}"));
        assert_eq!(validated.header().request_id(), &[1; 16]);
        assert_eq!(validated.fence().incarnation_id(), &[3; 16]);
        assert_eq!(validated.attachment_id(), &[5; 16]);
        assert_eq!(validated.source_generation(), 1);
        assert_eq!(validated.namespace_generation(), 1);

        let mut wrong_peer = peer();
        wrong_peer.uid = 0;
        assert_eq!(
            decode_mount_request(&encoded, wrong_peer, policy(), 100),
            Err(ProtocolValidationError::PeerCredentialMismatch)
        );
    }

    #[test]
    fn mount_action_shapes_and_security_attributes_fail_closed() {
        let mut request = ApplyMountRequest::decode_from_slice(&valid_mount_request())
            .unwrap_or_else(|error| panic!("fixture decode failed: {error}"));
        request.action = MountAction::MOUNT_ACTION_INSTALL.into();
        assert_eq!(
            decode_mount_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidField(
                "mount action field shape"
            ))
        );

        let mut request = ApplyMountRequest::decode_from_slice(&valid_mount_request())
            .unwrap_or_else(|error| panic!("fixture decode failed: {error}"));
        request.attributes.get_or_insert_default().no_device = false;
        assert_eq!(
            decode_mount_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidField("attributes"))
        );

        let mut request = ApplyMountRequest::decode_from_slice(&valid_mount_request())
            .unwrap_or_else(|error| panic!("fixture decode failed: {error}"));
        request.source_generation = 0;
        assert_eq!(
            decode_mount_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidField(
                "source or namespace generation"
            ))
        );

        let mut request = ApplyMountRequest::decode_from_slice(&valid_mount_request())
            .unwrap_or_else(|error| panic!("fixture decode failed: {error}"));
        request.namespace_generation = 0;
        assert_eq!(
            decode_mount_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidField(
                "source or namespace generation"
            ))
        );
    }

    #[test]
    fn runtime_validation_closes_plan_and_returns_typed_fence() {
        let request = valid_runtime_request();
        let validated = decode_runtime_request(&request.encode_to_vec(), peer(), policy(), 100)
            .unwrap_or_else(|error| panic!("valid runtime request failed: {error}"));
        assert_eq!(validated.action(), RuntimeAction::RUNTIME_ACTION_LAUNCH);
        assert_eq!(validated.fence().incarnation_id(), &[3; 16]);
        let plan = validated
            .launch_plan()
            .unwrap_or_else(|| panic!("launch plan was lost"));
        assert_eq!(plan.workspace_handle(), &[6; OPAQUE_HANDLE_BYTES]);
        assert_eq!(plan.limits()[1].dimension(), 3);
    }

    #[test]
    fn runtime_action_smuggling_and_noncanonical_collections_fail_closed() {
        let mut request = valid_runtime_request();
        request.action = RuntimeAction::RUNTIME_ACTION_FREEZE.into();
        assert_eq!(
            decode_runtime_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidField("launch_plan"))
        );

        let mut request = valid_runtime_request();
        request
            .launch_plan
            .get_or_insert_default()
            .limits
            .swap(0, 1);
        assert_eq!(
            decode_runtime_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidField("launch_plan.limits"))
        );

        let mut request = valid_runtime_request();
        request.fence.get_or_insert_default().desired_generation = 0;
        assert_eq!(
            decode_runtime_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidField(
                "fence.desired_generation"
            ))
        );
    }

    #[test]
    fn response_budget_must_carry_a_fixed_broker_observation() {
        let mut request = valid_runtime_request();
        request
            .header
            .get_or_insert_default()
            .maximum_response_bytes = MINIMUM_RESPONSE_BYTES - 1;
        assert_eq!(
            decode_runtime_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidResponseBound)
        );
    }

    #[test]
    fn malformed_request_corpus_never_panics_or_allocates_unboundedly() {
        let seed = valid_mount_request();
        for length in 0..seed.len() {
            exercise_malformed_request_decoders(&seed[..length]);
        }

        let mut state = 0x9e37_79b9_u32;
        for length in 0..=512 {
            let mut bytes = vec![0; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state.to_le_bytes()[0];
            }
            exercise_malformed_request_decoders(&bytes);
        }
    }

    #[test]
    fn unknown_fields_and_descriptor_type_confusion_fail_closed() {
        let mut encoded = valid_mount_request();
        encoded.extend_from_slice(&[0xf8, 0x07, 0x01]); // Unknown field 127.
        assert_eq!(
            decode_mount_request(&encoded, peer(), policy(), 100),
            Err(ProtocolValidationError::UnknownFields)
        );

        let mut request = ApplyMountRequest::decode_from_slice(&valid_mount_request())
            .unwrap_or_else(|error| panic!("fixture decode failed: {error}"));
        request.view_revision.get_or_insert_default().media_type =
            "application/vnd.aos.sandbox.tree.v1+cbor".to_owned();
        assert!(matches!(
            decode_mount_request(&request.encode_to_vec(), peer(), policy(), 100),
            Err(ProtocolValidationError::InvalidDescriptor(_))
        ));
    }

    #[test]
    fn query_response_requires_closed_status_shape_and_exact_apply_fence() {
        use aos_proto::aos::sandbox::local::v1::{
            QueryRuntimeEffectResponse, RuntimeEffectStatus, RuntimeObservation, RuntimeState,
        };

        let original = valid_runtime_request();
        let validated =
            decode_runtime_request(&original.encode_to_vec(), peer(), policy(), 100).unwrap();
        let receipt = RuntimeObservation {
            runtime_handle: semantics::host::runtime_handle_v1(
                validated.fence().incarnation_id(),
                validated.fence().assignment_epoch(),
                validated.fence().assignment_digest(),
            )
            .to_vec(),
            fence: original.fence.clone(),
            state: RuntimeState::RUNTIME_STATE_READY.into(),
            observation_sequence: 1,
            ..Default::default()
        }
        .encode_to_vec();
        let complete = QueryRuntimeEffectResponse {
            status: RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE.into(),
            receipt: receipt.clone(),
            ..Default::default()
        };
        assert_eq!(
            decode_query_runtime_effect_response(&complete.encode_to_vec(), &validated).unwrap(),
            ValidatedRuntimeEffectStatus::Complete(receipt)
        );
        validate_runtime_effect_receipt_for_apply(&complete.receipt, &original.encode_to_vec())
            .unwrap();

        for response in [
            QueryRuntimeEffectResponse::default(),
            QueryRuntimeEffectResponse {
                status: RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_ABSENT.into(),
                receipt: vec![1],
                ..Default::default()
            },
            QueryRuntimeEffectResponse {
                status: RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_PENDING.into(),
                receipt: vec![1],
                ..Default::default()
            },
            QueryRuntimeEffectResponse {
                status: RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE.into(),
                ..Default::default()
            },
        ] {
            assert!(
                decode_query_runtime_effect_response(&response.encode_to_vec(), &validated)
                    .is_err()
            );
        }

        let mut wrong = RuntimeObservation::decode_from_slice(&complete.receipt).unwrap();
        wrong.fence.get_or_insert_default().assignment_digest = vec![10; 32];
        let wrong = QueryRuntimeEffectResponse {
            status: RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE.into(),
            receipt: wrong.encode_to_vec(),
            ..Default::default()
        };
        assert!(decode_query_runtime_effect_response(&wrong.encode_to_vec(), &validated).is_err());
        assert!(
            validate_runtime_effect_receipt_for_apply(&wrong.receipt, &original.encode_to_vec())
                .is_err()
        );

        let mut coherent = RuntimeObservation::decode_from_slice(&complete.receipt).unwrap();
        coherent.fence.get_or_insert_default().assignment_digest = vec![11; 32];
        coherent.runtime_handle = semantics::host::runtime_handle_v1(
            validated.fence().incarnation_id(),
            validated.fence().assignment_epoch(),
            &[11; 32],
        )
        .to_vec();
        assert!(
            validate_runtime_effect_receipt_for_apply(
                &coherent.encode_to_vec(),
                &original.encode_to_vec(),
            )
            .is_err()
        );

        let mut wrong_handle = RuntimeObservation::decode_from_slice(&complete.receipt).unwrap();
        wrong_handle.runtime_handle = vec![9; 32];
        let wrong_handle = QueryRuntimeEffectResponse {
            status: RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE.into(),
            receipt: wrong_handle.encode_to_vec(),
            ..Default::default()
        };
        assert!(
            decode_query_runtime_effect_response(&wrong_handle.encode_to_vec(), &validated)
                .is_err()
        );

        let oversized = QueryRuntimeEffectResponse {
            status: RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE.into(),
            receipt: vec![1; session::MAXIMUM_RUNTIME_EFFECT_RECEIPT_BYTES + 1],
            ..Default::default()
        };
        assert!(
            decode_query_runtime_effect_response(&oversized.encode_to_vec(), &validated).is_err()
        );
        let mut unknown = complete.encode_to_vec();
        unknown.extend_from_slice(&[0xf8, 0x07, 0x01]);
        assert_eq!(
            decode_query_runtime_effect_response(&unknown, &validated),
            Err(ProtocolValidationError::UnknownFields)
        );
    }
}

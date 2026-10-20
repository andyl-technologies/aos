//! Canonical controller-to-Host execution handoff and protected readback bodies.
//!
//! These decoders establish wire shape and cross-links. The authenticated
//! broker session proves the sender; the fixed Host execution owner supplies
//! currentness, admission, effect, and outcome authority.

pub mod admission_content;
pub mod monitor;
pub mod capture_terminal;

use aos_proto::aos::sandbox::local::v1::{
    ApplyHostExecutionRequestV1, HostExecutionActionV1, HostExecutionCompletionStatusV1,
    HostExecutionOutcomeV1, HostExecutionPhaseV1, QueryHostExecutionRequestV1,
};
use aos_sandbox_core::runtime_backend::EffectOperationV1;
use aos_sandbox_core::{
    DecodeLimits, ExecutionId, ObjectDigest, ProtocolId, decode_execution_spec_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero,
    validate_request_header,
};

const MAXIMUM_HANDOFF_BODY_BYTES: usize = 64 * 1024;
const GUEST_RESULT_MAGIC: &[u8; 8] = b"AOSGER01";
const GUEST_RESULT_HEADER_BYTES: usize = 13;

/// Largest canonical execution specification admitted by the runtime backend.
pub const MAXIMUM_HOST_EXECUTION_SPEC_BYTES: usize = 15 * 1_048_576;

/// Exact sealed content for an Apply control action without a specification.
pub const HOST_EXECUTION_CONTROL_CONTENT_V1: &[u8] = &[0];

/// Reports the terminal result of one Host-authenticated Guest Observe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostExecutionTerminalResultV1 {
    /// The guest observed a child exit; -1 means no exit code was available.
    Exited(i32),
    /// The guest observed cancellation of the child.
    Canceled,
    /// The Guest timeout owner reaped the original tree and retained its waitstatus.
    ///
    /// This result is terminal evidence only inside its authenticated Failed
    /// response and matching FailedPermanent completion, never from a clock.
    TimedOut(aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4),
    /// The v2 Guest producer retained the exact original Linux waitstatus.
    Original {
        /// Original leader status, never a relay exit or synthetic sentinel.
        status: aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4,
        /// Recursive execution-tree cancellation completed under the Owner cut.
        canceled: bool,
    },
}

/// Decodes the exact bounded terminal payload emitted by the packaged guest.
///
/// These bytes gain authority only after Host verifies the signed guest packet
/// and binds it to the same completed Observe and observation sequence.
///
/// # Errors
///
/// Rejects a malformed or nonterminal Guest result.
pub fn decode_host_execution_terminal_result_v1(
    bytes: &[u8],
) -> Result<HostExecutionTerminalResultV1, ProtocolValidationError> {
    if matches!(bytes.get(..8), Some(magic) if magic == b"AOSGER02" || magic == b"AOSGER03") {
        if bytes.len() != GUEST_RESULT_HEADER_BYTES + 4
            || bytes[9..13] != 4_u32.to_be_bytes()
            || if bytes.get(..8) == Some(b"AOSGER03".as_slice()) { bytes[8] != 8 } else { !matches!(bytes[8], 6 | 7) }
        {
            return Err(ProtocolValidationError::InvalidField(
                "terminal guest result v2",
            ));
        }
        let raw = u32::from_be_bytes(
            bytes[13..17]
                .try_into()
                .map_err(|_| ProtocolValidationError::InvalidField("terminal guest result v2"))?,
        );
        let status = aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4::new(raw)
            .map_err(|_| ProtocolValidationError::InvalidField("terminal guest result v2"))?;
        if bytes.get(..8) == Some(b"AOSGER03".as_slice()) {
            return Ok(HostExecutionTerminalResultV1::TimedOut(status));
        }
        return Ok(HostExecutionTerminalResultV1::Original {
            status,
            canceled: bytes[8] == 7,
        });
    }
    if bytes.len() < GUEST_RESULT_HEADER_BYTES
        || bytes.get(..8) != Some(GUEST_RESULT_MAGIC.as_slice())
    {
        return Err(ProtocolValidationError::InvalidField(
            "terminal guest result",
        ));
    }
    let length = u32::from_be_bytes(
        bytes[9..13]
            .try_into()
            .map_err(|_| ProtocolValidationError::InvalidField("terminal guest result"))?,
    ) as usize;
    if length != bytes.len() - GUEST_RESULT_HEADER_BYTES {
        return Err(ProtocolValidationError::InvalidField(
            "terminal guest result",
        ));
    }
    match (bytes[8], &bytes[GUEST_RESULT_HEADER_BYTES..]) {
        (6, code) if code.len() == 4 => {
            Ok(HostExecutionTerminalResultV1::Exited(i32::from_be_bytes(
                code.try_into()
                    .map_err(|_| ProtocolValidationError::InvalidField("terminal guest result"))?,
            )))
        }
        (7, value) if value == b"canceled" => Ok(HostExecutionTerminalResultV1::Canceled),
        _ => Err(ProtocolValidationError::InvalidField(
            "terminal guest result",
        )),
    }
}

const SPEC_LIFETIME_ADMISSION_ATTEMPT_DOMAIN_V5: &[u8] =
    b"aos.sandbox.host.execution-lifetime-admission-attempt.v5\0";
const SPEC_ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.host.execution-spec-attempt.v1\0";
const QUERY_SPEC_ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.host.execution-query-spec-attempt.v1\0";
const QUERY_SPEC_ATTEMPT_DOMAIN_V2: &[u8] = b"aos.sandbox.host.execution-query-spec-attempt.v2\0";

/// Binds one sealed content reference to an authenticated Apply or Query attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionSpecContentFieldsV1 {
    bytes: u64,
    digest: [u8; 32],
    attempt_commitment: [u8; 32],
}

impl HostExecutionSpecContentFieldsV1 {
    /// Derives the stable content portion of a signed grant.
    #[must_use]
    pub fn for_grant(content: &[u8]) -> Self {
        Self {
            bytes: content.len() as u64,
            digest: Sha256::digest(content).into(),
            attempt_commitment: [0; 32],
        }
    }

    /// Binds stable content fields to one authenticated request attempt.
    #[must_use]
    pub fn bind_attempt(
        self,
        request_id: [u8; 16],
        operation_id: [u8; 16],
        execution_id: ExecutionId,
        source_commitment: ObjectDigest,
        action: EffectOperationV1,
    ) -> Self {
        Self {
            attempt_commitment: spec_attempt_commitment_v1(
                request_id,
                operation_id,
                execution_id,
                source_commitment,
                action,
                self.bytes,
                self.digest,
            ),
            ..self
        }
    }

    /// Binds the complete tagged lifetime content to one version-five Apply.
    #[must_use]
    pub fn bind_lifetime_admission_attempt_v5(
        self,
        request_id: [u8; 16],
        operation_id: [u8; 16],
        execution_id: ExecutionId,
        source_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attempt_commitment: spec_attempt_commitment_with_domain(
                SPEC_LIFETIME_ADMISSION_ATTEMPT_DOMAIN_V5, request_id, operation_id,
                execution_id, source_commitment, EffectOperationV1::AuthorizeExecution,
                self.bytes, self.digest,
            ),
            ..self
        }
    }

    /// Binds an exact Apply content reference to one Query readback attempt.
    #[must_use]
    pub fn bind_query_attempt(
        self,
        request_id: [u8; 16],
        operation_id: [u8; 16],
        execution_id: ExecutionId,
        source_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attempt_commitment: query_spec_attempt_commitment_v1(
                request_id,
                operation_id,
                execution_id,
                source_commitment,
                self.bytes,
                self.digest,
            ),
            ..self
        }
    }

    /// Binds a version-two Query to the admitted semantic specification digest.
    #[must_use]
    pub fn bind_query_attempt_v2(
        self,
        request_id: [u8; 16],
        operation_id: [u8; 16],
        execution_id: ExecutionId,
        source_commitment: ObjectDigest,
        specification_digest: ObjectDigest,
    ) -> Self {
        Self {
            attempt_commitment: query_spec_attempt_commitment_v2(
                request_id,
                operation_id,
                execution_id,
                source_commitment,
                self.bytes,
                self.digest,
                specification_digest,
            ),
            ..self
        }
    }

    /// Binds a content5 monitor read to the exact request and original lineage selectors.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn bind_query_attempt_v3(self, request_id: [u8; 16], create: [u8; 16],
        execution: ExecutionId, source: ObjectDigest, specification: ObjectDigest,
        selector: monitor::HostExecutionMonitorSelectorV3) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"aos.sandbox.host.execution-query-spec-attempt.v3\0");
        hash.update(request_id);
        hash.update(create);
        hash.update(execution.as_bytes());
        hash.update(source.as_bytes());
        hash.update(self.bytes.to_be_bytes());
        hash.update(self.digest);
        hash.update(specification.as_bytes());
        selector.append_comparison_bytes_v3(&mut hash);
        Self { attempt_commitment: hash.finalize().into(), ..self }
    }

    /// Returns the exact expected sealed descriptor size.
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Returns SHA-256 of the exact sealed descriptor contents.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Returns the commitment to content and the authenticated request attempt.
    pub const fn attempt_commitment(self) -> [u8; 32] {
        self.attempt_commitment
    }

    /// Reports whether this reference is the exact control marker.
    #[must_use]
    pub fn is_control_marker(self) -> bool {
        self.bytes == HOST_EXECUTION_CONTROL_CONTENT_V1.len() as u64
            && self.digest == <[u8; 32]>::from(Sha256::digest(HOST_EXECUTION_CONTROL_CONTENT_V1))
    }
}

/// Derives the signed fields for a sealed Host execution-spec descriptor.
///
/// # Errors
///
/// Rejects empty or oversized content and a control marker that differs from
/// the fixed one-byte value. The caller supplies canonical specification bytes
/// for Authorize; Host independently decodes and reproduces them before effect.
#[allow(clippy::too_many_arguments)]
pub fn host_execution_spec_content_fields_v1(
    request_id: [u8; 16],
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    action: EffectOperationV1,
    content: &[u8],
) -> Result<HostExecutionSpecContentFieldsV1, ProtocolValidationError> {
    if content.is_empty() || content.len() > MAXIMUM_HOST_EXECUTION_SPEC_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    if !matches!(action, EffectOperationV1::AuthorizeExecution)
        && content != HOST_EXECUTION_CONTROL_CONTENT_V1
    {
        return Err(ProtocolValidationError::InvalidField("spec content"));
    }
    Ok(
        HostExecutionSpecContentFieldsV1::for_grant(content).bind_attempt(
            request_id,
            operation_id,
            execution_id,
            source_commitment,
            action,
        ),
    )
}

fn spec_attempt_commitment_v1(
    request_id: [u8; 16],
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    action: EffectOperationV1,
    bytes: u64,
    digest: [u8; 32],
) -> [u8; 32] {
    spec_attempt_commitment_with_domain(SPEC_ATTEMPT_DOMAIN, request_id,
        operation_id, execution_id, source_commitment, action, bytes, digest)
}

#[allow(clippy::too_many_arguments)]
fn spec_attempt_commitment_with_domain(
    domain: &[u8], request_id: [u8; 16], operation_id: [u8; 16],
    execution_id: ExecutionId, source_commitment: ObjectDigest,
    action: EffectOperationV1, bytes: u64, digest: [u8; 32],
) -> [u8; 32] {
    let mut attempt = Sha256::new();
    attempt.update(domain);
    attempt.update(request_id);
    attempt.update(operation_id);
    attempt.update(execution_id.as_bytes());
    attempt.update(source_commitment.as_bytes());
    attempt.update([action.code()]);
    attempt.update(action.arguments());
    attempt.update(bytes.to_be_bytes());
    attempt.update(digest);
    attempt.finalize().into()
}

fn query_spec_attempt_commitment_v1(
    request_id: [u8; 16],
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    bytes: u64,
    digest: [u8; 32],
) -> [u8; 32] {
    let mut attempt = Sha256::new();
    attempt.update(QUERY_SPEC_ATTEMPT_DOMAIN);
    attempt.update(request_id);
    attempt.update(operation_id);
    attempt.update(execution_id.as_bytes());
    attempt.update(source_commitment.as_bytes());
    attempt.update(bytes.to_be_bytes());
    attempt.update(digest);
    attempt.finalize().into()
}

fn query_spec_attempt_commitment_v2(
    request_id: [u8; 16],
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    bytes: u64,
    digest: [u8; 32],
    specification_digest: ObjectDigest,
) -> [u8; 32] {
    let mut attempt = Sha256::new();
    attempt.update(QUERY_SPEC_ATTEMPT_DOMAIN_V2);
    attempt.update(request_id);
    attempt.update(operation_id);
    attempt.update(execution_id.as_bytes());
    attempt.update(source_commitment.as_bytes());
    attempt.update(bytes.to_be_bytes());
    attempt.update(digest);
    attempt.update(specification_digest.as_bytes());
    attempt.finalize().into()
}

/// Carries a validated intent without granting execution authority.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedHostExecutionApplyV1 {
    header: ValidatedHeader,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    action: EffectOperationV1,
    content_version: u32,
    admission_accepted_request: Option<ObjectDigest>,
    admission_source: Option<admission_content::LifetimeSourceDataV5>,
    specification: Option<aos_sandbox_core::ExecutionSpecV1>,
    content: Option<HostExecutionSpecContentFieldsV1>,
}

impl ValidatedHostExecutionApplyV1 {
    /// Returns the validated broker request header.
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the stable controller operation identity.
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the exact execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Returns the controller's stable canonical operation commitment.
    pub const fn source_commitment(&self) -> ObjectDigest {
        self.source_commitment
    }

    /// Returns the closed guest control action.
    pub const fn action(&self) -> EffectOperationV1 {
        self.action
    }

    /// Borrows the canonical execution specification for authorization.
    pub const fn specification(&self) -> Option<&aos_sandbox_core::ExecutionSpecV1> {
        self.specification.as_ref()
    }

    /// Returns the exact sealed descriptor size for descriptor transport v1.
    pub const fn content_bytes(&self) -> Option<u64> {
        match self.content {
            Some(content) => Some(content.bytes()),
            None => None,
        }
    }

    /// Returns the version bound to the signed complete descriptor contents.
    #[must_use]
    pub const fn content_version(&self) -> u32 { self.content_version }

    /// Returns the signed content reference for grant matching.
    pub const fn content_fields(&self) -> Option<HostExecutionSpecContentFieldsV1> {
        self.content
    }

    /// Returns the exact version-five accepted-request DATA after full content validation.
    ///
    /// This field grants no native claim or execution permission on its own.
    #[must_use]
    pub const fn admission_accepted_request_digest_v5(&self) -> Option<ObjectDigest> {
        self.admission_accepted_request
    }

    /// Copies source DATA only after the same complete sealed-content validation.
    ///
    /// A signed admission and native original remain independently mandatory.
    #[must_use]
    pub const fn admission_source_data_v5(&self) -> Option<admission_content::LifetimeSourceDataV5> {
        self.admission_source
    }

    /// Validates one pinned sealed descriptor against this exact Apply attempt.
    ///
    /// # Errors
    ///
    /// Rejects legacy inline transport, changed bytes, a noncanonical or
    /// mismatched specification, and a changed control marker.
    pub fn verify_content(&mut self, bytes: &[u8]) -> Result<(), ProtocolValidationError> {
        let expected = self.content.ok_or(ProtocolValidationError::InvalidField(
            "spec transfer version",
        ))?;
        let (actual, specification_bytes, admission_accepted_request, admission_source) = if self.content_version == 5 {
            let admission = admission_content::HostExecutionAdmissionContentV5::decode(bytes)?;
            let fields = crate::execution_spec_attempt::ExecutionSpecAttemptFieldsV1::decode(
                admission.attempt_bytes(),
            ).map_err(|_| ProtocolValidationError::InvalidField("admission attempt"))?;
            if self.action != EffectOperationV1::AuthorizeExecution
                || fields.execution != self.execution_id
                || fields.create_operation.as_bytes() != &self.operation_id
            {
                return Err(ProtocolValidationError::InvalidField("admission identity"));
            }
            let actual = HostExecutionSpecContentFieldsV1::for_grant(bytes)
                .bind_lifetime_admission_attempt_v5(*self.header.request_id(),
                    self.operation_id, self.execution_id, self.source_commitment);
            (actual, fields.specification_bytes, Some(fields.accepted_request_digest), Some(admission.source_data_v5()))
        } else {
            (host_execution_spec_content_fields_v1(
                *self.header.request_id(), self.operation_id, self.execution_id,
                self.source_commitment, self.action, bytes,
            )?, bytes, None, None)
        };
        if actual != expected {
            return Err(ProtocolValidationError::InvalidField("spec content"));
        }
        if matches!(self.action, EffectOperationV1::AuthorizeExecution) {
            let limits = DecodeLimits {
                maximum_bytes: MAXIMUM_HOST_EXECUTION_SPEC_BYTES,
                ..DecodeLimits::default()
            };
            let specification = decode_execution_spec_v1(specification_bytes, limits)
                .map_err(|_| ProtocolValidationError::InvalidField("spec content"))?;
            if specification.execution() != self.execution_id {
                return Err(ProtocolValidationError::InvalidField("execution_id"));
            }
            self.specification = Some(specification);
        }
        self.admission_accepted_request = admission_accepted_request;
        self.admission_source = admission_source;
        Ok(())
    }
}

/// Carries a validated readback locator without granting an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostExecutionQueryV1 {
    header: ValidatedHeader,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    content: HostExecutionSpecContentFieldsV1,
    specification_digest: ObjectDigest,
    monitor: Option<monitor::HostExecutionMonitorSelectorV3>,
}

impl ValidatedHostExecutionQueryV1 {
    /// Borrows the exact signed monitor selector, without admitting a child.
    #[must_use]
    pub const fn monitor_v3(&self) -> Option<&monitor::HostExecutionMonitorSelectorV3> {
        self.monitor.as_ref()
    }

    /// Returns the validated broker request header.
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the stable controller operation identity.
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the exact execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Returns the controller's stable canonical operation commitment.
    pub const fn source_commitment(&self) -> ObjectDigest {
        self.source_commitment
    }

    /// Returns the exact Apply content reference bound to this readback.
    pub const fn content_fields(&self) -> HostExecutionSpecContentFieldsV1 {
        self.content
    }

    /// Returns the admitted semantic execution-specification digest.
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }
}

/// Decodes one canonical authenticated Host execution intent.
///
/// # Errors
///
/// Rejects oversized, noncanonical, unknown-field, malformed, or semantically
/// inconsistent requests and expired or foreign broker headers.
pub fn decode_host_execution_apply_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostExecutionApplyV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HANDOFF_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyHostExecutionRequestV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
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
    let operation_id = exact_nonzero::<16>(&request.operation_id, "operation_id")?;
    let execution_id =
        ExecutionId::from_bytes(exact_nonzero::<16>(&request.execution_id, "execution_id")?);
    let source_commitment = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &request.source_operation_commitment,
        "source_operation_commitment",
    )?);

    let no_geometry = request.terminal_rows == 0 && request.terminal_columns == 0;
    let action = match request.action.as_known() {
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE)
            if no_geometry && request.signal_number == 0 =>
        {
            EffectOperationV1::AuthorizeExecution
        }
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_RESIZE)
            if request.signal_number == 0 && request.canonical_execution_spec.is_empty() =>
        {
            let rows = u16::try_from(request.terminal_rows)
                .ok()
                .filter(|value| *value != 0)
                .ok_or(ProtocolValidationError::InvalidField("terminal_rows"))?;
            let columns = u16::try_from(request.terminal_columns)
                .ok()
                .filter(|value| *value != 0)
                .ok_or(ProtocolValidationError::InvalidField("terminal_columns"))?;
            EffectOperationV1::ResizeTerminal { rows, columns }
        }
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_SIGNAL)
            if no_geometry
                && request.canonical_execution_spec.is_empty()
                && (1..=64).contains(&request.signal_number) =>
        {
            EffectOperationV1::Signal {
                signal_code: request.signal_number as u8,
            }
        }
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_CANCEL)
            if no_geometry
                && request.signal_number == 0
                && request.canonical_execution_spec.is_empty() =>
        {
            EffectOperationV1::Cancel
        }
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_OBSERVE)
            if no_geometry
                && request.signal_number == 0
                && request.canonical_execution_spec.is_empty() =>
        {
            EffectOperationV1::Observe
        }
        _ => {
            return Err(ProtocolValidationError::InvalidField(
                "execution action fields",
            ));
        }
    };
    let content = if matches!(request.spec_transfer_version, 1 | 5) {
        let maximum = if request.spec_transfer_version == 5 {
            if action != EffectOperationV1::AuthorizeExecution {
                return Err(ProtocolValidationError::InvalidField("admission action"));
            }
            admission_content::MAXIMUM_ADMISSION_CONTENT_BYTES_V5
        } else { MAXIMUM_HOST_EXECUTION_SPEC_BYTES };
        if !request.canonical_execution_spec.is_empty()
            || request.spec_content_bytes == 0
            || request.spec_content_bytes > maximum as u64
        {
            return Err(ProtocolValidationError::InvalidField("spec content"));
        }
        let digest = exact_nonzero::<32>(&request.spec_content_digest, "spec_content_digest")?;
        let attempt_commitment =
            exact_nonzero::<32>(&request.spec_attempt_commitment, "spec_attempt_commitment")?;
        if !matches!(action, EffectOperationV1::AuthorizeExecution)
            && (request.spec_content_bytes != HOST_EXECUTION_CONTROL_CONTENT_V1.len() as u64
                || digest != <[u8; 32]>::from(Sha256::digest(HOST_EXECUTION_CONTROL_CONTENT_V1)))
        {
            return Err(ProtocolValidationError::InvalidField("spec content"));
        }
        let domain = match request.spec_transfer_version {
            5 => SPEC_LIFETIME_ADMISSION_ATTEMPT_DOMAIN_V5,
            _ => SPEC_ATTEMPT_DOMAIN,
        };
        if spec_attempt_commitment_with_domain(
            domain, *header.request_id(),
            operation_id,
            execution_id,
            source_commitment,
            action,
            request.spec_content_bytes,
            digest,
        ) != attempt_commitment
        {
            return Err(ProtocolValidationError::InvalidField(
                "spec attempt commitment",
            ));
        }
        HostExecutionSpecContentFieldsV1 {
            bytes: request.spec_content_bytes,
            digest,
            attempt_commitment,
        }
    } else {
        return Err(ProtocolValidationError::InvalidField(
            "spec transfer version",
        ));
    };

    Ok(ValidatedHostExecutionApplyV1 {
        header,
        operation_id,
        execution_id,
        source_commitment,
        action,
        content_version: request.spec_transfer_version,
        admission_accepted_request: None,
        admission_source: None,
        specification: None,
        content: Some(content),
    })
}

/// Decodes one canonical protected-outcome readback locator.
///
/// # Errors
///
/// Rejects malformed, noncanonical, expired, or foreign requests.
pub fn decode_host_execution_query_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostExecutionQueryV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HANDOFF_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryHostExecutionRequestV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
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
    let content_bytes = request.spec_content_bytes;
    let monitor = match request.query_binding_version {
        2 if request.spec_transfer_version == 1
            && request.monitor_runtime_handle.is_empty()
            && request.monitor_first_observe_operation_id.is_empty()
            && request.monitor_source_digest.is_empty() && request.monitor_source_kind == 0 => None,
        3 if request.spec_transfer_version == 5 => Some(monitor::HostExecutionMonitorSelectorV3::new(
            ObjectDigest::from_bytes(exact_nonzero::<32>(&request.monitor_runtime_handle, "monitor runtime")?),
            aos_sandbox_core::runtime_backend::BackendOperationIdV1::new(exact_nonzero::<16>(
                &request.monitor_first_observe_operation_id, "first Observe")?).map_err(|_| monitor::invalid())?,
            ObjectDigest::from_bytes(exact_nonzero::<32>(&request.monitor_source_digest, "monitor source")?),
            request.monitor_source_kind)?),
        _ => return Err(ProtocolValidationError::InvalidField("query binding version")),
    };
    let maximum = if monitor.is_some() { admission_content::MAXIMUM_ADMISSION_CONTENT_BYTES_V5 }
        else { MAXIMUM_HOST_EXECUTION_SPEC_BYTES };
    if content_bytes == 0 || content_bytes > maximum as u64 {
        return Err(ProtocolValidationError::InvalidField("spec_content_bytes"));
    }
    let content_digest = exact_nonzero::<32>(&request.spec_content_digest, "spec_content_digest")?;
    let attempt_commitment =
        exact_nonzero::<32>(&request.spec_attempt_commitment, "spec_attempt_commitment")?;
    let operation_id = exact_nonzero::<16>(&request.operation_id, "operation_id")?;
    let execution_id =
        ExecutionId::from_bytes(exact_nonzero::<16>(&request.execution_id, "execution_id")?);
    let source_commitment = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &request.source_operation_commitment,
        "source_operation_commitment",
    )?);
    let specification_digest = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &request.execution_spec_digest,
        "execution_spec_digest",
    )?);
    let content = HostExecutionSpecContentFieldsV1 {
        bytes: content_bytes,
        digest: content_digest,
        attempt_commitment: [0; 32],
    };
    let content = match monitor {
        Some(selector) => content.bind_query_attempt_v3(*header.request_id(), operation_id,
            execution_id, source_commitment, specification_digest, selector),
        None => content.bind_query_attempt_v2(*header.request_id(), operation_id,
            execution_id, source_commitment, specification_digest),
    };
    if content.attempt_commitment() != attempt_commitment {
        return Err(ProtocolValidationError::InvalidField(
            "spec attempt commitment",
        ));
    }
    Ok(ValidatedHostExecutionQueryV1 {
        header,
        operation_id,
        execution_id,
        source_commitment,
        content,
        specification_digest,
        monitor,
    })
}

/// Checks a Host result against an exact authenticated apply or query locator.
///
/// # Errors
///
/// Rejects foreign IDs, malformed phase-specific fields, and noncanonical wire.
pub fn decode_host_execution_outcome_v1(
    bytes: &[u8],
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
) -> Result<HostExecutionOutcomeV1, ProtocolValidationError> {
    let outcome = decode_canonical_execution_outcome_v3(bytes)?;
    require_ordinary_outcome_shape_v3(&outcome)?;
    validate_execution_outcome_fields_v3(outcome, operation_id, execution_id, source_commitment)
}

fn decode_canonical_execution_outcome_v3(bytes: &[u8])
    -> Result<HostExecutionOutcomeV1, ProtocolValidationError> {
    let outcome = HostExecutionOutcomeV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !outcome.__buffa_unknown_fields.is_empty() || outcome.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    Ok(outcome)
}

fn require_ordinary_outcome_shape_v3(outcome: &HostExecutionOutcomeV1)
    -> Result<(), ProtocolValidationError> {
    if outcome.query_binding_version != 0 || outcome.backend_operation_sequence != 0
        || !outcome.capture_terminal_marker.is_empty()
    { return Err(monitor::invalid()); }
    Ok(())
}

fn validate_execution_outcome_fields_v3(outcome: HostExecutionOutcomeV1,
    operation_id: [u8; 16], execution_id: ExecutionId, source_commitment: ObjectDigest)
    -> Result<HostExecutionOutcomeV1, ProtocolValidationError> {
    if outcome.operation_id != operation_id
        || outcome.execution_id != execution_id.as_bytes()
        || outcome.source_operation_commitment != source_commitment.as_bytes()
    {
        return Err(ProtocolValidationError::InvalidField(
            "execution outcome identity",
        ));
    }
    match outcome.phase.as_known() {
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ABSENT)
            if outcome.effect_commitment.is_empty()
                && outcome.completion_digest.is_empty()
                && outcome.completion_bytes.is_empty()
                && outcome.completion_status.to_i32() == 0
                && outcome.observation_sequence == 0
                && outcome.terminal_guest_result.is_empty() => {}
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_PENDING
            | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ISSUED
            | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_INDETERMINATE)
            if exact_nonzero::<32>(&outcome.effect_commitment, "effect_commitment").is_ok()
                && outcome.completion_digest.is_empty()
                && outcome.completion_bytes.is_empty()
                && outcome.completion_status.to_i32() == 0
                && outcome.observation_sequence == 0
                && outcome.terminal_guest_result.is_empty() => {}
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE)
            if exact_nonzero::<32>(&outcome.effect_commitment, "effect_commitment").is_ok()
                && exact_nonzero::<32>(&outcome.completion_digest, "completion_digest").is_ok()
                && !outcome.completion_bytes.is_empty()
                && outcome.completion_bytes.len() <= 15 * 1_048_576
                && outcome.completion_digest == execution_result_digest(&outcome.completion_bytes)
                && outcome.observation_sequence != 0
                && matches!(outcome.completion_status.as_known(),
                    Some(HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED
                        | HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_REJECTED_BEFORE_EFFECT
                        | HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_FAILED_PERMANENT)) => {}
        _ => return Err(ProtocolValidationError::InvalidField("execution outcome phase")),
    }
    if !outcome.terminal_guest_result.is_empty() {
        let terminal = decode_host_execution_terminal_result_v1(&outcome.terminal_guest_result)?;
        let expected_phase = match terminal {
            HostExecutionTerminalResultV1::TimedOut(_) => 6,
            HostExecutionTerminalResultV1::Exited(_) => 4,
            HostExecutionTerminalResultV1::Canceled => 5,
            HostExecutionTerminalResultV1::Original { canceled, .. } => {
                if canceled {
                    5
                } else {
                    4
                }
            }
        };
        if outcome.phase.as_known() != Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE)
            || outcome.completion_status.as_known()
                != Some(if matches!(terminal, HostExecutionTerminalResultV1::TimedOut(_)) {
                    HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_FAILED_PERMANENT
                } else { HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED })
            || outcome.completion_bytes.len() != 298
            || outcome.completion_bytes[8] != EffectOperationV1::Observe.code()
            || outcome.completion_bytes[225] != expected_phase
        {
            return Err(ProtocolValidationError::InvalidField(
                "terminal guest result",
            ));
        }
    }
    Ok(outcome)
}

/// Retains validated historical monitor outcome DATA without native authority.
pub struct ValidatedHostExecutionMonitorOutcomeV3 {
    outcome: HostExecutionOutcomeV1,
    lineage: Option<monitor::ExecutionMonitorLineageDataV5>,
    capture_complete: Option<crate::storage_capture_result::CaptureCompleteRecordDataV2>,
}

impl ValidatedHostExecutionMonitorOutcomeV3 {
    /// Borrows the exact canonical Host outcome.
    #[must_use]
    pub const fn outcome_v3(&self) -> &HostExecutionOutcomeV1 { &self.outcome }

    /// Borrows ordinary monitor lineage; initial firstObserve and Absent carry none.
    #[must_use]
    pub const fn lineage_v3(&self) -> Option<&monitor::ExecutionMonitorLineageDataV5> { self.lineage.as_ref() }

    /// Borrows full676 DATA after exact versioned original-marker comparison.
    ///
    /// Actual native Host read scope/currentness and independent fresh Source61
    /// equality are required before Controller can publish physical completion.
    #[must_use]
    pub const fn capture_complete_v3(&self) -> Option<&crate::storage_capture_result::CaptureCompleteRecordDataV2> {
        self.capture_complete.as_ref()
    }
}

/// Validates Query3's actual existing terminal child and same-key Capture extension.
///
/// # Errors
/// Rejects foreign sequence/source/runtime/result, unknown grammar, or a marker
/// that changes C1's actual Complete or already-settled process reservation.
pub fn decode_host_execution_monitor_outcome_v3(bytes: &[u8],
    query: &ValidatedHostExecutionQueryV1) -> Result<ValidatedHostExecutionMonitorOutcomeV3, ProtocolValidationError> {
    use aos_sandbox_core::runtime_backend::BackendOperationSequenceV1;
    let selector = query.monitor_v3().copied().ok_or_else(monitor::invalid)?;
    let outcome = decode_canonical_execution_outcome_v3(bytes)?;
    if outcome.query_binding_version != 3 { return Err(monitor::invalid()); }
    if outcome.phase.as_known() == Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ABSENT) {
        if outcome.backend_operation_sequence != 0 || !outcome.capture_terminal_marker.is_empty() {
            return Err(monitor::invalid());
        }
        let outcome = validate_execution_outcome_fields_v3(outcome, query.operation_id(),
            query.execution_id(), query.source_commitment())?;
        return Ok(ValidatedHostExecutionMonitorOutcomeV3 { outcome, lineage: None, capture_complete: None });
    }
    let sequence = BackendOperationSequenceV1::new(outcome.backend_operation_sequence)
        .map_err(|_| monitor::invalid())?;
    let initial = outcome.operation_id == selector.first_observe_v3().as_bytes();
    let lineage = if initial { None } else {
        Some(selector.lineage_for_sequence_v3(aos_sandbox_core::OperationId::from_bytes(query.operation_id()),
            query.execution_id(), sequence)?)
    };
    let (operation, source) = match &lineage {
        Some(lineage) => (*lineage.operation_v5().as_bytes(), lineage.commitment_v5()),
        None => (*selector.first_observe_v3().as_bytes(), query.source_commitment()),
    };
    let outcome = validate_execution_outcome_fields_v3(outcome, operation, query.execution_id(), source)?;
    require_observed_completion_binding_v3(&outcome, operation, query.execution_id(), source,
        sequence.get(), selector.runtime_v3(), query.specification_digest())?;
    let capture_complete = if outcome.capture_terminal_marker.is_empty() { None } else {
        if selector.source_kind_v3() != 2 || outcome.terminal_guest_result.is_empty()
            || outcome.phase.as_known() != Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE)
        { return Err(monitor::invalid()); }
        let marker = capture_terminal::HostExecutionTerminalMarkerDataV3::decode_v3(&outcome.capture_terminal_marker)?;
        let original = marker.original_bytes_v3();
        let complete = *marker.capture_complete_v3().ok_or_else(monitor::invalid)?;
        if original.get(..32) != outcome.completion_bytes.get(113..145)
            || original.get(32..48) != Some(operation.as_slice())
            || original.get(48..80) != Some(outcome.effect_commitment.as_slice())
            || complete.source_digest != selector.source_v3()
            || complete.execution != *query.execution_id().as_bytes()
            || complete.create_operation != query.operation_id()
        { return Err(monitor::invalid()); }
        Some(complete)
    };
    Ok(ValidatedHostExecutionMonitorOutcomeV3 { outcome, lineage, capture_complete })
}

fn require_observed_completion_binding_v3(outcome: &HostExecutionOutcomeV1,
    operation: [u8; 16], execution: ExecutionId, source: ObjectDigest,
    sequence: u64, runtime: ObjectDigest, specification: ObjectDigest)
    -> Result<(), ProtocolValidationError> {
    if outcome.phase.as_known() != Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE) { return Ok(()); }
    let phase = crate::execution_evidence::decode_observe_completion_phase_v1(&outcome.completion_bytes,
        operation, *source.as_bytes(), *execution.as_bytes(), specification, outcome.observation_sequence)
        .map_err(|_| monitor::invalid())?;
    use aos_sandbox_core::runtime_backend::BackendExecutionPhaseV1;
    let status = match phase {
        BackendExecutionPhaseV1::Running | BackendExecutionPhaseV1::Exited | BackendExecutionPhaseV1::Canceled =>
            HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED,
        BackendExecutionPhaseV1::Failed | BackendExecutionPhaseV1::Lost =>
            HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_FAILED_PERMANENT,
        _ => return Err(monitor::invalid()),
    };
    if outcome.completion_status.as_known() != Some(status) { return Err(monitor::invalid()); }
    if outcome.completion_bytes.get(25..33) != Some(sequence.to_be_bytes().as_slice())
        || outcome.completion_bytes.get(177..209) != Some(runtime.as_bytes().as_slice())
    { return Err(monitor::invalid()); }
    Ok(())
}

fn execution_result_digest(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-execution-effect-result-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

#[cfg(test)]
mod content_tests {
    //! Exact signed terminal versions and immutable source/spec correlations.

    use super::*;
    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};

    #[test]
    fn terminal_guest_result_accepts_only_exact_packaged_observe_results() {
        let exited = [
            b"AOSGER01".as_slice(),
            &[6],
            &4_u32.to_be_bytes(),
            &17_i32.to_be_bytes(),
        ]
        .concat();
        let canceled = [
            b"AOSGER01".as_slice(),
            &[7],
            &8_u32.to_be_bytes(),
            b"canceled",
        ]
        .concat();

        assert_eq!(
            decode_host_execution_terminal_result_v1(&exited).unwrap(),
            HostExecutionTerminalResultV1::Exited(17)
        );
        let unknown_status = [
            b"AOSGER01".as_slice(),
            &[6],
            &4_u32.to_be_bytes(),
            &(-1_i32).to_be_bytes(),
        ]
        .concat();
        assert_eq!(
            decode_host_execution_terminal_result_v1(&unknown_status).unwrap(),
            HostExecutionTerminalResultV1::Exited(-1)
        );
        assert_eq!(
            decode_host_execution_terminal_result_v1(&canceled).unwrap(),
            HostExecutionTerminalResultV1::Canceled
        );

        for malformed in [
            exited[..exited.len() - 1].to_vec(),
            [exited.as_slice(), &[0]].concat(),
            [
                b"AOSGER01".as_slice(),
                &[5],
                &4_u32.to_be_bytes(),
                &17_i32.to_be_bytes(),
            ]
            .concat(),
            [
                b"AOSGER01".as_slice(),
                &[7],
                &8_u32.to_be_bytes(),
                b"cancelXd",
            ]
            .concat(),
        ] {
            assert!(decode_host_execution_terminal_result_v1(&malformed).is_err());
        }
    }

    #[test]
    fn terminal_readback_requires_completed_observe_with_matching_phase() {
        let operation = [1; 16];
        let execution = ExecutionId::from_bytes([2; 16]);
        let source = ObjectDigest::from_bytes([3; 32]);
        let mut completion = vec![0; 298];
        completion[8] = EffectOperationV1::Observe.code();
        completion[225] = 4;
        let mut result = HostExecutionOutcomeV1 {
            operation_id: operation.to_vec(),
            execution_id: execution.as_bytes().to_vec(),
            source_operation_commitment: source.as_bytes().to_vec(),
            phase: HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE.into(),
            effect_commitment: vec![4; 32],
            completion_digest: execution_result_digest(&completion).to_vec(),
            completion_bytes: completion,
            completion_status:
                HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED.into(),
            observation_sequence: 1,
            terminal_guest_result: [
                b"AOSGER01".as_slice(),
                &[6],
                &4_u32.to_be_bytes(),
                &0_i32.to_be_bytes(),
            ]
            .concat(),
            ..Default::default()
        };
        assert!(decode_host_execution_outcome_v1(
            &result.encode_to_vec(),
            operation,
            execution,
            source,
        )
        .is_ok());

        result.completion_bytes[225] = 3;
        result.completion_digest = execution_result_digest(&result.completion_bytes).to_vec();
        assert!(decode_host_execution_outcome_v1(
            &result.encode_to_vec(),
            operation,
            execution,
            source,
        )
        .is_err());
        result.completion_bytes[225] = 4;
        result.completion_bytes[8] = EffectOperationV1::AuthorizeExecution.code();
        result.completion_digest = execution_result_digest(&result.completion_bytes).to_vec();
        assert!(decode_host_execution_outcome_v1(
            &result.encode_to_vec(),
            operation,
            execution,
            source,
        )
        .is_err());
    }

    #[test]
    fn original_terminal_v2_preserves_status_and_rejects_ambiguous_shapes() {
        for (kind, raw, canceled) in [(6, 17 << 8, false), (6, 11 | 0x80, false), (7, 9, true)] {
            let bytes = [
                b"AOSGER02".as_slice(),
                &[kind],
                &4_u32.to_be_bytes(),
                &u32::to_be_bytes(raw),
            ]
            .concat();
            assert_eq!(
                decode_host_execution_terminal_result_v1(&bytes).unwrap(),
                HostExecutionTerminalResultV1::Original {
                    status: aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4::new(
                        raw
                    )
                    .unwrap(),
                    canceled,
                }
            );
            for partial in 0..bytes.len() {
                assert!(decode_host_execution_terminal_result_v1(&bytes[..partial]).is_err());
            }
            assert!(
                decode_host_execution_terminal_result_v1(&[bytes.as_slice(), &[0]].concat())
                    .is_err()
            );
        }
        for raw in [u32::MAX, 0x7f, 0xffff, 65, 128, 0x0109] {
            let bytes = [
                b"AOSGER02".as_slice(),
                &[6],
                &4_u32.to_be_bytes(),
                &u32::to_be_bytes(raw),
            ]
            .concat();
            assert!(decode_host_execution_terminal_result_v1(&bytes).is_err());
        }
    }

    fn fields(request_id: [u8; 16], content: &[u8]) -> HostExecutionSpecContentFieldsV1 {
        host_execution_spec_content_fields_v1(
            request_id,
            [2; 16],
            ExecutionId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]),
            EffectOperationV1::AuthorizeExecution,
            content,
        )
        .unwrap()
    }

    fn query(content: &[u8]) -> QueryHostExecutionRequestV1 {
        let content = HostExecutionSpecContentFieldsV1::for_grant(content).bind_query_attempt_v2(
            [1; 16],
            [2; 16],
            ExecutionId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
        );
        QueryHostExecutionRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 10,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            operation_id: vec![2; 16],
            execution_id: vec![3; 16],
            source_operation_commitment: vec![4; 32],
            spec_content_bytes: content.bytes(),
            spec_content_digest: content.digest().to_vec(),
            spec_transfer_version: 1,
            query_binding_version: 2,
            execution_spec_digest: vec![5; 32],
            spec_attempt_commitment: content.attempt_commitment().to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn monitor_query3_binds_every_original_selector_and_refuses_cross_version_fields() {
        let selector = monitor::HostExecutionMonitorSelectorV3::new(
            ObjectDigest::from_bytes([6; 32]),
            aos_sandbox_core::runtime_backend::BackendOperationIdV1::new([7; 16]).unwrap(),
            ObjectDigest::from_bytes([8; 32]), 2).unwrap();
        let mut request = query(b"original content5 bytes");
        request.query_binding_version = 3;
        request.spec_transfer_version = 5;
        request.monitor_runtime_handle = selector.runtime_v3().as_bytes().to_vec();
        request.monitor_first_observe_operation_id = selector.first_observe_v3().as_bytes().to_vec();
        request.monitor_source_digest = selector.source_v3().as_bytes().to_vec();
        request.monitor_source_kind = selector.source_kind_v3();
        request.spec_attempt_commitment = HostExecutionSpecContentFieldsV1::for_grant(b"original content5 bytes")
            .bind_query_attempt_v3([1; 16], [2; 16], ExecutionId::from_bytes([3; 16]),
                ObjectDigest::from_bytes([4; 32]), ObjectDigest::from_bytes([5; 32]), selector)
            .attempt_commitment().to_vec();
        let valid = decode_query(&request).unwrap();
        assert_eq!(valid.monitor_v3(), Some(&selector));

        for changed in 0..6 {
            let mut foreign = request.clone();
            match changed {
                0 => foreign.monitor_runtime_handle[0] ^= 1,
                1 => foreign.monitor_first_observe_operation_id[0] ^= 1,
                2 => foreign.monitor_source_digest[0] ^= 1,
                3 => foreign.monitor_source_kind = 1,
                4 => foreign.query_binding_version = 2,
                _ => foreign.spec_transfer_version = 1,
            }
            assert!(decode_query(&foreign).is_err());
        }
        let mut absent = HostExecutionOutcomeV1 {
            operation_id: vec![2; 16], execution_id: vec![3; 16],
            source_operation_commitment: vec![4; 32],
            phase: HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ABSENT.into(),
            query_binding_version: 3, ..Default::default()
        };
        assert!(decode_host_execution_monitor_outcome_v3(&absent.encode_to_vec(), &valid).is_ok());
        assert!(decode_host_execution_outcome_v1(&absent.encode_to_vec(), [2; 16],
            ExecutionId::from_bytes([3; 16]), ObjectDigest::from_bytes([4; 32])).is_err());
        absent.query_binding_version = 0;
        assert!(decode_host_execution_monitor_outcome_v3(&absent.encode_to_vec(), &valid).is_err());
    }

    fn decode_query(
        request: &QueryHostExecutionRequestV1,
    ) -> Result<ValidatedHostExecutionQueryV1, ProtocolValidationError> {
        decode_host_execution_query_v1(
            &request.encode_to_vec(),
            PeerCredentials {
                uid: 100,
                gid: 200,
                pid: Some(300),
            },
            PeerPolicy {
                uid: 100,
                gid: Some(200),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            1,
        )
    }

    #[test]
    fn sealed_content_reference_binds_the_exact_attempt_and_bytes() {
        let original = fields([1; 16], b"specification");

        assert_eq!(original.bytes(), 13);
        assert_ne!(
            original.digest(),
            fields([1; 16], b"specification!").digest()
        );
        assert_ne!(
            original.attempt_commitment(),
            fields([5; 16], b"specification").attempt_commitment()
        );
    }

    #[test]
    fn validated_content_fields_reuse_the_exact_stable_grant_binding() {
        let content = b"canonical specification";
        let execution = ExecutionId::from_bytes([3; 16]);
        let source = ObjectDigest::from_bytes([4; 32]);
        let actual = host_execution_spec_content_fields_v1(
            [1; 16],
            [2; 16],
            execution,
            source,
            EffectOperationV1::AuthorizeExecution,
            content,
        )
        .unwrap();
        let expected = HostExecutionSpecContentFieldsV1::for_grant(content).bind_attempt(
            [1; 16],
            [2; 16],
            execution,
            source,
            EffectOperationV1::AuthorizeExecution,
        );

        assert_eq!(actual, expected);
        assert!(
            host_execution_spec_content_fields_v1(
                [1; 16],
                [2; 16],
                execution,
                source,
                EffectOperationV1::AuthorizeExecution,
                b"",
            )
            .is_err()
        );
        assert!(
            host_execution_spec_content_fields_v1(
                [1; 16],
                [2; 16],
                execution,
                source,
                EffectOperationV1::Observe,
                content,
            )
            .is_err()
        );
    }

    #[test]
    fn full_runtime_content_ceiling_is_admitted_without_inline_framing() {
        let largest = vec![7; MAXIMUM_HOST_EXECUTION_SPEC_BYTES];

        assert_eq!(fields([1; 16], &largest).bytes(), largest.len() as u64);
        let oversized = vec![7; MAXIMUM_HOST_EXECUTION_SPEC_BYTES + 1];
        assert!(
            host_execution_spec_content_fields_v1(
                [1; 16],
                [2; 16],
                ExecutionId::from_bytes([3; 16]),
                ObjectDigest::from_bytes([4; 32]),
                EffectOperationV1::AuthorizeExecution,
                &oversized,
            )
            .is_err()
        );
    }

    #[test]
    fn query_references_maximum_content_in_a_small_authenticated_body() {
        let content = vec![7; MAXIMUM_HOST_EXECUTION_SPEC_BYTES];
        let request = query(&content);

        assert!(request.encode_to_vec().len() < MAXIMUM_HANDOFF_BODY_BYTES);
        assert_eq!(
            decode_query(&request).unwrap().content_fields().bytes(),
            MAXIMUM_HOST_EXECUTION_SPEC_BYTES as u64
        );

        let mut oversized = request;
        oversized.spec_content_bytes += 1;
        assert!(decode_query(&oversized).is_err());
    }

    #[test]
    fn query_rejects_legacy_corruption_and_attempt_replay() {
        let request = query(b"canonical content");
        assert!(decode_query(&request).is_ok());

        let mut legacy = request.clone();
        legacy.spec_transfer_version = 0;
        legacy.spec_attempt_commitment.clear();
        assert!(matches!(
            decode_query(&legacy),
            Err(ProtocolValidationError::InvalidField(
                "query binding version"
            ))
        ));

        let mut unknown_version = request.clone();
        unknown_version.spec_transfer_version = 3;
        assert!(matches!(
            decode_query(&unknown_version),
            Err(ProtocolValidationError::InvalidField(
                "query binding version"
            ))
        ));

        let mut old_binding = request.clone();
        old_binding.query_binding_version = 0;
        old_binding.execution_spec_digest.clear();
        assert!(matches!(
            decode_query(&old_binding),
            Err(ProtocolValidationError::InvalidField(
                "query binding version"
            ))
        ));

        let mut unknown_binding = request.clone();
        unknown_binding.query_binding_version = 3;
        assert!(matches!(
            decode_query(&unknown_binding),
            Err(ProtocolValidationError::InvalidField(
                "query binding version"
            ))
        ));

        let mut old_attempt = request.clone();
        let legacy_content = HostExecutionSpecContentFieldsV1::for_grant(b"canonical content")
            .bind_query_attempt(
                [1; 16],
                [2; 16],
                ExecutionId::from_bytes([3; 16]),
                ObjectDigest::from_bytes([4; 32]),
            );
        old_attempt.spec_attempt_commitment = legacy_content.attempt_commitment().to_vec();
        assert!(matches!(
            decode_query(&old_attempt),
            Err(ProtocolValidationError::InvalidField(
                "spec attempt commitment"
            ))
        ));

        let mut wrong_specification = request.clone();
        wrong_specification.execution_spec_digest = vec![6; 32];
        assert!(matches!(
            decode_query(&wrong_specification),
            Err(ProtocolValidationError::InvalidField(
                "spec attempt commitment"
            ))
        ));

        let mut missing_attempt = request.clone();
        missing_attempt.spec_attempt_commitment.clear();
        assert!(matches!(
            decode_query(&missing_attempt),
            Err(ProtocolValidationError::InvalidFixedBytes {
                field: "spec_attempt_commitment",
                bytes: 32,
            })
        ));

        let mut corrupted = request.clone();
        corrupted.spec_content_digest[0] ^= 1;
        assert!(matches!(
            decode_query(&corrupted),
            Err(ProtocolValidationError::InvalidField(
                "spec attempt commitment"
            ))
        ));

        let mut replayed = request.clone();
        let mut replayed_header = replayed.header.as_option().unwrap().clone();
        replayed_header.request_id = vec![9; 16];
        replayed.header = Some(replayed_header).into();
        assert!(matches!(
            decode_query(&replayed),
            Err(ProtocolValidationError::InvalidField(
                "spec attempt commitment"
            ))
        ));

        let mut wrong_locator = request;
        wrong_locator.operation_id = vec![8; 16];
        assert!(matches!(
            decode_query(&wrong_locator),
            Err(ProtocolValidationError::InvalidField(
                "spec attempt commitment"
            ))
        ));
    }

    #[test]
    fn control_content_has_one_canonical_marker() {
        let accepted = host_execution_spec_content_fields_v1(
            [1; 16],
            [2; 16],
            ExecutionId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]),
            EffectOperationV1::Cancel,
            HOST_EXECUTION_CONTROL_CONTENT_V1,
        )
        .unwrap();

        assert!(accepted.is_control_marker());
        assert!(
            host_execution_spec_content_fields_v1(
                [1; 16],
                [2; 16],
                ExecutionId::from_bytes([3; 16]),
                ObjectDigest::from_bytes([4; 32]),
                EffectOperationV1::Cancel,
                b"other",
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_inline_apply_is_rejected_by_the_host_decoder() {
        let request = ApplyHostExecutionRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 10,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            operation_id: vec![2; 16],
            execution_id: vec![3; 16],
            source_operation_commitment: vec![4; 32],
            action: HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE.into(),
            canonical_execution_spec: vec![5],
            ..Default::default()
        };
        let peer = PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        };
        let policy = PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };

        assert!(matches!(
            decode_host_execution_apply_v1(&request.encode_to_vec(), peer, policy, 1),
            Err(ProtocolValidationError::InvalidField(
                "spec transfer version"
            ))
        ));
    }
}

#[cfg(test)]
mod monitor_timeout_result_tests {
    use super::*;

    #[test]
    fn original_timeout_waitstatus_requires_exact_new_magic_kind_and_width() {
        let mut bytes = b"AOSGER03".to_vec();
        bytes.push(8);
        bytes.extend_from_slice(&4_u32.to_be_bytes());
        bytes.extend_from_slice(&9_u32.to_be_bytes());
        assert!(matches!(decode_host_execution_terminal_result_v1(&bytes),
            Ok(HostExecutionTerminalResultV1::TimedOut(status)) if status == aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4::new(9).unwrap()));
        for width in 0..bytes.len() {
            assert!(decode_host_execution_terminal_result_v1(&bytes[..width]).is_err());
        }
        for kind in [5, 6, 7, 9] {
            let mut changed = bytes.clone();
            changed[8] = kind;
            assert!(decode_host_execution_terminal_result_v1(&changed).is_err());
        }
        bytes.push(0);
        assert!(decode_host_execution_terminal_result_v1(&bytes).is_err());
    }
}

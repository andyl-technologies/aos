//! Typed canonical semantics for the networkless publisher protocol.
//!
//! ```text
//! message = "AOSPLP02" | version:u16be | method:u8 | flags:u8
//!           | request-id:16 | body-len:u32be | body-digest:32 | typed-body
//! body    = "AOSPLB01" | version:u16be | method-specific canonical fields
//! ```
//!
//! Descriptor observations contain no file-descriptor number. The carrier
//! derives an immutable identity commitment and access class from each received
//! description, in received order, and binds the set to the exact body digest.

use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, OperationId, PrincipalId, ProjectId,
    PublisherChallengeV1, PublisherInstanceId,
    format::{
        decode_publisher_admission_request_v1, decode_publisher_domain_plan,
        encode_publisher_admission_request_v1, encode_publisher_domain_plan,
    },
};
use sha2::{Digest as _, Sha256};

use super::PublicationPermitId;

const MESSAGE_MAGIC: &[u8; 8] = b"AOSPLP02";
const BODY_MAGIC: &[u8; 8] = b"AOSPLB01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 64;
const MAXIMUM_BODY_BYTES: usize = 1024 * 1024;
const BODY_DOMAIN: &[u8] = b"aos.sandbox.publisher.local-body.v2\0";

/// Selects one closed local method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublisherLocalMethodV1 {
    /// Registers a challenge and exact request bytes.
    RegisterChallenge = 1,
    /// Returns a retained admission decision and signed plan.
    AdmissionResult = 2,
    /// Supplies one readable source descriptor for materialization.
    PrepareArtifact = 3,
    /// Requests a completion permit for one prepared artifact.
    RequestCompletion = 4,
    /// Returns one retained completion permit.
    CompletionPermit = 5,
    /// Reports a durable physical/catalog result.
    CommitReceipt = 6,
    /// Requests observation-only recovery.
    ObserveRecovery = 7,
    /// Returns one closed recovery disposition.
    RecoveryResult = 8,
    /// Requests an independently authorized cache read.
    OpenForRead = 9,
    /// Returns one pinned immutable backing descriptor.
    OpenFound = 10,
    /// Returns the same result for absence and concealment.
    OpenNotFoundOrConcealed = 11,
}

impl PublisherLocalMethodV1 {
    fn from_code(code: u8) -> Result<Self, PublisherLocalProtocolError> {
        Ok(match code {
            1 => Self::RegisterChallenge,
            2 => Self::AdmissionResult,
            3 => Self::PrepareArtifact,
            4 => Self::RequestCompletion,
            5 => Self::CompletionPermit,
            6 => Self::CommitReceipt,
            7 => Self::ObserveRecovery,
            8 => Self::RecoveryResult,
            9 => Self::OpenForRead,
            10 => Self::OpenFound,
            11 => Self::OpenNotFoundOrConcealed,
            _ => return Err(PublisherLocalProtocolError::UnknownMethod),
        })
    }
}

/// Selects the semantic access class observed on one transferred description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DescriptorAccessV1 {
    /// Readable regular source; immutability is not implied.
    ReadableSource = 1,
    /// Read-only, independently verified immutable committed backing.
    ReadOnlyImmutableBacking = 2,
}

/// Commits one expected descriptor's identity, order, and access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorCommitmentV1 {
    /// Zero-based position in the received control-message descriptor array.
    ordinal: u8,
    /// Carrier-derived identity/metadata commitment, never an fd/device/inode scalar.
    identity_digest: ObjectDigest,
    /// Exact required access/immutability class.
    access: DescriptorAccessV1,
}

impl DescriptorCommitmentV1 {
    /// Constructs the sole v1 descriptor commitment at received ordinal zero.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherLocalProtocolError::Malformed`] for a zero identity.
    pub fn first(
        identity_digest: ObjectDigest,
        access: DescriptorAccessV1,
    ) -> Result<Self, PublisherLocalProtocolError> {
        if identity_digest.as_bytes() == &[0; 32] {
            return Err(PublisherLocalProtocolError::Malformed);
        }
        Ok(Self {
            ordinal: 0,
            identity_digest,
            access,
        })
    }
}

/// Reports one freshly inspected received descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedDescriptorV1 {
    /// Position observed by the carrier.
    ordinal: u8,
    /// Domain-separated identity/metadata observation.
    identity_digest: ObjectDigest,
    /// Access/immutability class proven by the carrier.
    access: DescriptorAccessV1,
    /// Digest of the exact canonical body received with this descriptor set.
    body_digest: ObjectDigest,
}

impl ObservedDescriptorV1 {
    /// Records one descriptor observation made by the trusted carrier.
    pub(crate) const fn from_carrier(
        ordinal: u8,
        identity_digest: ObjectDigest,
        access: DescriptorAccessV1,
        body_digest: ObjectDigest,
    ) -> Self {
        Self {
            ordinal,
            identity_digest,
            access,
            body_digest,
        }
    }

    /// Checks one body-bound carrier observation against a typed commitment.
    pub(crate) fn matches(
        &self,
        commitment: DescriptorCommitmentV1,
        body_digest: ObjectDigest,
    ) -> bool {
        self.ordinal == commitment.ordinal
            && self.identity_digest == commitment.identity_digest
            && self.access as u8 == commitment.access as u8
            && self.body_digest == body_digest
    }
}

/// Owns one closed typed method body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublisherLocalBodyV1 {
    /// Registers an exact canonical admission request.
    RegisterChallenge {
        /// Publisher execution that generated the challenge.
        publisher_instance: PublisherInstanceId,
        /// Exact unpredictable challenge.
        challenge: PublisherChallengeV1,
        /// Canonical publisher admission request.
        canonical_request: Vec<u8>,
    },
    /// Returns the durable admission and signed plan commitments.
    AdmissionResult {
        /// Publication operation.
        operation: OperationId,
        /// Durable decision commitment.
        decision_digest: ObjectDigest,
        /// Exact canonical publisher-domain plan bytes.
        canonical_plan: Vec<u8>,
        /// Detached controller signature over the decision and plan.
        signature: Vec<u8>,
    },
    /// Requests private materialization from one descriptor.
    PrepareArtifact {
        /// Publication operation.
        operation: OperationId,
        /// Durable admission decision.
        decision_digest: ObjectDigest,
        /// Expected source descriptor observation.
        source: DescriptorCommitmentV1,
    },
    /// Requests issuance of an exact artifact-bound permit.
    RequestCompletion {
        /// Publication operation.
        operation: OperationId,
        /// Prepared artifact commitment.
        artifact_digest: ObjectDigest,
    },
    /// Returns one durable one-shot permit.
    CompletionPermit {
        /// Publication operation.
        operation: OperationId,
        /// Permit identity.
        permit: PublicationPermitId,
        /// Complete permit commitment.
        permit_digest: ObjectDigest,
    },
    /// Reports a terminal durable receipt commitment.
    CommitReceipt {
        /// Publication operation.
        operation: OperationId,
        /// Permit spent by completion.
        permit: PublicationPermitId,
        /// Terminal receipt commitment.
        receipt_digest: ObjectDigest,
    },
    /// Requests observation-only recovery for one decision.
    ObserveRecovery {
        /// Publication operation.
        operation: OperationId,
        /// Retained decision commitment.
        decision_digest: ObjectDigest,
    },
    /// Returns one non-extensible recovery result.
    RecoveryResult {
        /// Publication operation.
        operation: OperationId,
        /// Closed disposition.
        disposition: CompletionDispositionV1,
        /// Exact observed-state commitment.
        observation_digest: ObjectDigest,
    },
    /// Requests an independent current read authorization.
    OpenForRead {
        /// Authenticated requesting holder.
        holder: PrincipalId,
        /// Authorized project.
        project: ProjectId,
        /// Exact requested object.
        object: ObjectDescriptor,
        /// Current read-policy/revocation commitment.
        read_authority_digest: ObjectDigest,
        /// Required current catalog generation.
        catalog_generation: u64,
    },
    /// Returns a pinned backing descriptor commitment.
    OpenFound {
        /// Exact object being returned.
        object: ObjectDescriptor,
        /// Current catalog entry commitment.
        catalog_entry_digest: ObjectDigest,
        /// Expected immutable backing descriptor.
        backing: DescriptorCommitmentV1,
    },
    /// Conceals whether the requested object exists.
    OpenNotFoundOrConcealed {
        /// Commitment to the exact request receiving the concealed result.
        request_digest: ObjectDigest,
    },
}

impl PublisherLocalBodyV1 {
    /// Returns the exact method selected by this typed body.
    #[must_use]
    pub const fn method(&self) -> PublisherLocalMethodV1 {
        match self {
            Self::RegisterChallenge { .. } => PublisherLocalMethodV1::RegisterChallenge,
            Self::AdmissionResult { .. } => PublisherLocalMethodV1::AdmissionResult,
            Self::PrepareArtifact { .. } => PublisherLocalMethodV1::PrepareArtifact,
            Self::RequestCompletion { .. } => PublisherLocalMethodV1::RequestCompletion,
            Self::CompletionPermit { .. } => PublisherLocalMethodV1::CompletionPermit,
            Self::CommitReceipt { .. } => PublisherLocalMethodV1::CommitReceipt,
            Self::ObserveRecovery { .. } => PublisherLocalMethodV1::ObserveRecovery,
            Self::RecoveryResult { .. } => PublisherLocalMethodV1::RecoveryResult,
            Self::OpenForRead { .. } => PublisherLocalMethodV1::OpenForRead,
            Self::OpenFound { .. } => PublisherLocalMethodV1::OpenFound,
            Self::OpenNotFoundOrConcealed { .. } => PublisherLocalMethodV1::OpenNotFoundOrConcealed,
        }
    }

    fn descriptor(&self) -> Option<DescriptorCommitmentV1> {
        match self {
            Self::PrepareArtifact { source, .. } => Some(*source),
            Self::OpenFound { backing, .. } => Some(*backing),
            _ => None,
        }
    }
}

/// Owns one typed canonical local message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherLocalMessageV1 {
    /// Nonzero transport correlation identity.
    pub request_id: [u8; 16],
    /// Fully decoded method body.
    pub body: PublisherLocalBodyV1,
    /// Commitment binding method, request, and canonical body.
    pub body_digest: ObjectDigest,
}

impl PublisherLocalMessageV1 {
    /// Revalidates that this typed value is the exact canonical message it claims.
    ///
    /// This check is required because the public data model is convenient for
    /// diagnostics and construction, while dispatch accepts only values that
    /// could have passed the canonical decoder.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherLocalProtocolError`] for a malformed body, invalid
    /// request identity, or a body commitment that differs from canonical bytes.
    pub fn validate_canonical(&self) -> Result<(), PublisherLocalProtocolError> {
        if self.request_id == [0; 16] {
            return Err(PublisherLocalProtocolError::Malformed);
        }
        let body = encode_body(&self.body)?;
        let expected = body_digest(self.body.method(), self.request_id, &body);
        if self.body_digest != expected {
            return Err(PublisherLocalProtocolError::DigestMismatch);
        }
        Ok(())
    }
}

/// Reports malformed protocol or descriptor observations.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublisherLocalProtocolError {
    /// A fixed body or message bound was exceeded.
    #[error("publisher local message exceeds its bound")]
    LimitExceeded,
    /// Framing, field, enum, identity, or canonical encoding is malformed.
    #[error("publisher local message is malformed")]
    Malformed,
    /// Method is outside the closed registry.
    #[error("publisher local method is unknown")]
    UnknownMethod,
    /// Body commitment differs.
    #[error("publisher local body digest differs")]
    DigestMismatch,
    /// Descriptor count, order, identity, access, or body binding differs.
    #[error("publisher local descriptor commitment differs")]
    DescriptorMismatch,
    /// Bounded allocation failed.
    #[error("publisher local allocation failed")]
    Allocation,
}

/// Encodes one typed canonical message.
///
/// # Errors
///
/// Returns [`PublisherLocalProtocolError`] for invalid identities, bounds,
/// semantic fields, or allocation.
pub fn encode_local_message_v1(
    request_id: [u8; 16],
    body: &PublisherLocalBodyV1,
) -> Result<Vec<u8>, PublisherLocalProtocolError> {
    if request_id == [0; 16] {
        return Err(PublisherLocalProtocolError::Malformed);
    }
    let canonical_body = encode_body(body)?;
    let body_len = u32::try_from(canonical_body.len())
        .map_err(|_| PublisherLocalProtocolError::LimitExceeded)?;
    let total = HEADER_BYTES
        .checked_add(canonical_body.len())
        .ok_or(PublisherLocalProtocolError::LimitExceeded)?;
    let digest = body_digest(body.method(), request_id, &canonical_body);
    let mut bytes = bounded_vec(total)?;
    bytes.extend_from_slice(MESSAGE_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(body.method() as u8);
    bytes.push(0);
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&body_len.to_be_bytes());
    bytes.extend_from_slice(digest.as_bytes());
    bytes.extend_from_slice(&canonical_body);
    Ok(bytes)
}

/// Decodes a typed message and validates all descriptor observations.
///
/// # Errors
///
/// Returns [`PublisherLocalProtocolError`] for any framing, canonical body,
/// digest, count, order, identity, access, body-binding, or bound violation.
pub fn decode_local_message_v1(
    bytes: &[u8],
    descriptors: &[ObservedDescriptorV1],
) -> Result<PublisherLocalMessageV1, PublisherLocalProtocolError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > HEADER_BYTES + MAXIMUM_BODY_BYTES {
        return Err(PublisherLocalProtocolError::LimitExceeded);
    }
    if &bytes[..8] != MESSAGE_MAGIC
        || u16::from_be_bytes(exact(&bytes[8..10])?) != VERSION
        || bytes[11] != 0
    {
        return Err(PublisherLocalProtocolError::Malformed);
    }
    let method = PublisherLocalMethodV1::from_code(bytes[10])?;
    let request_id = exact(&bytes[12..28])?;
    if request_id == [0; 16] {
        return Err(PublisherLocalProtocolError::Malformed);
    }
    let length = usize::try_from(u32::from_be_bytes(exact(&bytes[28..32])?))
        .map_err(|_| PublisherLocalProtocolError::LimitExceeded)?;
    if HEADER_BYTES.checked_add(length) != Some(bytes.len()) {
        return Err(PublisherLocalProtocolError::Malformed);
    }
    let stored = ObjectDigest::from_bytes(exact(&bytes[32..64])?);
    let canonical_body = &bytes[64..];
    let digest = body_digest(method, request_id, canonical_body);
    if digest != stored {
        return Err(PublisherLocalProtocolError::DigestMismatch);
    }
    let body = decode_body(method, canonical_body)?;
    validate_descriptors(&body, digest, descriptors)?;
    if encode_local_message_v1(request_id, &body)? != bytes {
        return Err(PublisherLocalProtocolError::Malformed);
    }
    Ok(PublisherLocalMessageV1 {
        request_id,
        body,
        body_digest: digest,
    })
}

/// Decodes one exact readable-source message from the fixed local carrier.
pub(crate) fn decode_local_source_message_from_carrier_v1(
    bytes: &[u8],
    identity_digest: ObjectDigest,
) -> Result<PublisherLocalMessageV1, PublisherLocalProtocolError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > HEADER_BYTES + MAXIMUM_BODY_BYTES {
        return Err(PublisherLocalProtocolError::LimitExceeded);
    }
    let body_digest = ObjectDigest::from_bytes(exact(&bytes[32..64])?);
    let observed = ObservedDescriptorV1::from_carrier(
        0,
        identity_digest,
        DescriptorAccessV1::ReadableSource,
        body_digest,
    );
    let message = decode_local_message_v1(bytes, &[observed])?;
    if !matches!(&message.body, PublisherLocalBodyV1::PrepareArtifact { .. }) {
        return Err(PublisherLocalProtocolError::DescriptorMismatch);
    }
    Ok(message)
}

/// Decodes one exact immutable-backing response from the fixed local carrier.
///
/// # Errors
///
/// Returns an error for malformed framing, an inexact descriptor observation,
/// or a method other than `OpenFound`.
pub(crate) fn decode_local_backing_message_from_carrier_v1(
    bytes: &[u8],
    identity_digest: ObjectDigest,
) -> Result<PublisherLocalMessageV1, PublisherLocalProtocolError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > HEADER_BYTES + MAXIMUM_BODY_BYTES {
        return Err(PublisherLocalProtocolError::LimitExceeded);
    }
    let body_digest = ObjectDigest::from_bytes(exact(&bytes[32..64])?);
    let observed = ObservedDescriptorV1::from_carrier(
        0,
        identity_digest,
        DescriptorAccessV1::ReadOnlyImmutableBacking,
        body_digest,
    );
    let message = decode_local_message_v1(bytes, &[observed])?;
    if !matches!(&message.body, PublisherLocalBodyV1::OpenFound { .. }) {
        return Err(PublisherLocalProtocolError::DescriptorMismatch);
    }
    Ok(message)
}

fn validate_descriptors(
    body: &PublisherLocalBodyV1,
    body_digest: ObjectDigest,
    observed: &[ObservedDescriptorV1],
) -> Result<(), PublisherLocalProtocolError> {
    match body.descriptor() {
        None if observed.is_empty() => Ok(()),
        Some(expected)
            if observed
                == [ObservedDescriptorV1 {
                    ordinal: expected.ordinal,
                    identity_digest: expected.identity_digest,
                    access: expected.access,
                    body_digest,
                }] =>
        {
            Ok(())
        }
        _ => Err(PublisherLocalProtocolError::DescriptorMismatch),
    }
}

fn encode_body(body: &PublisherLocalBodyV1) -> Result<Vec<u8>, PublisherLocalProtocolError> {
    validate_body(body)?;
    let expected_size = encoded_body_size(body)?;
    let mut bytes = bounded_vec(expected_size)?;
    bytes.extend_from_slice(BODY_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    match body {
        PublisherLocalBodyV1::RegisterChallenge {
            publisher_instance,
            challenge,
            canonical_request,
        } => {
            bytes.extend_from_slice(publisher_instance.as_bytes());
            bytes.extend_from_slice(challenge.as_bytes());
            push_bytes(&mut bytes, canonical_request)?;
        }
        PublisherLocalBodyV1::AdmissionResult {
            operation,
            decision_digest,
            canonical_plan,
            signature,
        } => {
            bytes.extend_from_slice(operation.as_bytes());
            bytes.extend_from_slice(decision_digest.as_bytes());
            push_bytes(&mut bytes, canonical_plan)?;
            push_bytes(&mut bytes, signature)?;
        }
        PublisherLocalBodyV1::PrepareArtifact {
            operation,
            decision_digest,
            source,
        } => {
            bytes.extend_from_slice(operation.as_bytes());
            bytes.extend_from_slice(decision_digest.as_bytes());
            push_descriptor(&mut bytes, *source)?;
        }
        PublisherLocalBodyV1::RequestCompletion {
            operation,
            artifact_digest,
        } => {
            bytes.extend_from_slice(operation.as_bytes());
            bytes.extend_from_slice(artifact_digest.as_bytes());
        }
        PublisherLocalBodyV1::CompletionPermit {
            operation,
            permit,
            permit_digest,
        } => {
            bytes.extend_from_slice(operation.as_bytes());
            bytes.extend_from_slice(permit.as_bytes());
            bytes.extend_from_slice(permit_digest.as_bytes());
        }
        PublisherLocalBodyV1::CommitReceipt {
            operation,
            permit,
            receipt_digest,
        } => {
            bytes.extend_from_slice(operation.as_bytes());
            bytes.extend_from_slice(permit.as_bytes());
            bytes.extend_from_slice(receipt_digest.as_bytes());
        }
        PublisherLocalBodyV1::ObserveRecovery {
            operation,
            decision_digest,
        } => {
            bytes.extend_from_slice(operation.as_bytes());
            bytes.extend_from_slice(decision_digest.as_bytes());
        }
        PublisherLocalBodyV1::RecoveryResult {
            operation,
            disposition,
            observation_digest,
        } => {
            bytes.extend_from_slice(operation.as_bytes());
            bytes.push(disposition_code(*disposition));
            bytes.extend_from_slice(observation_digest.as_bytes());
        }
        PublisherLocalBodyV1::OpenForRead {
            holder,
            project,
            object,
            read_authority_digest,
            catalog_generation,
        } => {
            bytes.extend_from_slice(holder.as_bytes());
            bytes.extend_from_slice(project.as_bytes());
            push_object(&mut bytes, object)?;
            bytes.extend_from_slice(read_authority_digest.as_bytes());
            bytes.extend_from_slice(&catalog_generation.to_be_bytes());
        }
        PublisherLocalBodyV1::OpenFound {
            object,
            catalog_entry_digest,
            backing,
        } => {
            push_object(&mut bytes, object)?;
            bytes.extend_from_slice(catalog_entry_digest.as_bytes());
            push_descriptor(&mut bytes, *backing)?;
        }
        PublisherLocalBodyV1::OpenNotFoundOrConcealed { request_digest } => {
            bytes.extend_from_slice(request_digest.as_bytes())
        }
    }
    if bytes.len() != expected_size || bytes.len() > MAXIMUM_BODY_BYTES {
        return Err(PublisherLocalProtocolError::LimitExceeded);
    }
    Ok(bytes)
}

fn encoded_body_size(body: &PublisherLocalBodyV1) -> Result<usize, PublisherLocalProtocolError> {
    let fields = match body {
        PublisherLocalBodyV1::RegisterChallenge {
            canonical_request, ..
        } => 52_usize.checked_add(canonical_request.len()),
        PublisherLocalBodyV1::AdmissionResult {
            canonical_plan,
            signature,
            ..
        } => 56_usize
            .checked_add(canonical_plan.len())
            .and_then(|size| size.checked_add(signature.len())),
        PublisherLocalBodyV1::PrepareArtifact { .. } => Some(82),
        PublisherLocalBodyV1::RequestCompletion { .. }
        | PublisherLocalBodyV1::ObserveRecovery { .. } => Some(48),
        PublisherLocalBodyV1::CompletionPermit { .. }
        | PublisherLocalBodyV1::CommitReceipt { .. } => Some(64),
        PublisherLocalBodyV1::RecoveryResult { .. } => Some(49),
        PublisherLocalBodyV1::OpenForRead { object, .. } => {
            113_usize.checked_add(object.media_type().as_str().len())
        }
        PublisherLocalBodyV1::OpenFound { object, .. } => {
            107_usize.checked_add(object.media_type().as_str().len())
        }
        PublisherLocalBodyV1::OpenNotFoundOrConcealed { .. } => Some(32),
    }
    .and_then(|size| size.checked_add(10))
    .ok_or(PublisherLocalProtocolError::LimitExceeded)?;
    if fields > MAXIMUM_BODY_BYTES {
        return Err(PublisherLocalProtocolError::LimitExceeded);
    }
    Ok(fields)
}

fn decode_body(
    method: PublisherLocalMethodV1,
    bytes: &[u8],
) -> Result<PublisherLocalBodyV1, PublisherLocalProtocolError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != BODY_MAGIC || cursor.u16()? != VERSION {
        return Err(PublisherLocalProtocolError::Malformed);
    }
    let body = match method {
        PublisherLocalMethodV1::RegisterChallenge => PublisherLocalBodyV1::RegisterChallenge {
            publisher_instance: PublisherInstanceId::from_bytes(cursor.array()?),
            challenge: PublisherChallengeV1::from_bytes(cursor.array()?)
                .map_err(|_| PublisherLocalProtocolError::Malformed)?,
            canonical_request: cursor.length_prefixed()?,
        },
        PublisherLocalMethodV1::AdmissionResult => PublisherLocalBodyV1::AdmissionResult {
            operation: OperationId::from_bytes(cursor.array()?),
            decision_digest: cursor.digest()?,
            canonical_plan: cursor.length_prefixed()?,
            signature: cursor.length_prefixed()?,
        },
        PublisherLocalMethodV1::PrepareArtifact => PublisherLocalBodyV1::PrepareArtifact {
            operation: OperationId::from_bytes(cursor.array()?),
            decision_digest: cursor.digest()?,
            source: cursor.descriptor()?,
        },
        PublisherLocalMethodV1::RequestCompletion => PublisherLocalBodyV1::RequestCompletion {
            operation: OperationId::from_bytes(cursor.array()?),
            artifact_digest: cursor.digest()?,
        },
        PublisherLocalMethodV1::CompletionPermit => PublisherLocalBodyV1::CompletionPermit {
            operation: OperationId::from_bytes(cursor.array()?),
            permit: PublicationPermitId::from_bytes(cursor.array()?)
                .map_err(|_| PublisherLocalProtocolError::Malformed)?,
            permit_digest: cursor.digest()?,
        },
        PublisherLocalMethodV1::CommitReceipt => PublisherLocalBodyV1::CommitReceipt {
            operation: OperationId::from_bytes(cursor.array()?),
            permit: PublicationPermitId::from_bytes(cursor.array()?)
                .map_err(|_| PublisherLocalProtocolError::Malformed)?,
            receipt_digest: cursor.digest()?,
        },
        PublisherLocalMethodV1::ObserveRecovery => PublisherLocalBodyV1::ObserveRecovery {
            operation: OperationId::from_bytes(cursor.array()?),
            decision_digest: cursor.digest()?,
        },
        PublisherLocalMethodV1::RecoveryResult => PublisherLocalBodyV1::RecoveryResult {
            operation: OperationId::from_bytes(cursor.array()?),
            disposition: decode_disposition(cursor.u8()?)?,
            observation_digest: cursor.digest()?,
        },
        PublisherLocalMethodV1::OpenForRead => PublisherLocalBodyV1::OpenForRead {
            holder: PrincipalId::from_bytes(cursor.array()?),
            project: ProjectId::from_bytes(cursor.array()?),
            object: cursor.object()?,
            read_authority_digest: cursor.digest()?,
            catalog_generation: cursor.u64()?,
        },
        PublisherLocalMethodV1::OpenFound => PublisherLocalBodyV1::OpenFound {
            object: cursor.object()?,
            catalog_entry_digest: cursor.digest()?,
            backing: cursor.descriptor()?,
        },
        PublisherLocalMethodV1::OpenNotFoundOrConcealed => {
            PublisherLocalBodyV1::OpenNotFoundOrConcealed {
                request_digest: cursor.digest()?,
            }
        }
    };
    cursor.finish()?;
    validate_body(&body)?;
    Ok(body)
}

fn validate_body(body: &PublisherLocalBodyV1) -> Result<(), PublisherLocalProtocolError> {
    let nonzero = match body {
        PublisherLocalBodyV1::RegisterChallenge {
            publisher_instance,
            challenge,
            canonical_request,
            ..
        } => {
            let decoded =
                decode_publisher_admission_request_v1(canonical_request, Default::default())
                    .map_err(|_| PublisherLocalProtocolError::Malformed)?;
            publisher_instance.as_bytes() != &[0; 16]
                && decoded.plan().fields().target.instance == *publisher_instance
                && decoded.challenge() == *challenge
                && encode_publisher_admission_request_v1(&decoded) == *canonical_request
        }
        PublisherLocalBodyV1::AdmissionResult {
            operation,
            decision_digest,
            canonical_plan,
            signature,
        } => {
            let decoded = decode_publisher_domain_plan(canonical_plan, Default::default())
                .map_err(|_| PublisherLocalProtocolError::Malformed)?;
            operation.as_bytes() != &[0; 16]
                && decision_digest.as_bytes() != &[0; 32]
                && decoded.fields().request.operation == *operation
                && encode_publisher_domain_plan(&decoded) == *canonical_plan
                && !signature.is_empty()
                && signature.len() <= 1024
        }
        PublisherLocalBodyV1::PrepareArtifact {
            operation,
            decision_digest,
            source,
        } => {
            operation.as_bytes() != &[0; 16]
                && decision_digest.as_bytes() != &[0; 32]
                && valid_descriptor(*source, DescriptorAccessV1::ReadableSource)
        }
        PublisherLocalBodyV1::RequestCompletion {
            operation,
            artifact_digest,
        } => operation.as_bytes() != &[0; 16] && artifact_digest.as_bytes() != &[0; 32],
        PublisherLocalBodyV1::CompletionPermit {
            operation,
            permit,
            permit_digest,
        } => {
            operation.as_bytes() != &[0; 16]
                && permit_digest.as_bytes() != &[0; 32]
                && &permit_digest.as_bytes()[..16] == permit.as_bytes()
        }
        PublisherLocalBodyV1::CommitReceipt {
            operation,
            receipt_digest,
            ..
        } => operation.as_bytes() != &[0; 16] && receipt_digest.as_bytes() != &[0; 32],
        PublisherLocalBodyV1::ObserveRecovery {
            operation,
            decision_digest,
        } => operation.as_bytes() != &[0; 16] && decision_digest.as_bytes() != &[0; 32],
        PublisherLocalBodyV1::RecoveryResult {
            operation,
            observation_digest,
            ..
        } => operation.as_bytes() != &[0; 16] && observation_digest.as_bytes() != &[0; 32],
        PublisherLocalBodyV1::OpenForRead {
            holder,
            project,
            object,
            read_authority_digest,
            catalog_generation,
            ..
        } => {
            holder.as_bytes() != &[0; 16]
                && project.as_bytes() != &[0; 16]
                && object.digest().as_bytes() != &[0; 32]
                && read_authority_digest.as_bytes() != &[0; 32]
                && *catalog_generation != 0
        }
        PublisherLocalBodyV1::OpenFound {
            object,
            catalog_entry_digest,
            backing,
            ..
        } => {
            object.digest().as_bytes() != &[0; 32]
                && catalog_entry_digest.as_bytes() != &[0; 32]
                && valid_descriptor(*backing, DescriptorAccessV1::ReadOnlyImmutableBacking)
        }
        PublisherLocalBodyV1::OpenNotFoundOrConcealed { request_digest } => {
            request_digest.as_bytes() != &[0; 32]
        }
    };
    if !nonzero {
        return Err(PublisherLocalProtocolError::Malformed);
    }
    Ok(())
}

fn valid_descriptor(value: DescriptorCommitmentV1, access: DescriptorAccessV1) -> bool {
    value.ordinal == 0 && value.identity_digest.as_bytes() != &[0; 32] && value.access == access
}

fn push_descriptor(
    bytes: &mut Vec<u8>,
    value: DescriptorCommitmentV1,
) -> Result<(), PublisherLocalProtocolError> {
    if !valid_descriptor(value, value.access) {
        return Err(PublisherLocalProtocolError::Malformed);
    }
    bytes.push(value.ordinal);
    bytes.push(value.access as u8);
    bytes.extend_from_slice(value.identity_digest.as_bytes());
    Ok(())
}

fn push_object(
    bytes: &mut Vec<u8>,
    value: &ObjectDescriptor,
) -> Result<(), PublisherLocalProtocolError> {
    let media = value.media_type().as_str().as_bytes();
    let length =
        u8::try_from(media.len()).map_err(|_| PublisherLocalProtocolError::LimitExceeded)?;
    bytes.push(length);
    bytes.extend_from_slice(media);
    bytes.extend_from_slice(value.digest().as_bytes());
    bytes.extend_from_slice(&value.encoded_size().to_be_bytes());
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), PublisherLocalProtocolError> {
    if value.is_empty() || value.len() > MAXIMUM_BODY_BYTES {
        return Err(PublisherLocalProtocolError::LimitExceeded);
    }
    let length =
        u32::try_from(value.len()).map_err(|_| PublisherLocalProtocolError::LimitExceeded)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn disposition_code(value: CompletionDispositionV1) -> u8 {
    match value {
        CompletionDispositionV1::Committed => 1,
        CompletionDispositionV1::AbortedBeforeEffect => 2,
        CompletionDispositionV1::RecoveryRequired => 3,
        CompletionDispositionV1::AuthorityUnavailable => 4,
        CompletionDispositionV1::NotFoundOrConcealed => 5,
    }
}

fn decode_disposition(code: u8) -> Result<CompletionDispositionV1, PublisherLocalProtocolError> {
    Ok(match code {
        1 => CompletionDispositionV1::Committed,
        2 => CompletionDispositionV1::AbortedBeforeEffect,
        3 => CompletionDispositionV1::RecoveryRequired,
        4 => CompletionDispositionV1::AuthorityUnavailable,
        5 => CompletionDispositionV1::NotFoundOrConcealed,
        _ => return Err(PublisherLocalProtocolError::Malformed),
    })
}

fn body_digest(method: PublisherLocalMethodV1, request_id: [u8; 16], body: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(BODY_DOMAIN);
    digest.update([method as u8]);
    digest.update(request_id);
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn bounded_vec(capacity: usize) -> Result<Vec<u8>, PublisherLocalProtocolError> {
    if capacity > HEADER_BYTES + MAXIMUM_BODY_BYTES {
        return Err(PublisherLocalProtocolError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PublisherLocalProtocolError::Allocation)?;
    Ok(bytes)
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PublisherLocalProtocolError> {
    bytes
        .try_into()
        .map_err(|_| PublisherLocalProtocolError::Malformed)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], PublisherLocalProtocolError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(PublisherLocalProtocolError::LimitExceeded)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PublisherLocalProtocolError::Malformed)?;
        self.offset = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], PublisherLocalProtocolError> {
        exact(self.take(N)?)
    }
    fn u8(&mut self) -> Result<u8, PublisherLocalProtocolError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, PublisherLocalProtocolError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, PublisherLocalProtocolError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn digest(&mut self) -> Result<ObjectDigest, PublisherLocalProtocolError> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }
    fn length_prefixed(&mut self) -> Result<Vec<u8>, PublisherLocalProtocolError> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| PublisherLocalProtocolError::LimitExceeded)?;
        if length == 0 || length > MAXIMUM_BODY_BYTES {
            return Err(PublisherLocalProtocolError::LimitExceeded);
        }
        let value = self.take(length)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(length)
            .map_err(|_| PublisherLocalProtocolError::Allocation)?;
        owned.extend_from_slice(value);
        Ok(owned)
    }
    fn descriptor(&mut self) -> Result<DescriptorCommitmentV1, PublisherLocalProtocolError> {
        let ordinal = self.u8()?;
        let access = match self.u8()? {
            1 => DescriptorAccessV1::ReadableSource,
            2 => DescriptorAccessV1::ReadOnlyImmutableBacking,
            _ => return Err(PublisherLocalProtocolError::Malformed),
        };
        Ok(DescriptorCommitmentV1 {
            ordinal,
            access,
            identity_digest: self.digest()?,
        })
    }
    fn object(&mut self) -> Result<ObjectDescriptor, PublisherLocalProtocolError> {
        let length = usize::from(self.u8()?);
        let media = std::str::from_utf8(self.take(length)?)
            .map_err(|_| PublisherLocalProtocolError::Malformed)?;
        let media =
            MediaType::new(media.to_owned()).map_err(|_| PublisherLocalProtocolError::Malformed)?;
        let digest = self.digest()?;
        let size = self.u64()?;
        Ok(ObjectDescriptor::new(media, digest, size))
    }
    fn finish(self) -> Result<(), PublisherLocalProtocolError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PublisherLocalProtocolError::Malformed)
        }
    }
}

/// Closed completion and concealment dispositions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDispositionV1 {
    /// Exact operation committed or replayed.
    Committed,
    /// No physical effect began.
    AbortedBeforeEffect,
    /// Observation-only recovery remains required.
    RecoveryRequired,
    /// Protected authority is unavailable.
    AuthorityUnavailable,
    /// Absence and concealment share one result.
    NotFoundOrConcealed,
}

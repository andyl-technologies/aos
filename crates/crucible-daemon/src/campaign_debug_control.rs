//! Authenticated operational control for campaign-owned debug sessions.
//!
//! This protocol binds one campaign snapshot and finding to a daemon-owned
//! exact checkpoint selection. It carries no checkpoint bytes or temporary
//! artifact paths; the repository and exact-store owners remain in process.

use crucible::ContentHash;
use crucible_api::{SessionId, SessionRef};
use crucible_campaign::{
    CampaignHash, CampaignName, CampaignPrincipal, CampaignServiceFailure, CampaignSnapshotId,
    ExactCheckpointId, FindingId, GetCampaignFindingObjectRequest,
    GetCampaignFindingObjectResponse,
};
use thiserror::Error;

const SCHEMA_VERSION: u32 = 1;
const REQUEST_DIGEST_DOMAIN: &str = "crucible.campaign.debug-session-request.v1";
const MAX_MESSAGE_BYTES: usize = 8 * 1024;
const RESPONSE_FIXED_BYTES: usize = 122;

/// Owner-side service that opens one exclusive campaign debug session.
pub trait CampaignDebugControlService: Send + Sync {
    /// Opens or exactly replays one authenticated read-only debug allocation.
    ///
    /// # Errors
    ///
    /// Returns a stable campaign-service failure after transport authorization
    /// and finding-proof authentication have completed.
    fn open_campaign_debug_session(
        &self,
        request: &OpenCampaignDebugSessionRequest,
        finding: GetCampaignFindingObjectResponse,
    ) -> Result<OpenCampaignDebugSessionResponse, CampaignServiceFailure>;
}

#[cfg(test)]
mod tests {
    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;

    #[test]
    fn current_debug_messages_round_trip_and_bind_the_exact_request() {
        let alpha_request = request("alpha");
        let response = response(&alpha_request);

        assert_eq!(
            OpenCampaignDebugSessionRequest::from_canonical_bytes(&alpha_request.canonical_bytes()),
            Ok(alpha_request.clone())
        );
        assert_eq!(
            OpenCampaignDebugSessionResponse::from_canonical_bytes(&response.canonical_bytes()),
            Ok(response.clone())
        );
        assert_eq!(response.validate_for(&alpha_request), Ok(()));
        assert_eq!(
            response.validate_for(&request("beta")),
            Err(CampaignDebugControlCodecError::ResponseMismatch)
        );
        assert!(response.read_only());
    }

    #[test]
    fn debug_response_rejects_mutable_and_trailing_encodings() {
        let response = response(&request("strict"));
        let mut mutable = response.canonical_bytes();
        let last = mutable.len().saturating_sub(1);
        mutable[last] = 0;
        assert_eq!(
            OpenCampaignDebugSessionResponse::from_canonical_bytes(&mutable),
            Err(CampaignDebugControlCodecError::NotReadOnly)
        );

        let mut trailing = response.canonical_bytes();
        trailing.push(0);
        assert_eq!(
            OpenCampaignDebugSessionResponse::from_canonical_bytes(&trailing),
            Err(CampaignDebugControlCodecError::TrailingBytes)
        );
    }

    fn response(request: &OpenCampaignDebugSessionRequest) -> OpenCampaignDebugSessionResponse {
        let checkpoint = ExactCheckpointId::parse(&format!(
            "crucible.executor.exact-checkpoint-root@exact-manifest.4.{}",
            hex([0x31; 32])
        ))
        .unwrap_or_else(|error| panic!("checkpoint identity should parse: {error}"));
        OpenCampaignDebugSessionResponse::new(
            request,
            checkpoint,
            CampaignDebugCheckpointRole::PostFailure,
            ContentHash { bytes: [0x41; 32] },
            SessionRef::new(SessionId::new(7), 3, crucible::Seed::from_bytes([0x51; 32])),
        )
        .unwrap_or_else(|error| panic!("response should encode: {error}"))
    }

    fn request(label: &str) -> OpenCampaignDebugSessionRequest {
        let snapshot_content =
            ContentId::for_bytes(ObjectKind::CampaignSnapshot, 3, label.as_bytes());
        let finding_content = ContentId::for_bytes(ObjectKind::Finding, 4, label.as_bytes());
        OpenCampaignDebugSessionRequest::new(
            CampaignPrincipal::new("debugger")
                .unwrap_or_else(|error| panic!("principal should parse: {error}")),
            CampaignName::new("campaign")
                .unwrap_or_else(|error| panic!("campaign should parse: {error}")),
            CampaignSnapshotId::parse(&format!(
                "crucible.campaign.snapshot@{}",
                snapshot_content.encode()
            ))
            .unwrap_or_else(|error| panic!("snapshot should parse: {error}")),
            FindingId::parse(&format!("crucible.campaign.finding@{finding_content}"))
                .unwrap_or_else(|error| panic!("finding should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("request should encode: {error}"))
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Canonical request for a snapshot-bound campaign debug session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenCampaignDebugSessionRequest {
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    finding: FindingId,
    principal_length: u32,
    campaign_length: u32,
    snapshot_text: String,
    snapshot_length: u32,
    finding_text: String,
    finding_length: u32,
}

impl OpenCampaignDebugSessionRequest {
    /// Builds one exact campaign debug request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignDebugControlCodecError::Oversized`] when a component
    /// cannot be represented by the bounded current protocol.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        finding: FindingId,
    ) -> Result<Self, CampaignDebugControlCodecError> {
        let snapshot_text = snapshot.to_text();
        let finding_text = finding.to_text();
        let principal_length = bounded_text_length(principal.as_str())?;
        let campaign_length = bounded_text_length(campaign.as_str())?;
        let snapshot_length = bounded_text_length(&snapshot_text)?;
        let finding_length = bounded_text_length(&finding_text)?;
        let request = Self {
            principal,
            campaign,
            snapshot,
            finding,
            principal_length,
            campaign_length,
            snapshot_text,
            snapshot_length,
            finding_text,
            finding_length,
        };
        ensure_size(&request.canonical_bytes())?;
        Ok(request)
    }

    /// Returns the authenticated request principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the selected campaign.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact historical snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the finding authenticated at the snapshot.
    #[must_use]
    pub const fn finding(&self) -> FindingId {
        self.finding
    }

    /// Returns the digest of the complete canonical request tuple.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(REQUEST_DIGEST_DOMAIN, &self.canonical_bytes())
    }

    pub(crate) fn finding_object_request(
        &self,
    ) -> Result<GetCampaignFindingObjectRequest, CampaignDebugControlCodecError> {
        GetCampaignFindingObjectRequest::new(
            self.principal.clone(),
            self.campaign.clone(),
            self.snapshot,
            self.finding,
            crucible_campaign::CampaignFindingObjectKind::Reproduction,
        )
        .map_err(|_| CampaignDebugControlCodecError::InvalidIdentity)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        put_u32(&mut bytes, SCHEMA_VERSION);
        put_bounded_text(&mut bytes, self.principal.as_str(), self.principal_length);
        put_bounded_text(&mut bytes, self.campaign.as_str(), self.campaign_length);
        put_bounded_text(&mut bytes, &self.snapshot_text, self.snapshot_length);
        put_bounded_text(&mut bytes, &self.finding_text, self.finding_length);
        bytes
    }

    /// Decodes one strict current campaign debug request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignDebugControlCodecError`] for malformed, unsupported,
    /// oversized, trailing, or noncanonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignDebugControlCodecError> {
        ensure_size(bytes)?;
        let mut decoder = Decoder::new(bytes);
        decoder.require_version()?;
        let principal = CampaignPrincipal::new(decoder.text()?)
            .map_err(|_| CampaignDebugControlCodecError::InvalidIdentity)?;
        let campaign = CampaignName::new(decoder.text()?)
            .map_err(|_| CampaignDebugControlCodecError::InvalidIdentity)?;
        let snapshot = CampaignSnapshotId::parse(&decoder.text()?)
            .map_err(|_| CampaignDebugControlCodecError::InvalidIdentity)?;
        let finding = FindingId::parse(&decoder.text()?)
            .map_err(|_| CampaignDebugControlCodecError::InvalidIdentity)?;
        decoder.finish()?;
        let request = Self::new(principal, campaign, snapshot, finding)?;
        if request.canonical_bytes() != bytes {
            return Err(CampaignDebugControlCodecError::Noncanonical);
        }
        Ok(request)
    }
}

/// Exact finding checkpoint role selected by the daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignDebugCheckpointRole {
    /// Safest exact state captured immediately after failure.
    PostFailure,
    /// Exact state immediately before the failure window.
    PreFailure,
    /// Exact measurement boundary retained by the finding.
    MeasurementBoundary,
    /// Additional exact state retained by finding policy.
    Additional,
}

impl CampaignDebugCheckpointRole {
    const fn tag(self) -> u8 {
        match self {
            Self::PostFailure => 1,
            Self::PreFailure => 2,
            Self::MeasurementBoundary => 3,
            Self::Additional => 4,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, CampaignDebugControlCodecError> {
        match tag {
            1 => Ok(Self::PostFailure),
            2 => Ok(Self::PreFailure),
            3 => Ok(Self::MeasurementBoundary),
            4 => Ok(Self::Additional),
            _ => Err(CampaignDebugControlCodecError::InvalidRole),
        }
    }
}

/// Stable result of one exclusive read-only campaign debug allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenCampaignDebugSessionResponse {
    request_digest: CampaignHash,
    checkpoint: ExactCheckpointId,
    role: CampaignDebugCheckpointRole,
    configuration: ContentHash,
    session: SessionRef,
    checkpoint_text: String,
    checkpoint_length: u32,
}

impl OpenCampaignDebugSessionResponse {
    /// Builds a request-bound campaign debug response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignDebugControlCodecError::Oversized`] when the exact
    /// checkpoint identity cannot be represented by the bounded protocol.
    pub fn new(
        request: &OpenCampaignDebugSessionRequest,
        checkpoint: ExactCheckpointId,
        role: CampaignDebugCheckpointRole,
        configuration: ContentHash,
        session: SessionRef,
    ) -> Result<Self, CampaignDebugControlCodecError> {
        Ok(CampaignDebugResponseEncoding::prepare(checkpoint)?.finish(
            request,
            role,
            configuration,
            session,
        ))
    }

    pub(crate) fn prepare_encoding(
        checkpoint: ExactCheckpointId,
    ) -> Result<CampaignDebugResponseEncoding, CampaignDebugControlCodecError> {
        CampaignDebugResponseEncoding::prepare(checkpoint)
    }

    fn from_encoding(
        request_digest: CampaignHash,
        encoding: CampaignDebugResponseEncoding,
        role: CampaignDebugCheckpointRole,
        configuration: ContentHash,
        session: SessionRef,
    ) -> Self {
        Self {
            request_digest,
            checkpoint: encoding.checkpoint,
            role,
            configuration,
            session,
            checkpoint_text: encoding.checkpoint_text,
            checkpoint_length: encoding.checkpoint_length,
        }
    }

    /// Returns the selected exact checkpoint.
    #[must_use]
    pub const fn checkpoint(&self) -> ExactCheckpointId {
        self.checkpoint
    }

    /// Returns the selected finding pin role.
    #[must_use]
    pub const fn role(&self) -> CampaignDebugCheckpointRole {
        self.role
    }

    /// Returns the exact restored configuration.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }

    /// Returns the lifecycle session served by the existing debug relay.
    #[must_use]
    pub const fn session(&self) -> SessionRef {
        self.session
    }

    /// Returns whether canonical mutation is owner-enforced as disabled.
    #[must_use]
    pub const fn read_only(&self) -> bool {
        true
    }

    /// Validates this response against the complete request tuple.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignDebugControlCodecError::ResponseMismatch`] when the
    /// response belongs to another request.
    pub fn validate_for(
        &self,
        request: &OpenCampaignDebugSessionRequest,
    ) -> Result<(), CampaignDebugControlCodecError> {
        if self.request_digest != request.request_digest() {
            return Err(CampaignDebugControlCodecError::ResponseMismatch);
        }
        Ok(())
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        put_u32(&mut bytes, SCHEMA_VERSION);
        bytes.extend_from_slice(&self.request_digest.as_bytes());
        put_bounded_text(&mut bytes, &self.checkpoint_text, self.checkpoint_length);
        bytes.push(self.role.tag());
        bytes.extend_from_slice(&self.configuration.bytes);
        put_u64(&mut bytes, self.session.id.value);
        put_u64(&mut bytes, self.session.epoch);
        bytes.extend_from_slice(&self.session.seed.bytes());
        bytes.push(1);
        bytes
    }

    /// Decodes one strict current campaign debug response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignDebugControlCodecError`] for malformed, unsupported,
    /// oversized, trailing, or noncanonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignDebugControlCodecError> {
        ensure_size(bytes)?;
        let mut decoder = Decoder::new(bytes);
        decoder.require_version()?;
        let request_digest = CampaignHash::from_bytes(decoder.fixed()?);
        let checkpoint = ExactCheckpointId::parse(&decoder.text()?)
            .map_err(|_| CampaignDebugControlCodecError::InvalidIdentity)?;
        let role = CampaignDebugCheckpointRole::from_tag(decoder.byte()?)?;
        let configuration = ContentHash {
            bytes: decoder.fixed()?,
        };
        let session = SessionRef::new(
            SessionId::new(decoder.u64()?),
            decoder.u64()?,
            crucible::Seed::from_bytes(decoder.fixed()?),
        );
        if decoder.byte()? != 1 {
            return Err(CampaignDebugControlCodecError::NotReadOnly);
        }
        decoder.finish()?;
        let response = Self::from_encoding(
            request_digest,
            CampaignDebugResponseEncoding::prepare(checkpoint)?,
            role,
            configuration,
            session,
        );
        if response.canonical_bytes() != bytes {
            return Err(CampaignDebugControlCodecError::Noncanonical);
        }
        Ok(response)
    }
}

pub(crate) struct CampaignDebugResponseEncoding {
    checkpoint: ExactCheckpointId,
    checkpoint_text: String,
    checkpoint_length: u32,
}

impl CampaignDebugResponseEncoding {
    fn prepare(checkpoint: ExactCheckpointId) -> Result<Self, CampaignDebugControlCodecError> {
        let checkpoint_text = checkpoint.to_text();
        let checkpoint_length = bounded_text_length(&checkpoint_text)?;
        let encoded_length = RESPONSE_FIXED_BYTES
            .checked_add(checkpoint_text.len())
            .ok_or(CampaignDebugControlCodecError::Oversized)?;
        if encoded_length > MAX_MESSAGE_BYTES {
            return Err(CampaignDebugControlCodecError::Oversized);
        }
        Ok(Self {
            checkpoint,
            checkpoint_text,
            checkpoint_length,
        })
    }

    pub(crate) fn finish(
        self,
        request: &OpenCampaignDebugSessionRequest,
        role: CampaignDebugCheckpointRole,
        configuration: ContentHash,
        session: SessionRef,
    ) -> OpenCampaignDebugSessionResponse {
        OpenCampaignDebugSessionResponse::from_encoding(
            request.request_digest(),
            self,
            role,
            configuration,
            session,
        )
    }
}

/// Strict current campaign debug-control codec failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CampaignDebugControlCodecError {
    /// The message exceeds its fixed byte ceiling.
    #[error("campaign debug control message exceeds its byte bound")]
    Oversized,
    /// The message ended before a complete field.
    #[error("campaign debug control message is truncated")]
    Truncated,
    /// The schema version is not current.
    #[error("campaign debug control message version is unsupported")]
    UnsupportedVersion,
    /// Bytes remain after the complete message.
    #[error("campaign debug control message has trailing bytes")]
    TrailingBytes,
    /// A bounded field length is invalid.
    #[error("campaign debug control field length is invalid")]
    InvalidLength,
    /// A principal or typed content identity is invalid.
    #[error("campaign debug control identity is invalid")]
    InvalidIdentity,
    /// The checkpoint role is outside the closed current set.
    #[error("campaign debug checkpoint role is invalid")]
    InvalidRole,
    /// A response did not preserve the mandatory read-only contract.
    #[error("campaign debug response is not read-only")]
    NotReadOnly,
    /// A response belongs to another request.
    #[error("campaign debug response does not match its request")]
    ResponseMismatch,
    /// The decoded value has a different canonical representation.
    #[error("campaign debug control message is not canonical")]
    Noncanonical,
}

fn ensure_size(bytes: &[u8]) -> Result<(), CampaignDebugControlCodecError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        Err(CampaignDebugControlCodecError::Oversized)
    } else {
        Ok(())
    }
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn bounded_text_length(value: &str) -> Result<u32, CampaignDebugControlCodecError> {
    let length =
        u32::try_from(value.len()).map_err(|_| CampaignDebugControlCodecError::Oversized)?;
    if value.len() > MAX_MESSAGE_BYTES {
        return Err(CampaignDebugControlCodecError::Oversized);
    }
    Ok(length)
}

fn put_bounded_text(output: &mut Vec<u8>, value: &str, length: u32) {
    put_u32(output, length);
    output.extend_from_slice(value.as_bytes());
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn require_version(&mut self) -> Result<(), CampaignDebugControlCodecError> {
        if self.u32()? == SCHEMA_VERSION {
            Ok(())
        } else {
            Err(CampaignDebugControlCodecError::UnsupportedVersion)
        }
    }

    fn byte(&mut self) -> Result<u8, CampaignDebugControlCodecError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(CampaignDebugControlCodecError::Truncated)?;
        self.offset += 1;
        Ok(byte)
    }

    fn u32(&mut self) -> Result<u32, CampaignDebugControlCodecError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, CampaignDebugControlCodecError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CampaignDebugControlCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(CampaignDebugControlCodecError::InvalidLength)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(CampaignDebugControlCodecError::Truncated)?;
        let mut output = [0; N];
        output.copy_from_slice(source);
        self.offset = end;
        Ok(output)
    }

    fn text(&mut self) -> Result<String, CampaignDebugControlCodecError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| CampaignDebugControlCodecError::InvalidLength)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CampaignDebugControlCodecError::InvalidLength)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(CampaignDebugControlCodecError::InvalidLength)?;
        self.offset = end;
        String::from_utf8(bytes.to_vec()).map_err(|_| CampaignDebugControlCodecError::Noncanonical)
    }

    fn finish(self) -> Result<(), CampaignDebugControlCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CampaignDebugControlCodecError::TrailingBytes)
        }
    }
}

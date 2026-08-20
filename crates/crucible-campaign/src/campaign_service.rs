//! Principal-aware user-facing campaign service contracts.
//!
//! This module owns strict canonical messages for the first repository-backed
//! `CampaignService` operations. The service boundary authenticates an
//! operational principal before invoking the existing semantic repository
//! owner. Principal identity and authorization decisions remain operational:
//! neither enters immutable campaign facts or content identities.

use crucible_cas::content_store::RefName;
use thiserror::Error;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    BranchRequest, BranchRequestResult, CampaignCodecError, CampaignCommandResult, CampaignHash,
    CampaignLineageId, CampaignPolicyId, CampaignRepository, CampaignRepositoryError,
    CampaignSnapshotId, CampaignState, ControlRequest,
};

const CAMPAIGN_SERVICE_SCHEMA_VERSION: u32 = 1;

/// Maximum canonical bytes accepted for one campaign-service message.
pub const MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Authenticated operational principal presented to `CampaignService`.
///
/// The identifier is transport-derived and deliberately absent from campaign
/// semantic objects. It uses the repository's portable identifier alphabet so
/// direct and future RPC adapters compare the same canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignPrincipal(String);

impl CampaignPrincipal {
    /// Creates a bounded canonical principal identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the identifier is empty, oversized,
    /// or contains a character outside the portable identifier alphabet.
    pub fn new(value: impl Into<String>) -> Result<Self, CampaignCodecError> {
        let value = value.into();
        validate_identifier(&value, "campaign service principal is invalid")?;
        Ok(Self(value))
    }

    /// Returns the canonical principal identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Canonical for CampaignPrincipal {
    fn encode(&self, encoder: &mut Encoder) {
        self.0.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(decoder.string_bounded(MAX_IDENTIFIER_BYTES, "campaign-service-principal-bytes")?)
    }
}

/// Canonical user-facing campaign name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignName(String);

impl CampaignName {
    /// Creates a bounded portable campaign name.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the name is empty, oversized, or
    /// contains a character outside the portable identifier alphabet.
    pub fn new(value: impl Into<String>) -> Result<Self, CampaignCodecError> {
        let value = value.into();
        if value.len() > MAX_IDENTIFIER_BYTES || RefName::new(format!("campaigns/{value}")).is_err()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign service name is invalid",
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical campaign name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Canonical for CampaignName {
    fn encode(&self, encoder: &mut Encoder) {
        self.0.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(decoder.string_bounded(MAX_IDENTIFIER_BYTES, "campaign-service-name-bytes")?)
    }
}

/// Closed authorization operation presented to a campaign principal policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CampaignServiceOperation {
    /// Read the authenticated current campaign head and lifecycle state.
    GetCampaign,
    /// Apply one idempotent lifecycle, budget, or policy command.
    ApplyCampaignCommand,
    /// Submit one additive operator branch request.
    SubmitBranchRequest,
}

/// Stable fail-closed authorization failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CampaignAuthorizationError {
    /// The authenticated principal lacks the requested capability.
    #[error("campaign service principal is not authorized")]
    Unauthorized,
    /// The authorization backend could not make a definitive decision.
    #[error("campaign service authorization is unavailable")]
    Unavailable,
}

/// Principal policy required by the repository-backed campaign adapter.
pub trait CampaignPrincipalAuthorizer {
    /// Authenticates and authorizes one exact principal and request digest.
    ///
    /// A direct adapter may close over an already-authenticated caller
    /// capability. A transport adapter may verify a peer credential or keyed
    /// request proof. Checking only the self-asserted principal text is not a
    /// conforming production implementation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignAuthorizationError`] on denial or when authorization
    /// cannot be decided. Both outcomes fail before repository access.
    fn authorize(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        campaign: &CampaignName,
        request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError>;
}

/// Strict request for the current authenticated campaign description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
}

impl GetCampaignRequest {
    /// Builds a bounded request for one named campaign.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the encoded message exceeds the
    /// campaign-service bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
        };
        ensure_message_size(&request, "get-campaign-request-encoded-bytes")?;
        Ok(request)
    }

    /// Returns the authenticated operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the canonical campaign name.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("get-campaign", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, unsupported,
    /// or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-request-encoded-bytes")
    }
}

impl Canonical for GetCampaignRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
        )
    }
}

/// Request-bound current campaign description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCampaignResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot: CampaignSnapshotId,
    lineage: CampaignLineageId,
    policy: CampaignPolicyId,
    state: CampaignState,
}

impl GetCampaignResponse {
    /// Builds a response bound to one exact request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the encoded response exceeds the
    /// campaign-service bound.
    pub fn new(
        request: &GetCampaignRequest,
        snapshot: CampaignSnapshotId,
        lineage: CampaignLineageId,
        policy: CampaignPolicyId,
        state: CampaignState,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot,
            lineage,
            policy,
            state,
        };
        ensure_message_size(&response, "get-campaign-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the authoritative current snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the current snapshot's immutable lineage.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the policy active for future work.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the projected durable lifecycle state.
    #[must_use]
    pub const fn state(&self) -> CampaignState {
        self.state
    }

    /// Validates exact request binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// canonical request.
    pub fn validate_for(&self, request: &GetCampaignRequest) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, unsupported,
    /// or oversized input. Exact request validation remains required.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "get-campaign-response-encoded-bytes")
    }
}

impl Canonical for GetCampaignResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot.encode(encoder);
        self.lineage.encode(encoder);
        self.policy.encode(encoder);
        self.state.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot: CampaignSnapshotId::decode(decoder)?,
            lineage: CampaignLineageId::decode(decoder)?,
            policy: CampaignPolicyId::decode(decoder)?,
            state: CampaignState::decode(decoder)?,
        };
        ensure_message_size(&response, "get-campaign-response-encoded-bytes")?;
        Ok(response)
    }
}

/// Strict request for one idempotent campaign control transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyCampaignCommandRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    command: ControlRequest,
}

impl ApplyCampaignCommandRequest {
    /// Builds one principal-bound control request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the encoded request exceeds the
    /// campaign-service bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        command: ControlRequest,
    ) -> Result<Self, CampaignCodecError> {
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            command,
        };
        ensure_message_size(&request, "apply-campaign-command-request-encoded-bytes")?;
        Ok(request)
    }

    /// Returns the authenticated operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the canonical campaign name.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact semantic command envelope.
    #[must_use]
    pub const fn command(&self) -> &ControlRequest {
        &self.command
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("apply-campaign-command", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, unsupported,
    /// or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "apply-campaign-command-request-encoded-bytes")
    }
}

impl Canonical for ApplyCampaignCommandRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.command.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            ControlRequest::decode(decoder)?,
        )
    }
}

/// Strict request for one additive operator branch source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitCampaignBranchRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    expected_snapshot: CampaignSnapshotId,
    request: BranchRequest,
}

impl SubmitCampaignBranchRequest {
    /// Builds one principal-bound branch submission.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the encoded request exceeds the
    /// campaign-service bound.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        expected_snapshot: CampaignSnapshotId,
        request: BranchRequest,
    ) -> Result<Self, CampaignCodecError> {
        let submission = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            expected_snapshot,
            request,
        };
        ensure_message_size(&submission, "submit-campaign-branch-request-encoded-bytes")?;
        Ok(submission)
    }

    /// Returns the authenticated operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the canonical campaign name.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact snapshot precondition.
    #[must_use]
    pub const fn expected_snapshot(&self) -> CampaignSnapshotId {
        self.expected_snapshot
    }

    /// Returns the immutable additive branch request.
    #[must_use]
    pub const fn request(&self) -> &BranchRequest {
        &self.request
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("submit-branch-request", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, unsupported,
    /// or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "submit-campaign-branch-request-encoded-bytes")
    }
}

impl Canonical for SubmitCampaignBranchRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.request.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            BranchRequest::decode(decoder)?,
        )
    }
}

/// Request-bound result of one accepted campaign control command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyCampaignCommandResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    prior_snapshot: CampaignSnapshotId,
    new_snapshot: CampaignSnapshotId,
    replayed: bool,
}

impl ApplyCampaignCommandResponse {
    /// Builds a response from the semantic repository result.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the result's prior snapshot differs
    /// from the command precondition or the encoded response exceeds the
    /// campaign-service bound.
    pub fn new(
        request: &ApplyCampaignCommandRequest,
        result: CampaignCommandResult,
    ) -> Result<Self, CampaignCodecError> {
        if result.prior_snapshot != request.command.expected_snapshot {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign command response prior snapshot mismatch",
            });
        }
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            prior_snapshot: result.prior_snapshot,
            new_snapshot: result.new_snapshot,
            replayed: result.replayed,
        };
        ensure_message_size(&response, "apply-campaign-command-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the snapshot named by the command precondition.
    #[must_use]
    pub const fn prior_snapshot(&self) -> CampaignSnapshotId {
        self.prior_snapshot
    }

    /// Returns the snapshot first produced by the command.
    #[must_use]
    pub const fn new_snapshot(&self) -> CampaignSnapshotId {
        self.new_snapshot
    }

    /// Returns whether the service observed an idempotent replay.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    /// Validates exact request binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// canonical request.
    pub fn validate_for(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        if self.prior_snapshot == request.command.expected_snapshot {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "campaign command response prior snapshot mismatch",
            })
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, unsupported,
    /// or oversized input. Exact request validation remains required.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "apply-campaign-command-response-encoded-bytes")
    }
}

impl Canonical for ApplyCampaignCommandResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.prior_snapshot.encode(encoder);
        self.new_snapshot.encode(encoder);
        self.replayed.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            prior_snapshot: CampaignSnapshotId::decode(decoder)?,
            new_snapshot: CampaignSnapshotId::decode(decoder)?,
            replayed: bool::decode(decoder)?,
        };
        ensure_message_size(&response, "apply-campaign-command-response-encoded-bytes")?;
        Ok(response)
    }
}

/// Request-bound result of one accepted operator branch request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitCampaignBranchResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    prior_snapshot: CampaignSnapshotId,
    new_snapshot: CampaignSnapshotId,
    request: crate::BranchRequestId,
    replayed: bool,
}

impl SubmitCampaignBranchResponse {
    /// Builds a response from the semantic repository result.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the repository result does not name
    /// the submitted request or the encoded response exceeds its bound.
    pub fn new(
        request: &SubmitCampaignBranchRequest,
        result: BranchRequestResult,
    ) -> Result<Self, CampaignCodecError> {
        if result.request != request.request.id()? {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign branch response names another request",
            });
        }
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            prior_snapshot: result.prior_snapshot,
            new_snapshot: result.new_snapshot,
            request: result.request,
            replayed: result.replayed,
        };
        ensure_message_size(&response, "submit-campaign-branch-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the snapshot that first accepted the immutable request.
    #[must_use]
    pub const fn prior_snapshot(&self) -> CampaignSnapshotId {
        self.prior_snapshot
    }

    /// Returns the snapshot first produced by accepting the request.
    #[must_use]
    pub const fn new_snapshot(&self) -> CampaignSnapshotId {
        self.new_snapshot
    }

    /// Returns the exact immutable branch request identity.
    #[must_use]
    pub const fn request(&self) -> crate::BranchRequestId {
        self.request
    }

    /// Returns whether the service observed an idempotent replay.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    /// Validates exact request binding and request identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// canonical request.
    pub fn validate_for(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        if self.request == request.request.id()? {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "campaign branch response names another request",
            })
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, unsupported,
    /// or oversized input. Exact request validation remains required.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "submit-campaign-branch-response-encoded-bytes")
    }
}

impl Canonical for SubmitCampaignBranchResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.prior_snapshot.encode(encoder);
        self.new_snapshot.encode(encoder);
        self.request.encode(encoder);
        self.replayed.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            prior_snapshot: CampaignSnapshotId::decode(decoder)?,
            new_snapshot: CampaignSnapshotId::decode(decoder)?,
            request: crate::BranchRequestId::decode(decoder)?,
            replayed: bool::decode(decoder)?,
        };
        ensure_message_size(&response, "submit-campaign-branch-response-encoded-bytes")?;
        Ok(response)
    }
}

/// Initial user-facing campaign service implemented by direct and RPC adapters.
pub trait CampaignService {
    /// Implementation-specific operational failure.
    type Error;

    /// Returns the authenticated current campaign description.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// repository access, or response construction fails.
    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error>;

    /// Applies one exact idempotent campaign command.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// semantic validation, publication, or response construction fails.
    fn apply_campaign_command(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error>;

    /// Submits one exact additive operator branch request.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// semantic validation, publication, or response construction fails.
    fn submit_branch_request(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error>;
}

/// Failure from the checked campaign-service client.
#[derive(Debug, Error)]
pub enum CampaignClientError<E> {
    /// The service implementation failed.
    #[error("campaign service failed")]
    Service(#[source] E),
    /// A response did not match the exact request.
    #[error("campaign service response validation failed: {0}")]
    InvalidResponse(#[from] CampaignCodecError),
}

/// Checked direct/RPC client that enforces exact response binding.
pub struct CampaignClient<S> {
    service: S,
}

impl<S> CampaignClient<S>
where
    S: CampaignService,
{
    /// Creates a checked client over one service adapter.
    #[must_use]
    pub const fn new(service: S) -> Self {
        Self { service }
    }

    /// Gets one campaign and validates exact response binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request.
    pub fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, CampaignClientError<S::Error>> {
        let response = self
            .service
            .get_campaign(request)
            .map_err(CampaignClientError::Service)?;
        response.validate_for(request)?;
        Ok(response)
    }

    /// Applies one command and validates exact response binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request.
    pub fn apply_campaign_command(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, CampaignClientError<S::Error>> {
        let response = self
            .service
            .apply_campaign_command(request)
            .map_err(CampaignClientError::Service)?;
        response.validate_for(request)?;
        Ok(response)
    }

    /// Submits one branch request and validates exact response binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request.
    pub fn submit_branch_request(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, CampaignClientError<S::Error>> {
        let response = self
            .service
            .submit_branch_request(request)
            .map_err(CampaignClientError::Service)?;
        response.validate_for(request)?;
        Ok(response)
    }

    /// Returns the wrapped service adapter.
    #[must_use]
    pub const fn service(&self) -> &S {
        &self.service
    }
}

/// Error from the repository-backed campaign-service adapter.
#[derive(Debug, Error)]
pub enum RepositoryCampaignServiceError {
    /// Principal authorization denied or was unavailable.
    #[error(transparent)]
    Authorization(#[from] CampaignAuthorizationError),
    /// The semantic repository owner rejected the operation.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Response construction or binding failed.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
}

/// Principal-aware direct adapter over the semantic campaign repository owner.
pub struct RepositoryCampaignService<'a, A> {
    repository: &'a CampaignRepository,
    authorizer: A,
}

impl<'a, A> RepositoryCampaignService<'a, A> {
    /// Creates a direct service with mandatory principal authorization.
    #[must_use]
    pub const fn new(repository: &'a CampaignRepository, authorizer: A) -> Self {
        Self {
            repository,
            authorizer,
        }
    }
}

impl<A> CampaignService for RepositoryCampaignService<'_, A>
where
    A: CampaignPrincipalAuthorizer,
{
    type Error = RepositoryCampaignServiceError;

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaign,
            request.campaign(),
            request.request_digest(),
        )?;
        let (head, state) = self
            .repository
            .head_with_state(request.campaign().as_str())?;
        Ok(GetCampaignResponse::new(
            request,
            head.snapshot_id(),
            head.snapshot().lineage(),
            head.snapshot().active_policy(),
            state,
        )?)
    }

    fn apply_campaign_command(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::ApplyCampaignCommand,
            request.campaign(),
            request.request_digest(),
        )?;
        let result = self
            .repository
            .apply_control(request.campaign().as_str(), request.command())?;
        Ok(ApplyCampaignCommandResponse::new(request, result)?)
    }

    fn submit_branch_request(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::SubmitBranchRequest,
            request.campaign(),
            request.request_digest(),
        )?;
        let result = self.repository.submit_operator_branch_request(
            request.campaign().as_str(),
            request.expected_snapshot(),
            request.request(),
        )?;
        Ok(SubmitCampaignBranchResponse::new(request, result)?)
    }
}

fn service_request_digest(domain: &str, value: &impl Canonical) -> CampaignHash {
    CampaignHash::derive(
        &format!("crucible.campaign-service.{domain}.v1"),
        &codec::encode(value),
    )
}

fn validate_request_digest(
    actual: CampaignHash,
    expected: CampaignHash,
) -> Result<(), CampaignCodecError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "campaign service response request digest mismatch",
        })
    }
}

fn ensure_message_size(
    value: &impl Canonical,
    limit: &'static str,
) -> Result<(), CampaignCodecError> {
    codec::ensure_encoded_size(value, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES, limit)
}

fn decode_message<T: Canonical>(
    bytes: &[u8],
    limit: &'static str,
) -> Result<T, CampaignCodecError> {
    if bytes.len() > MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES {
        return Err(CampaignCodecError::LimitExceeded { limit });
    }
    codec::decode(bytes)
}

const fn require_service_version(version: u32) -> Result<(), CampaignCodecError> {
    if version == CAMPAIGN_SERVICE_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported campaign service schema version",
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::BTreeSet;
    use std::convert::Infallible;
    use std::sync::Arc;

    use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

    use super::*;
    use crate::{
        BranchBudget, BranchPointId, BranchRequestCause, CampaignCommandId, CampaignControlAction,
        CandidateSource, ChoiceDomainId, ChoiceOpportunityId, ChoiceValue, ConfigurationArtifactId,
        StopCondition,
    };

    fn hash(label: &str) -> CampaignHash {
        CampaignHash::derive("campaign-service-test", label.as_bytes())
    }

    fn snapshot(label: &str) -> CampaignSnapshotId {
        CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            2,
            label.as_bytes(),
        ))
        .expect("snapshot id")
    }

    fn lineage(label: &str) -> CampaignLineageId {
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            label.as_bytes(),
        ))
        .expect("lineage id")
    }

    fn policy(label: &str) -> CampaignPolicyId {
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            label.as_bytes(),
        ))
        .expect("policy id")
    }

    fn branch_request(label: &str) -> BranchRequest {
        BranchRequest::new(
            BranchPointId::from_hash(hash(&format!("{label}-branch-point"))),
            ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
                ObjectKind::Configuration,
                1,
                format!("{label}-parent").as_bytes(),
            ))
            .expect("parent id"),
            ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                format!("{label}-opportunity").as_bytes(),
            ))
            .expect("opportunity id"),
            ChoiceDomainId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                format!("{label}-domain").as_bytes(),
            ))
            .expect("domain id"),
            CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                .expect("finite source"),
            BranchRequestCause::Operator(CampaignCommandId::from_hash(hash(&format!(
                "{label}-command"
            )))),
            BranchBudget::new(1, 1).expect("branch budget"),
            StopCondition::NextChoice,
        )
        .expect("branch request")
    }

    fn get_request(name: &str) -> GetCampaignRequest {
        GetCampaignRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new(name).expect("campaign name"),
        )
        .expect("get request")
    }

    #[test]
    fn campaign_names_match_the_repository_ref_grammar() {
        for invalid in ["bad:name", "a//b", "a/../b", "."] {
            assert!(CampaignName::new(invalid).is_err(), "accepted {invalid}");
        }
        assert!(CampaignName::new(format!("{}x", "a".repeat(255))).is_err());
        assert_eq!(
            CampaignName::new("team/network-recovery")
                .expect("nested campaign name")
                .as_str(),
            "team/network-recovery"
        );
    }

    #[test]
    fn get_campaign_messages_are_canonical_and_request_bound() {
        let request = get_request("network-recovery");
        assert_eq!(
            GetCampaignRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );
        let response = GetCampaignResponse::new(
            &request,
            snapshot("snapshot"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Running,
        )
        .expect("response");
        assert_eq!(
            GetCampaignResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response"),
            response
        );
        response.validate_for(&request).expect("request binding");
        assert!(response.validate_for(&get_request("other")).is_err());

        assert_eq!(
            [
                blake3::hash(&request.canonical_bytes())
                    .to_hex()
                    .to_string(),
                blake3::hash(&response.canonical_bytes())
                    .to_hex()
                    .to_string(),
            ],
            [
                String::from("e25fd54be8cb0ea10f0dc695d3f7b029883e0f87269c692abe85f5ba9701a61d"),
                String::from("3621345eb7ec6ae17e20f42ced081f182266ce1599d25e21e319a8baf9691a47"),
            ]
        );
    }

    #[test]
    fn apply_command_messages_bind_principal_name_and_payload() {
        let request = ApplyCampaignCommandRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign name"),
            ControlRequest {
                command: CampaignCommandId::from_hash(hash("resume")),
                expected_snapshot: snapshot("prior"),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("apply request");
        assert_eq!(
            ApplyCampaignCommandRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );
        let response = ApplyCampaignCommandResponse::new(
            &request,
            CampaignCommandResult {
                prior_snapshot: snapshot("prior"),
                new_snapshot: snapshot("next"),
                replayed: false,
            },
        )
        .expect("apply response");
        response.validate_for(&request).expect("request binding");

        let other_principal = ApplyCampaignCommandRequest::new(
            CampaignPrincipal::new("operator:bob").expect("principal"),
            request.campaign().clone(),
            request.command().clone(),
        )
        .expect("other request");
        assert!(response.validate_for(&other_principal).is_err());

        assert_eq!(
            [
                blake3::hash(&request.canonical_bytes())
                    .to_hex()
                    .to_string(),
                blake3::hash(&response.canonical_bytes())
                    .to_hex()
                    .to_string(),
            ],
            [
                String::from("854db6d9d21dd722d3c8c754fe83fa55db271325a8c06dbbbd95d63222fbb8c7"),
                String::from("66bf01a14552275865ffd5b6a9a91075387c976244cda5c3efaaee9324f18c18"),
            ]
        );
    }

    struct WrongGetService {
        response: GetCampaignResponse,
    }

    impl CampaignService for WrongGetService {
        type Error = Infallible;

        fn get_campaign(
            &self,
            _request: &GetCampaignRequest,
        ) -> Result<GetCampaignResponse, Self::Error> {
            Ok(self.response.clone())
        }

        fn apply_campaign_command(
            &self,
            _request: &ApplyCampaignCommandRequest,
        ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
            unreachable!("test service only handles GetCampaign")
        }

        fn submit_branch_request(
            &self,
            _request: &SubmitCampaignBranchRequest,
        ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
            unreachable!("test service only handles GetCampaign")
        }
    }

    #[test]
    fn checked_client_rejects_a_cross_request_response() {
        let original = get_request("original");
        let response = GetCampaignResponse::new(
            &original,
            snapshot("snapshot"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Running,
        )
        .expect("response");
        let client = CampaignClient::new(WrongGetService { response });

        assert!(matches!(
            client.get_campaign(&get_request("other")),
            Err(CampaignClientError::InvalidResponse(
                CampaignCodecError::InvalidValue {
                    reason: "campaign service response request digest mismatch"
                }
            ))
        ));
    }

    struct WrongApplyService {
        response: ApplyCampaignCommandResponse,
    }

    impl CampaignService for WrongApplyService {
        type Error = Infallible;

        fn get_campaign(
            &self,
            _request: &GetCampaignRequest,
        ) -> Result<GetCampaignResponse, Self::Error> {
            unreachable!("test service only handles ApplyCampaignCommand")
        }

        fn apply_campaign_command(
            &self,
            _request: &ApplyCampaignCommandRequest,
        ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
            Ok(self.response.clone())
        }

        fn submit_branch_request(
            &self,
            _request: &SubmitCampaignBranchRequest,
        ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
            unreachable!("test service only handles ApplyCampaignCommand")
        }
    }

    #[test]
    fn checked_client_rejects_a_command_response_with_the_wrong_prior_snapshot() {
        let request = ApplyCampaignCommandRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign name"),
            ControlRequest {
                command: CampaignCommandId::from_hash(hash("resume")),
                expected_snapshot: snapshot("prior"),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("apply request");
        assert!(
            ApplyCampaignCommandResponse::new(
                &request,
                CampaignCommandResult {
                    prior_snapshot: snapshot("wrong"),
                    new_snapshot: snapshot("next"),
                    replayed: false,
                },
            )
            .is_err()
        );

        let mut response = ApplyCampaignCommandResponse::new(
            &request,
            CampaignCommandResult {
                prior_snapshot: snapshot("prior"),
                new_snapshot: snapshot("next"),
                replayed: false,
            },
        )
        .expect("apply response");
        response.prior_snapshot = snapshot("wrong");
        let client = CampaignClient::new(WrongApplyService { response });

        assert!(matches!(
            client.apply_campaign_command(&request),
            Err(CampaignClientError::InvalidResponse(
                CampaignCodecError::InvalidValue {
                    reason: "campaign command response prior snapshot mismatch"
                }
            ))
        ));
    }

    #[test]
    fn branch_messages_are_canonical_and_bind_the_exact_request() {
        let request = SubmitCampaignBranchRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign name"),
            snapshot("prior"),
            branch_request("first"),
        )
        .expect("branch submission");
        assert_eq!(
            SubmitCampaignBranchRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );
        let response = SubmitCampaignBranchResponse::new(
            &request,
            BranchRequestResult {
                prior_snapshot: snapshot("prior"),
                new_snapshot: snapshot("next"),
                request: request.request().id().expect("request id"),
                replayed: false,
            },
        )
        .expect("branch response");
        assert_eq!(
            SubmitCampaignBranchResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response"),
            response
        );
        response.validate_for(&request).expect("request binding");

        let changed = SubmitCampaignBranchRequest::new(
            request.principal().clone(),
            request.campaign().clone(),
            snapshot("other-prior"),
            request.request().clone(),
        )
        .expect("changed submission");
        assert!(response.validate_for(&changed).is_err());

        assert_eq!(
            [
                blake3::hash(&request.canonical_bytes())
                    .to_hex()
                    .to_string(),
                blake3::hash(&response.canonical_bytes())
                    .to_hex()
                    .to_string(),
            ],
            [
                String::from("5c95a74d12bd2e39db8e76627afe774e802511ad688a0a752bb126cf8a1979a6"),
                String::from("05f8c12cdd340786b2fe4fd62fe7d7971884e2346a06011a489b3668bab15f73"),
            ]
        );
    }

    struct DenyAll;

    impl CampaignPrincipalAuthorizer for DenyAll {
        fn authorize(
            &self,
            _principal: &CampaignPrincipal,
            _operation: CampaignServiceOperation,
            _campaign: &CampaignName,
            _request_digest: CampaignHash,
        ) -> Result<(), CampaignAuthorizationError> {
            Err(CampaignAuthorizationError::Unauthorized)
        }
    }

    #[test]
    fn repository_adapter_authorizes_before_repository_access() {
        let repository = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("campaign-service-test", u64::MAX)),
            Arc::new(MemoryRefBackend::new()),
        );
        let service = RepositoryCampaignService::new(&repository, DenyAll);
        assert!(matches!(
            service.get_campaign(&get_request("absent")),
            Err(RepositoryCampaignServiceError::Authorization(
                CampaignAuthorizationError::Unauthorized
            ))
        ));
    }
}

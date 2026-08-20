//! Principal-aware user-facing campaign service contracts.
//!
//! This module owns strict canonical messages for the first repository-backed
//! `CampaignService` operations. The service boundary authenticates an
//! operational principal before invoking the existing semantic repository
//! owner. Principal identity and authorization decisions remain operational:
//! neither enters immutable campaign facts or content identities.

use crucible_cas::content_store::{RefName, StoreError};
use thiserror::Error;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    BranchRequest, BranchRequestResult, CampaignCodecError, CampaignCommandResult, CampaignHash,
    CampaignLineageId, CampaignPolicyId, CampaignRecordKind, CampaignRepository,
    CampaignRepositoryError, CampaignSnapshot, CampaignSnapshotId, CampaignState,
    ChoiceOpportunityId, ControlRequest, MerkleMap, MerkleMapLookupProof, MerkleMapPageProof,
    ObjectEnvelope,
};

mod create;
mod derive;
mod get_snapshot;
mod query;
mod watch;

pub use create::{
    CreateCampaignRequest, CreateCampaignResponse, MAX_CREATE_CAMPAIGN_GENERATOR_BYTES,
    MAX_CREATE_CAMPAIGN_GENERATORS,
};
pub use derive::{DeriveCampaignRequest, DeriveCampaignResponse};
pub use get_snapshot::{GetCampaignSnapshotRequest, GetCampaignSnapshotResponse};
pub use query::{
    CampaignChoiceEntry, CampaignGraphEntry, GetCampaignGraphObjectRequest,
    GetCampaignGraphObjectResponse, MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_QUERY_PAGE_ITEMS, QueryCampaignChoicesRequest, QueryCampaignChoicesResponse,
    QueryCampaignGraphRequest, QueryCampaignGraphResponse,
};
pub use watch::{WatchCampaignRequest, WatchCampaignResponse};

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
    /// Create one named campaign at its canonical genesis snapshot.
    CreateCampaign,
    /// Derive a new named campaign from an authenticated source snapshot.
    DeriveCampaign,
    /// Read the authenticated current campaign head and lifecycle state.
    GetCampaign,
    /// Read one authenticated snapshot from a named campaign history.
    GetCampaignSnapshot,
    /// Read the latest coalesced campaign head after an optional snapshot cursor.
    WatchCampaign,
    /// Read snapshot metadata and one bounded page from its campaign graph.
    QueryCampaignGraph,
    /// Read one exact object body named by the authenticated campaign graph.
    GetCampaignGraphObject,
    /// Read one bounded page from the authenticated discovered-choice index.
    QueryCampaignChoices,
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

/// Stable language-neutral failure returned by a campaign service.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CampaignServiceFailure {
    /// The authenticated principal lacks the requested capability.
    #[error("campaign service principal is not authorized")]
    Unauthorized,
    /// The authorization backend could not make a definitive decision.
    #[error("campaign service authorization is unavailable")]
    AuthorizationUnavailable,
    /// The named campaign does not exist.
    #[error("campaign was not found")]
    NotFound,
    /// The requested create operation names an existing campaign.
    #[error("campaign already exists")]
    AlreadyExists,
    /// The supplied semantic snapshot is not the current head.
    #[error("campaign request used stale snapshot {expected}; current snapshot is {current}")]
    Stale {
        /// Snapshot supplied by the caller.
        expected: CampaignSnapshotId,
        /// Current authoritative snapshot.
        current: CampaignSnapshotId,
    },
    /// An idempotency key was reused for different canonical input.
    #[error("campaign command id was reused with another request")]
    CommandReuse,
    /// A concurrent transaction changed the authoritative campaign ref.
    #[error("campaign changed during the request")]
    ConcurrentUpdate,
    /// The requested lifecycle action is illegal from the current state.
    #[error("campaign action is invalid from state {state:?}")]
    InvalidTransition {
        /// State that rejected the lifecycle action.
        state: CampaignState,
    },
    /// Canonical request bytes or semantic input were invalid.
    #[error("campaign request is invalid")]
    InvalidRequest,
    /// A required storage tier denied access.
    #[error("campaign storage access is unauthorized")]
    BackendUnauthorized,
    /// A configured storage or service resource ceiling was exhausted.
    #[error("campaign service resource capacity is exhausted")]
    ResourceExhausted,
    /// Required campaign data or an operational backend is temporarily unavailable.
    #[error("campaign service is temporarily unavailable")]
    Unavailable,
    /// Authenticated repository state violated an internal invariant.
    #[error("campaign repository integrity validation failed")]
    IntegrityFailure,
    /// A service peer violated the versioned framing or response contract.
    #[error("campaign service protocol or response validation failed")]
    ProtocolViolation,
}

/// Closed caller action derived from one stable campaign-service failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignServiceRetryDisposition {
    /// Retry the same canonical request after bounded backoff or capacity recovery.
    RetryAfterBackoff,
    /// Refresh the authoritative campaign head before constructing a new request.
    RefreshCampaign,
    /// Refresh or correct caller/storage credentials before retrying.
    Reauthenticate,
    /// User or operator intent must resolve the reported state conflict.
    OperatorAction,
    /// Repeating the request cannot succeed without correcting data or software.
    DoNotRetry,
}

impl CampaignServiceFailure {
    /// Returns the language-neutral caller action for this failure.
    #[must_use]
    pub const fn retry_disposition(self) -> CampaignServiceRetryDisposition {
        match self {
            Self::AuthorizationUnavailable | Self::ResourceExhausted | Self::Unavailable => {
                CampaignServiceRetryDisposition::RetryAfterBackoff
            }
            Self::Stale { .. } | Self::ConcurrentUpdate => {
                CampaignServiceRetryDisposition::RefreshCampaign
            }
            Self::Unauthorized | Self::BackendUnauthorized => {
                CampaignServiceRetryDisposition::Reauthenticate
            }
            Self::NotFound | Self::AlreadyExists | Self::InvalidTransition { .. } => {
                CampaignServiceRetryDisposition::OperatorAction
            }
            Self::CommandReuse
            | Self::InvalidRequest
            | Self::IntegrityFailure
            | Self::ProtocolViolation => CampaignServiceRetryDisposition::DoNotRetry,
        }
    }

    /// Validates that this failure is meaningful for `CreateCampaign`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a read- or mutation-only failure.
    pub fn validate_for_create_campaign(self) -> Result<(), CampaignCodecError> {
        match self {
            Self::NotFound
            | Self::Stale { .. }
            | Self::CommandReuse
            | Self::ConcurrentUpdate
            | Self::InvalidTransition { .. } => Err(CampaignCodecError::InvalidValue {
                reason: "campaign service failure is invalid for create campaign",
            }),
            _ => Ok(()),
        }
    }

    /// Validates that this failure is meaningful for `DeriveCampaign`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an existing-campaign mutation-only
    /// failure that a name-creation operation cannot produce.
    pub fn validate_for_derive_campaign(self) -> Result<(), CampaignCodecError> {
        match self {
            Self::Stale { .. } | Self::CommandReuse | Self::InvalidTransition { .. } => {
                Err(CampaignCodecError::InvalidValue {
                    reason: "campaign service failure is invalid for derive campaign",
                })
            }
            _ => Ok(()),
        }
    }

    /// Validates that this failure is meaningful for `GetCampaign`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create-only or mutation-only
    /// failure because a current-head read cannot produce that outcome.
    pub fn validate_for_get_campaign(self) -> Result<(), CampaignCodecError> {
        match self {
            Self::AlreadyExists
            | Self::Stale { .. }
            | Self::CommandReuse
            | Self::ConcurrentUpdate
            | Self::InvalidTransition { .. } => Err(CampaignCodecError::InvalidValue {
                reason: "campaign service failure is invalid for get campaign",
            }),
            _ => Ok(()),
        }
    }

    /// Validates that this failure is meaningful for `WatchCampaign`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create-only or mutation-only
    /// failure that a coalesced current-head read cannot produce.
    pub fn validate_for_watch_campaign(self) -> Result<(), CampaignCodecError> {
        self.validate_for_get_campaign()
    }

    /// Validates a failure for one exact campaign graph query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this query's exact snapshot.
    pub fn validate_for_query_campaign_graph(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        match self {
            Self::AlreadyExists
            | Self::CommandReuse
            | Self::ConcurrentUpdate
            | Self::InvalidTransition { .. } => Err(CampaignCodecError::InvalidValue {
                reason: "campaign service failure is invalid for graph query",
            }),
            Self::Stale { expected, current }
                if expected != expected_snapshot || current == expected =>
            {
                Err(CampaignCodecError::InvalidValue {
                    reason: "campaign graph query stale failure snapshot mismatch",
                })
            }
            _ => Ok(()),
        }
    }

    /// Validates a failure for one exact campaign graph-object lookup.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this lookup's exact snapshot.
    pub fn validate_for_get_campaign_graph_object(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        self.validate_for_query_campaign_graph(expected_snapshot)
    }

    /// Validates a failure for one exact campaign choice query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this query's exact snapshot.
    pub fn validate_for_query_campaign_choices(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        self.validate_for_query_campaign_graph(expected_snapshot)
    }

    /// Validates a failure for one exact campaign-command request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create-only failure, or when a
    /// stale failure does not describe this request's exact precondition.
    pub fn validate_for_apply_campaign_command(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        match self {
            Self::AlreadyExists => Err(CampaignCodecError::InvalidValue {
                reason: "campaign service failure is invalid for apply campaign command",
            }),
            Self::Stale { expected, current }
                if expected != expected_snapshot || current == expected =>
            {
                Err(CampaignCodecError::InvalidValue {
                    reason: "campaign service stale failure snapshot mismatch",
                })
            }
            _ => Ok(()),
        }
    }

    /// Validates a failure for one exact branch-submission request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or lifecycle-only failure,
    /// or when a stale failure does not describe this request's exact
    /// precondition.
    pub fn validate_for_submit_branch_request(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        match self {
            Self::AlreadyExists | Self::InvalidTransition { .. } => {
                Err(CampaignCodecError::InvalidValue {
                    reason: "campaign service failure is invalid for submit branch request",
                })
            }
            Self::Stale { expected, current }
                if expected != expected_snapshot || current == expected =>
            {
                Err(CampaignCodecError::InvalidValue {
                    reason: "campaign service stale failure snapshot mismatch",
                })
            }
            _ => Ok(()),
        }
    }
}

impl Canonical for CampaignServiceFailure {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Unauthorized => encoder.u8(0),
            Self::AuthorizationUnavailable => encoder.u8(1),
            Self::NotFound => encoder.u8(2),
            Self::AlreadyExists => encoder.u8(3),
            Self::Stale { expected, current } => {
                encoder.u8(4);
                expected.encode(encoder);
                current.encode(encoder);
            }
            Self::CommandReuse => encoder.u8(5),
            Self::ConcurrentUpdate => encoder.u8(6),
            Self::InvalidTransition { state } => {
                encoder.u8(7);
                state.encode(encoder);
            }
            Self::InvalidRequest => encoder.u8(8),
            Self::BackendUnauthorized => encoder.u8(9),
            Self::ResourceExhausted => encoder.u8(10),
            Self::Unavailable => encoder.u8(11),
            Self::IntegrityFailure => encoder.u8(12),
            Self::ProtocolViolation => encoder.u8(13),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Unauthorized),
            1 => Ok(Self::AuthorizationUnavailable),
            2 => Ok(Self::NotFound),
            3 => Ok(Self::AlreadyExists),
            4 => Ok(Self::Stale {
                expected: CampaignSnapshotId::decode(decoder)?,
                current: CampaignSnapshotId::decode(decoder)?,
            }),
            5 => Ok(Self::CommandReuse),
            6 => Ok(Self::ConcurrentUpdate),
            7 => Ok(Self::InvalidTransition {
                state: CampaignState::decode(decoder)?,
            }),
            8 => Ok(Self::InvalidRequest),
            9 => Ok(Self::BackendUnauthorized),
            10 => Ok(Self::ResourceExhausted),
            11 => Ok(Self::Unavailable),
            12 => Ok(Self::IntegrityFailure),
            13 => Ok(Self::ProtocolViolation),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-service-failure",
                tag,
            }),
        }
    }
}

/// Maps implementation-specific failures into the stable service vocabulary.
pub trait CampaignServiceFailureSource {
    /// Returns the failure safe to expose across a campaign-service boundary.
    #[must_use]
    fn campaign_service_failure(&self) -> CampaignServiceFailure;
}

impl CampaignServiceFailureSource for CampaignServiceFailure {
    fn campaign_service_failure(&self) -> CampaignServiceFailure {
        *self
    }
}

impl CampaignServiceFailureSource for std::convert::Infallible {
    fn campaign_service_failure(&self) -> CampaignServiceFailure {
        match *self {}
    }
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

/// Request-bound stable failure response shared by every service operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignServiceErrorResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    failure: CampaignServiceFailure,
}

impl CampaignServiceErrorResponse {
    /// Builds a bounded error response for one exact canonical request digest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the encoded response exceeds the
    /// campaign-service message bound.
    pub fn new(
        request_digest: CampaignHash,
        failure: CampaignServiceFailure,
    ) -> Result<Self, CampaignCodecError> {
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest,
            failure,
        };
        ensure_message_size(&response, "campaign-service-error-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the stable semantic failure.
    #[must_use]
    pub const fn failure(self) -> CampaignServiceFailure {
        self.failure
    }

    /// Validates exact request-digest binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// canonical request.
    pub fn validate_for_digest(
        &self,
        request_digest: CampaignHash,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request_digest)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded error response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, unsupported,
    /// or oversized input. Exact request validation remains required.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "campaign-service-error-response-encoded-bytes")
    }
}

impl Canonical for CampaignServiceErrorResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.failure.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            failure: CampaignServiceFailure::decode(decoder)?,
        };
        ensure_message_size(&response, "campaign-service-error-response-encoded-bytes")?;
        Ok(response)
    }
}

/// Initial user-facing campaign service implemented by direct and RPC adapters.
pub trait CampaignService {
    /// Implementation-specific operational failure.
    type Error;

    /// Creates one canonical named campaign or replays its exact genesis.
    ///
    /// The lineage's scenario and genesis artifacts must first be present in
    /// the repository through an execution-model verifier-backed importer.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// required artifact availability, semantic validation, publication, or
    /// response construction fails.
    fn create_campaign(
        &self,
        request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error>;

    /// Derives one new campaign from an authenticated source snapshot.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// source membership, policy validation, publication, or response
    /// construction fails.
    fn derive_campaign(
        &self,
        request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error>;

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

    /// Returns one exact snapshot from the named campaign's authenticated history.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// campaign-history membership, repository access, or response
    /// construction fails.
    fn get_campaign_snapshot(
        &self,
        request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error>;

    /// Returns the latest coalesced campaign head after an optional cursor.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// repository access, or response construction fails.
    fn watch_campaign(
        &self,
        request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, Self::Error>;

    /// Returns complete snapshot metadata and one bounded graph page.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, cursor validation, repository access, or
    /// response construction fails.
    fn query_campaign_graph(
        &self,
        request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error>;

    /// Returns one exact object named by the authenticated current graph.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, graph membership, repository access, or response
    /// construction fails.
    fn get_campaign_graph_object(
        &self,
        request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error>;

    /// Returns one bounded page from the authenticated discovered-choice index.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, cursor validation, repository access, or
    /// response construction fails.
    fn query_campaign_choices(
        &self,
        request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error>;

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
pub enum CampaignClientError {
    /// The service returned a stable semantic or operational failure.
    #[error(transparent)]
    Service(#[from] CampaignServiceFailure),
}

/// Checked direct/RPC client that enforces exact response binding.
pub struct CampaignClient<S> {
    service: S,
}

impl<S> CampaignClient<S>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    /// Creates a checked client over one service adapter.
    #[must_use]
    pub const fn new(service: S) -> Self {
        Self { service }
    }

    /// Creates one campaign and validates exact response binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request.
    pub fn create_campaign(
        &self,
        request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, CampaignClientError> {
        let response = match self.service.create_campaign(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_create_campaign()
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Derives one campaign and validates exact response binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request.
    pub fn derive_campaign(
        &self,
        request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, CampaignClientError> {
        let response = match self.service.derive_campaign(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_derive_campaign()
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
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
    ) -> Result<GetCampaignResponse, CampaignClientError> {
        let response = match self.service.get_campaign(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_get_campaign()
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Loads one exact named-history snapshot and validates response binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request or snapshot identity.
    pub fn get_campaign_snapshot(
        &self,
        request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, CampaignClientError> {
        let response = match self.service.get_campaign_snapshot(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_get_campaign()
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Watches one campaign through a coalesced snapshot cursor and validates
    /// exact response binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request or cursor relation.
    pub fn watch_campaign(
        &self,
        request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, CampaignClientError> {
        let response = match self.service.watch_campaign(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_watch_campaign()
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Queries one snapshot-bound graph page and validates exact response binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, page, or cursor relation.
    pub fn query_campaign_graph(
        &self,
        request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, CampaignClientError> {
        let response = match self.service.query_campaign_graph(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_query_campaign_graph(request.snapshot())
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Gets one snapshot-bound graph object and validates its membership proof.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, graph key, object, or proof.
    pub fn get_campaign_graph_object(
        &self,
        request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, CampaignClientError> {
        let response = match self.service.get_campaign_graph_object(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_get_campaign_graph_object(request.snapshot())
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Queries one snapshot-bound choice page and validates both Merkle proofs.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, nested index, page, or cursor relation.
    pub fn query_campaign_choices(
        &self,
        request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, CampaignClientError> {
        let response = match self.service.query_campaign_choices(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_query_campaign_choices(request.snapshot())
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
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
    ) -> Result<ApplyCampaignCommandResponse, CampaignClientError> {
        let response = match self.service.apply_campaign_command(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_apply_campaign_command(request.command.expected_snapshot)
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
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
    ) -> Result<SubmitCampaignBranchResponse, CampaignClientError> {
        let response = match self.service.submit_branch_request(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_submit_branch_request(request.expected_snapshot)
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
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

impl CampaignServiceFailureSource for RepositoryCampaignServiceError {
    fn campaign_service_failure(&self) -> CampaignServiceFailure {
        match self {
            Self::Authorization(CampaignAuthorizationError::Unauthorized) => {
                CampaignServiceFailure::Unauthorized
            }
            Self::Authorization(CampaignAuthorizationError::Unavailable) => {
                CampaignServiceFailure::AuthorizationUnavailable
            }
            Self::Repository(error) => repository_service_failure(error),
            Self::Codec(_) => CampaignServiceFailure::IntegrityFailure,
        }
    }
}

fn repository_service_failure(error: &CampaignRepositoryError) -> CampaignServiceFailure {
    match error {
        CampaignRepositoryError::Store(error) => store_service_failure(error),
        CampaignRepositoryError::Codec(_) => CampaignServiceFailure::IntegrityFailure,
        CampaignRepositoryError::Merkle(crate::CampaignStoreError::Store(error)) => {
            store_service_failure(error)
        }
        CampaignRepositoryError::Merkle(_) => CampaignServiceFailure::IntegrityFailure,
        CampaignRepositoryError::AlreadyExists => CampaignServiceFailure::AlreadyExists,
        CampaignRepositoryError::NotFound => CampaignServiceFailure::NotFound,
        CampaignRepositoryError::Stale { expected, current } => CampaignServiceFailure::Stale {
            expected: *expected,
            current: *current,
        },
        CampaignRepositoryError::CommandReuse => CampaignServiceFailure::CommandReuse,
        CampaignRepositoryError::RefConflict { .. } => CampaignServiceFailure::ConcurrentUpdate,
        CampaignRepositoryError::InvalidRequest { .. } => CampaignServiceFailure::InvalidRequest,
        CampaignRepositoryError::Integrity { .. } => CampaignServiceFailure::IntegrityFailure,
        CampaignRepositoryError::InvalidTransition { state } => {
            CampaignServiceFailure::InvalidTransition { state: *state }
        }
        CampaignRepositoryError::Poisoned => CampaignServiceFailure::IntegrityFailure,
    }
}

fn store_service_failure(error: &StoreError) -> CampaignServiceFailure {
    match error {
        StoreError::Unauthorized => CampaignServiceFailure::BackendUnauthorized,
        StoreError::Quota => CampaignServiceFailure::ResourceExhausted,
        StoreError::NotFound { .. }
        | StoreError::Unavailable
        | StoreError::Io { .. }
        | StoreError::StreamIo { .. } => CampaignServiceFailure::Unavailable,
        StoreError::Corrupt { .. }
        | StoreError::InvalidId
        | StoreError::InvalidRefName { .. }
        | StoreError::InvalidRange { .. }
        | StoreError::InvalidComposition { .. }
        | StoreError::InvalidGraph { .. }
        | StoreError::Incompatible
        | StoreError::InvalidSourceLength { .. }
        | StoreError::Poisoned { .. }
        | StoreError::Unsupported { .. } => CampaignServiceFailure::IntegrityFailure,
    }
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

    fn create_campaign(
        &self,
        request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::CreateCampaign,
            request.campaign(),
            request.request_digest(),
        )?;
        match self.repository.create_from_stored(
            request.campaign().as_str(),
            request.lineage(),
            request.policy(),
        ) {
            Ok(head) => Ok(CreateCampaignResponse::new(
                request,
                head.snapshot_id(),
                false,
            )?),
            Err(CampaignRepositoryError::AlreadyExists) => {
                let genesis = self.repository.genesis(request.campaign().as_str())?;
                if genesis.snapshot().lineage() != request.lineage().id()?
                    || genesis.snapshot().active_policy() != request.policy().id()?
                {
                    return Err(CampaignRepositoryError::AlreadyExists.into());
                }
                Ok(CreateCampaignResponse::new(
                    request,
                    genesis.snapshot_id(),
                    true,
                )?)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn derive_campaign(
        &self,
        request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error> {
        for campaign in [request.source_campaign(), request.target_campaign()] {
            self.authorizer.authorize(
                request.principal(),
                CampaignServiceOperation::DeriveCampaign,
                campaign,
                request.request_digest(),
            )?;
        }
        let result = self.repository.derive_campaign(
            request.source_campaign().as_str(),
            request.source_snapshot(),
            request.target_campaign().as_str(),
            request.policy(),
        )?;
        Ok(DeriveCampaignResponse::new(request, result)?)
    }

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

    fn get_campaign_snapshot(
        &self,
        request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignSnapshot,
            request.campaign(),
            request.request_digest(),
        )?;
        let snapshot = self
            .repository
            .snapshot_in_campaign(request.campaign().as_str(), request.snapshot())?;
        Ok(GetCampaignSnapshotResponse::new(request, snapshot)?)
    }

    fn watch_campaign(
        &self,
        request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::WatchCampaign,
            request.campaign(),
            request.request_digest(),
        )?;
        let (head, state) = self
            .repository
            .head_with_state(request.campaign().as_str())?;
        Ok(WatchCampaignResponse::new(
            request,
            head.snapshot_id(),
            head.snapshot().lineage(),
            head.snapshot().active_policy(),
            state,
        )?)
    }

    fn query_campaign_graph(
        &self,
        request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::QueryCampaignGraph,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let limit = usize::try_from(request.limit()).map_err(|_| {
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-query-page-size-is-invalid",
            }
        })?;
        let (page, proof) = self.repository.scan_graph_page(
            head.snapshot().roots().graph,
            request.after(),
            limit,
        )?;
        let entries = page
            .entries()
            .iter()
            .map(|(key, object)| CampaignGraphEntry::new(*key, *object))
            .collect();
        Ok(QueryCampaignGraphResponse::new(
            request,
            head.snapshot().clone(),
            entries,
            page.next_after(),
            proof,
        )?)
    }

    fn get_campaign_graph_object(
        &self,
        request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignGraphObject,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let (object, proof) = self
            .repository
            .graph_object_with_proof(head.snapshot().roots().graph, request.key())?;
        Ok(GetCampaignGraphObjectResponse::new(
            request,
            head.snapshot().clone(),
            object,
            proof,
        )?)
    }

    fn query_campaign_choices(
        &self,
        request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::QueryCampaignChoices,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let limit = usize::try_from(request.limit()).map_err(|_| {
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-choice-query-page-size-is-invalid",
            }
        })?;
        let (page, index_proof, page_proof) = self.repository.scan_choice_page(
            head.snapshot().roots().graph,
            request.after(),
            limit,
        )?;
        let entries = page
            .entries()
            .iter()
            .map(|(_, object)| {
                ChoiceOpportunityId::from_content_id(*object).map(CampaignChoiceEntry::new)
            })
            .collect::<Result<Vec<_>, CampaignCodecError>>()?;
        let next_after = page
            .next_after()
            .and_then(|_| entries.last().map(|entry| entry.opportunity()));
        Ok(QueryCampaignChoicesResponse::new(
            request,
            head.snapshot().clone(),
            entries,
            next_after,
            index_proof,
            page_proof,
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

        fn create_campaign(
            &self,
            _request: &CreateCampaignRequest,
        ) -> Result<CreateCampaignResponse, Self::Error> {
            unreachable!("test service only handles GetCampaign")
        }

        fn derive_campaign(
            &self,
            _request: &DeriveCampaignRequest,
        ) -> Result<DeriveCampaignResponse, Self::Error> {
            unreachable!("test service only handles GetCampaign")
        }

        fn get_campaign(
            &self,
            _request: &GetCampaignRequest,
        ) -> Result<GetCampaignResponse, Self::Error> {
            Ok(self.response.clone())
        }

        fn get_campaign_snapshot(
            &self,
            _request: &GetCampaignSnapshotRequest,
        ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
            unreachable!("test service only handles GetCampaign")
        }

        fn watch_campaign(
            &self,
            _request: &WatchCampaignRequest,
        ) -> Result<WatchCampaignResponse, Self::Error> {
            unreachable!("test service only handles GetCampaign")
        }

        fn query_campaign_graph(
            &self,
            _request: &QueryCampaignGraphRequest,
        ) -> Result<QueryCampaignGraphResponse, Self::Error> {
            unreachable!("test service only handles GetCampaign")
        }

        fn get_campaign_graph_object(
            &self,
            _request: &GetCampaignGraphObjectRequest,
        ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
            unreachable!("test service only handles GetCampaign")
        }

        fn query_campaign_choices(
            &self,
            _request: &QueryCampaignChoicesRequest,
        ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
            unreachable!("test service only handles GetCampaign")
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
            Err(CampaignClientError::Service(
                CampaignServiceFailure::ProtocolViolation
            ))
        ));
    }

    struct WrongApplyService {
        response: ApplyCampaignCommandResponse,
    }

    struct FixedFailureService(CampaignServiceFailure);

    impl CampaignService for FixedFailureService {
        type Error = CampaignServiceFailure;

        fn create_campaign(
            &self,
            _request: &CreateCampaignRequest,
        ) -> Result<CreateCampaignResponse, Self::Error> {
            Err(self.0)
        }

        fn derive_campaign(
            &self,
            _request: &DeriveCampaignRequest,
        ) -> Result<DeriveCampaignResponse, Self::Error> {
            Err(self.0)
        }

        fn get_campaign(
            &self,
            _request: &GetCampaignRequest,
        ) -> Result<GetCampaignResponse, Self::Error> {
            Err(self.0)
        }

        fn get_campaign_snapshot(
            &self,
            _request: &GetCampaignSnapshotRequest,
        ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
            Err(self.0)
        }

        fn watch_campaign(
            &self,
            _request: &WatchCampaignRequest,
        ) -> Result<WatchCampaignResponse, Self::Error> {
            Err(self.0)
        }

        fn query_campaign_graph(
            &self,
            _request: &QueryCampaignGraphRequest,
        ) -> Result<QueryCampaignGraphResponse, Self::Error> {
            Err(self.0)
        }

        fn get_campaign_graph_object(
            &self,
            _request: &GetCampaignGraphObjectRequest,
        ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
            Err(self.0)
        }

        fn query_campaign_choices(
            &self,
            _request: &QueryCampaignChoicesRequest,
        ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
            Err(self.0)
        }

        fn apply_campaign_command(
            &self,
            _request: &ApplyCampaignCommandRequest,
        ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
            Err(self.0)
        }

        fn submit_branch_request(
            &self,
            _request: &SubmitCampaignBranchRequest,
        ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
            Err(self.0)
        }
    }

    impl CampaignService for WrongApplyService {
        type Error = Infallible;

        fn create_campaign(
            &self,
            _request: &CreateCampaignRequest,
        ) -> Result<CreateCampaignResponse, Self::Error> {
            unreachable!("test service only handles ApplyCampaignCommand")
        }

        fn derive_campaign(
            &self,
            _request: &DeriveCampaignRequest,
        ) -> Result<DeriveCampaignResponse, Self::Error> {
            unreachable!("test service only handles ApplyCampaignCommand")
        }

        fn get_campaign(
            &self,
            _request: &GetCampaignRequest,
        ) -> Result<GetCampaignResponse, Self::Error> {
            unreachable!("test service only handles ApplyCampaignCommand")
        }

        fn get_campaign_snapshot(
            &self,
            _request: &GetCampaignSnapshotRequest,
        ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
            unreachable!("test service only handles ApplyCampaignCommand")
        }

        fn watch_campaign(
            &self,
            _request: &WatchCampaignRequest,
        ) -> Result<WatchCampaignResponse, Self::Error> {
            unreachable!("test service only handles ApplyCampaignCommand")
        }

        fn query_campaign_graph(
            &self,
            _request: &QueryCampaignGraphRequest,
        ) -> Result<QueryCampaignGraphResponse, Self::Error> {
            unreachable!("test service only handles ApplyCampaignCommand")
        }

        fn get_campaign_graph_object(
            &self,
            _request: &GetCampaignGraphObjectRequest,
        ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
            unreachable!("test service only handles ApplyCampaignCommand")
        }

        fn query_campaign_choices(
            &self,
            _request: &QueryCampaignChoicesRequest,
        ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
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
            Err(CampaignClientError::Service(
                CampaignServiceFailure::ProtocolViolation
            ))
        ));
    }

    #[test]
    fn checked_client_rejects_failures_with_the_wrong_operation_basis() {
        let get = get_request("network-recovery");
        for failure in [
            CampaignServiceFailure::AlreadyExists,
            CampaignServiceFailure::Stale {
                expected: snapshot("irrelevant"),
                current: snapshot("current"),
            },
            CampaignServiceFailure::CommandReuse,
            CampaignServiceFailure::ConcurrentUpdate,
            CampaignServiceFailure::InvalidTransition {
                state: CampaignState::Sealed,
            },
        ] {
            let client = CampaignClient::new(FixedFailureService(failure));
            assert!(matches!(
                client.get_campaign(&get),
                Err(CampaignClientError::Service(
                    CampaignServiceFailure::ProtocolViolation
                ))
            ));
        }

        let apply = ApplyCampaignCommandRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign name"),
            ControlRequest {
                command: CampaignCommandId::from_hash(hash("resume")),
                expected_snapshot: snapshot("expected"),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("apply request");
        for failure in [
            CampaignServiceFailure::AlreadyExists,
            CampaignServiceFailure::Stale {
                expected: snapshot("wrong"),
                current: snapshot("current"),
            },
            CampaignServiceFailure::Stale {
                expected: snapshot("expected"),
                current: snapshot("expected"),
            },
        ] {
            let client = CampaignClient::new(FixedFailureService(failure));
            assert!(matches!(
                client.apply_campaign_command(&apply),
                Err(CampaignClientError::Service(
                    CampaignServiceFailure::ProtocolViolation
                ))
            ));
        }

        let branch = SubmitCampaignBranchRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign name"),
            snapshot("expected"),
            branch_request("wrong-failure-basis"),
        )
        .expect("branch request");
        for failure in [
            CampaignServiceFailure::AlreadyExists,
            CampaignServiceFailure::InvalidTransition {
                state: CampaignState::Sealed,
            },
        ] {
            let client = CampaignClient::new(FixedFailureService(failure));
            assert!(matches!(
                client.submit_branch_request(&branch),
                Err(CampaignClientError::Service(
                    CampaignServiceFailure::ProtocolViolation
                ))
            ));
        }
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

    #[test]
    fn service_error_responses_are_canonical_and_request_bound() {
        let request_digest = hash("error-request");
        let failures = [
            (
                CampaignServiceFailure::Unauthorized,
                CampaignServiceRetryDisposition::Reauthenticate,
            ),
            (
                CampaignServiceFailure::AuthorizationUnavailable,
                CampaignServiceRetryDisposition::RetryAfterBackoff,
            ),
            (
                CampaignServiceFailure::NotFound,
                CampaignServiceRetryDisposition::OperatorAction,
            ),
            (
                CampaignServiceFailure::AlreadyExists,
                CampaignServiceRetryDisposition::OperatorAction,
            ),
            (
                CampaignServiceFailure::Stale {
                    expected: snapshot("expected"),
                    current: snapshot("current"),
                },
                CampaignServiceRetryDisposition::RefreshCampaign,
            ),
            (
                CampaignServiceFailure::CommandReuse,
                CampaignServiceRetryDisposition::DoNotRetry,
            ),
            (
                CampaignServiceFailure::ConcurrentUpdate,
                CampaignServiceRetryDisposition::RefreshCampaign,
            ),
            (
                CampaignServiceFailure::InvalidTransition {
                    state: CampaignState::Sealed,
                },
                CampaignServiceRetryDisposition::OperatorAction,
            ),
            (
                CampaignServiceFailure::InvalidRequest,
                CampaignServiceRetryDisposition::DoNotRetry,
            ),
            (
                CampaignServiceFailure::BackendUnauthorized,
                CampaignServiceRetryDisposition::Reauthenticate,
            ),
            (
                CampaignServiceFailure::ResourceExhausted,
                CampaignServiceRetryDisposition::RetryAfterBackoff,
            ),
            (
                CampaignServiceFailure::Unavailable,
                CampaignServiceRetryDisposition::RetryAfterBackoff,
            ),
            (
                CampaignServiceFailure::IntegrityFailure,
                CampaignServiceRetryDisposition::DoNotRetry,
            ),
            (
                CampaignServiceFailure::ProtocolViolation,
                CampaignServiceRetryDisposition::DoNotRetry,
            ),
        ];
        for (failure, retry_disposition) in failures {
            let response =
                CampaignServiceErrorResponse::new(request_digest, failure).expect("error response");
            assert_eq!(
                CampaignServiceErrorResponse::from_canonical_bytes(&response.canonical_bytes())
                    .expect("decode error response"),
                response
            );
            response
                .validate_for_digest(request_digest)
                .expect("request binding");
            assert_eq!(response.failure(), failure);
            assert!(
                response
                    .validate_for_digest(hash("other-error-request"))
                    .is_err()
            );
            assert_eq!(failure.retry_disposition(), retry_disposition);
        }
        let golden =
            CampaignServiceErrorResponse::new(request_digest, CampaignServiceFailure::Unauthorized)
                .expect("golden error response");
        assert_eq!(
            blake3::hash(&golden.canonical_bytes()).to_hex().to_string(),
            "26766ef9f5cf89d87b0e660c0a498a7dcad09764bd5952d89c82728bd7c34d67"
        );
        assert_eq!(
            repository_service_failure(&CampaignRepositoryError::Poisoned),
            CampaignServiceFailure::IntegrityFailure
        );
        assert_eq!(
            store_service_failure(&StoreError::Poisoned {
                operation: "campaign-service-test",
            }),
            CampaignServiceFailure::IntegrityFailure
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
        let client = CampaignClient::new(RepositoryCampaignService::new(&repository, DenyAll));
        assert!(matches!(
            client.get_campaign(&get_request("absent")),
            Err(CampaignClientError::Service(
                CampaignServiceFailure::Unauthorized
            ))
        ));
    }
}

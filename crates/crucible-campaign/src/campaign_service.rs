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
    BranchRequest, BranchRequestResult, CampaignCodecError, CampaignCommandResult, CampaignFact,
    CampaignHash, CampaignLineageId, CampaignPolicyId, CampaignRecordKind, CampaignRepository,
    CampaignRepositoryError, CampaignSnapshot, CampaignSnapshotId, CampaignState,
    ChoiceOpportunityId, ControlRequest, MerkleMap, MerkleMapLookupProof, MerkleMapPageProof,
    ObjectEnvelope,
};

mod create;
mod derive;
mod get_snapshot;
mod list;
mod pin;
mod query;
mod ranking;
mod repository;
mod watch;

pub use create::{
    CreateCampaignRequest, CreateCampaignResponse, MAX_CREATE_CAMPAIGN_GENERATOR_BYTES,
    MAX_CREATE_CAMPAIGN_GENERATORS,
};
pub use derive::{DeriveCampaignRequest, DeriveCampaignResponse};
pub use get_snapshot::{GetCampaignSnapshotRequest, GetCampaignSnapshotResponse};
pub use list::{
    CampaignListEntry, ListCampaignsRequest, ListCampaignsResponse, MAX_CAMPAIGN_LIST_PAGE_ITEMS,
};
pub use pin::{PinCampaignRequest, PinCampaignResponse};
pub use query::{
    CampaignChoiceEntry, CampaignChoiceObject, CampaignChoiceObjectKind, CampaignFindingObject,
    CampaignFindingObjectKind, CampaignGraphEntry, ExplainCampaignAttemptRequest,
    ExplainCampaignAttemptResponse, GetCampaignChoiceObjectRequest,
    GetCampaignChoiceObjectResponse, GetCampaignFindingObjectRequest,
    GetCampaignFindingObjectResponse, GetCampaignFrontierObjectRequest,
    GetCampaignFrontierObjectResponse, GetCampaignGraphObjectRequest,
    GetCampaignGraphObjectResponse, MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_QUERY_PAGE_ITEMS, QueryCampaignChoicesRequest, QueryCampaignChoicesResponse,
    QueryCampaignFindingsRequest, QueryCampaignFindingsResponse, QueryCampaignFrontierRequest,
    QueryCampaignFrontierResponse, QueryCampaignGraphRequest, QueryCampaignGraphResponse,
};
pub use ranking::{GetCampaignPlannerRankingsRequest, GetCampaignPlannerRankingsResponse};
pub use repository::{RepositoryCampaignService, RepositoryCampaignServiceError};
#[cfg(test)]
use repository::{repository_service_failure, store_service_failure};
pub use watch::{WatchCampaignRequest, WatchCampaignResponse};

const CAMPAIGN_SERVICE_SCHEMA_VERSION: u32 = 1;
const SUBMIT_CAMPAIGN_BRANCH_RESPONSE_SCHEMA_VERSION: u32 = 2;

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
    /// Enumerate authenticated current heads across the campaign namespace.
    ListCampaigns,
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
    /// Read one bounded page from the authenticated continuation frontier.
    QueryCampaignFrontier,
    /// Read complete finding records from the authenticated findings index.
    QueryCampaignFindings,
    /// Read one exact dependency named by an authenticated finding.
    GetCampaignFindingObject,
    /// Explain one exact attempt, execution basis, proposal, and completion.
    ExplainCampaignAttempt,
    /// Read one accepted planner step and its proof-bearing PUCT rankings.
    GetCampaignPlannerRankings,
    /// Read one exact branch-request body named by the authenticated frontier.
    GetCampaignFrontierObject,
    /// Read one exact declaration or domain named by an authenticated choice.
    GetCampaignChoiceObject,
    /// Apply one idempotent lifecycle, budget, or policy command.
    ApplyCampaignCommand,
    /// Apply one idempotent semantic configuration-pin command.
    PinCampaign,
    /// Submit one additive operator branch request.
    SubmitBranchRequest,
    /// Attach one daemon runtime to a local executor endpoint.
    AttachCampaignRuntime,
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

    /// Validates that this failure is meaningful for `ListCampaigns`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a name- or mutation-specific failure
    /// because a catalog scan cannot produce that outcome.
    pub fn validate_for_list_campaigns(self) -> Result<(), CampaignCodecError> {
        match self {
            Self::NotFound
            | Self::AlreadyExists
            | Self::Stale { .. }
            | Self::CommandReuse
            | Self::ConcurrentUpdate
            | Self::InvalidTransition { .. } => Err(CampaignCodecError::InvalidValue {
                reason: "campaign service failure is invalid for list campaigns",
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

    /// Validates a failure for one exact planner-ranking lookup.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this lookup's exact snapshot.
    pub fn validate_for_get_campaign_planner_rankings(
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

    /// Validates a failure for one exact campaign frontier query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this query's exact snapshot.
    pub fn validate_for_query_campaign_frontier(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        self.validate_for_query_campaign_graph(expected_snapshot)
    }

    /// Validates a failure for one exact campaign findings query.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this query's exact snapshot.
    pub fn validate_for_query_campaign_findings(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        self.validate_for_query_campaign_graph(expected_snapshot)
    }

    /// Validates a failure for one exact campaign finding-dependency read.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this request's exact snapshot.
    pub fn validate_for_get_campaign_finding_object(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        self.validate_for_query_campaign_graph(expected_snapshot)
    }

    /// Validates a failure for one exact campaign attempt explanation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this request's exact snapshot.
    pub fn validate_for_explain_campaign_attempt(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        self.validate_for_query_campaign_graph(expected_snapshot)
    }

    /// Validates a failure for one exact campaign frontier-object read.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this read's exact snapshot.
    pub fn validate_for_get_campaign_frontier_object(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        self.validate_for_query_campaign_graph(expected_snapshot)
    }

    /// Validates a failure for one exact campaign choice-object read.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or mutation-only failure,
    /// or when a stale failure does not describe this read's exact snapshot.
    pub fn validate_for_get_campaign_choice_object(
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

    /// Validates a failure for one exact semantic pin request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a create- or lifecycle-only failure,
    /// or when a stale failure does not describe this request's exact
    /// precondition.
    pub fn validate_for_pin_campaign(
        self,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(), CampaignCodecError> {
        match self {
            Self::AlreadyExists | Self::InvalidTransition { .. } => {
                Err(CampaignCodecError::InvalidValue {
                    reason: "campaign service failure is invalid for pin campaign",
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

    /// Validates a failure for one operational runtime attachment.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a creation-, snapshot-, or
    /// lifecycle-only failure that runtime attachment cannot produce.
    pub fn validate_for_attach_campaign_runtime(self) -> Result<(), CampaignCodecError> {
        match self {
            Self::AlreadyExists
            | Self::Stale { .. }
            | Self::ConcurrentUpdate
            | Self::InvalidTransition { .. } => Err(CampaignCodecError::InvalidValue {
                reason: "campaign service failure is invalid for runtime attachment",
            }),
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
    /// Authenticates and authorizes one all-campaign namespace request.
    ///
    /// The default denies access so existing authorizers cannot accidentally
    /// grant catalog discovery through a campaign-specific capability.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignAuthorizationError`] on denial or when authorization
    /// cannot be decided. Both outcomes fail before repository access.
    fn authorize_all_campaigns(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Err(CampaignAuthorizationError::Unauthorized)
    }

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

/// Strict request for one additive operator or exhaustive-policy branch source.
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
    summary: crate::BranchAcceptanceSummary,
    snapshot: CampaignSnapshot,
    acceptance_fact: CampaignFact,
    summary_recorded: bool,
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
            schema_version: SUBMIT_CAMPAIGN_BRANCH_RESPONSE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            prior_snapshot: result.prior_snapshot,
            new_snapshot: result.new_snapshot,
            request: result.request,
            summary: result.summary,
            snapshot: result.snapshot,
            acceptance_fact: result.acceptance_fact,
            summary_recorded: result.summary_recorded,
            replayed: result.replayed,
        };
        response.validate_for(request)?;
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

    /// Returns the immutable candidate and budget summary at acceptance.
    #[must_use]
    pub const fn summary(&self) -> crate::BranchAcceptanceSummary {
        self.summary
    }

    /// Returns whether the accepting transition recorded the summary.
    ///
    /// `false` identifies a legacy transition whose summary was owner-recomputed
    /// from its immutable original snapshot during replay.
    #[must_use]
    pub const fn summary_recorded(&self) -> bool {
        self.summary_recorded
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
        if self.request != request.request.id()? {
            Err(CampaignCodecError::InvalidValue {
                reason: "campaign branch response names another request",
            })
        } else if !self.replayed && self.prior_snapshot != request.expected_snapshot {
            Err(CampaignCodecError::InvalidValue {
                reason: "new campaign branch response has the wrong prior snapshot",
            })
        } else if !self.summary_recorded && !self.replayed {
            Err(CampaignCodecError::InvalidValue {
                reason: "new campaign branch response has an unrecorded summary",
            })
        } else if self.summary.maximum_proposals() != request.request.budget().maximum_proposals()
            || self.summary.maximum_attempts() != request.request.budget().maximum_attempts()
        {
            Err(CampaignCodecError::InvalidValue {
                reason: "campaign branch response has the wrong request budget",
            })
        } else {
            self.validate_acceptance_binding()
        }
    }

    fn validate_acceptance_binding(&self) -> Result<(), CampaignCodecError> {
        if self.snapshot.id()? != self.new_snapshot
            || self.snapshot.parent() != Some(self.prior_snapshot)
            || self.snapshot.transition() != Some(self.acceptance_fact.id()?)
            || if self.summary_recorded {
                self.acceptance_fact
                    != (CampaignFact::BranchRequestAccepted {
                        request: self.request,
                        summary: self.summary,
                    })
            } else {
                self.acceptance_fact != CampaignFact::BranchRequestIssued(self.request)
            }
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign branch summary is not bound to its accepting transition",
            });
        }
        Ok(())
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
        self.summary.encode(encoder);
        self.snapshot.encode(encoder);
        self.acceptance_fact.encode(encoder);
        self.summary_recorded.encode(encoder);
        self.replayed.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != SUBMIT_CAMPAIGN_BRANCH_RESPONSE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported campaign branch response schema version",
            });
        }
        let response = Self {
            schema_version: SUBMIT_CAMPAIGN_BRANCH_RESPONSE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            prior_snapshot: CampaignSnapshotId::decode(decoder)?,
            new_snapshot: CampaignSnapshotId::decode(decoder)?,
            request: crate::BranchRequestId::decode(decoder)?,
            summary: crate::BranchAcceptanceSummary::decode(decoder)?,
            snapshot: CampaignSnapshot::decode(decoder)?,
            acceptance_fact: CampaignFact::decode(decoder)?,
            summary_recorded: bool::decode(decoder)?,
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

    /// Returns one ordered page of authenticated current campaign heads.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when all-campaign
    /// authorization, repository access, or response construction fails.
    fn list_campaigns(
        &self,
        request: &ListCampaignsRequest,
    ) -> Result<ListCampaignsResponse, Self::Error>;

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

    /// Returns one bounded page from the authenticated continuation frontier.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, cursor validation, repository access, or
    /// response construction fails.
    fn query_campaign_frontier(
        &self,
        request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error>;

    /// Returns one bounded page from the authenticated findings index.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, cursor validation, repository access, or
    /// response construction fails.
    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, Self::Error>;

    /// Returns one exact dependency named by an authenticated finding.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, finding membership, dependency validation,
    /// repository access, or response construction fails.
    fn get_campaign_finding_object(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, Self::Error>;

    /// Returns one authenticated attempt with its execution provenance.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, attempt membership, provenance validation,
    /// repository access, or response construction fails.
    fn explain_campaign_attempt(
        &self,
        request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, Self::Error>;

    /// Returns one owner-authenticated planner step and its retained ranking basis.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, planner-step membership, retained-request
    /// validation, repository access, or response construction fails.
    fn get_campaign_planner_rankings(
        &self,
        request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error>;

    /// Returns one exact branch-request body authenticated by the frontier.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, frontier membership, repository access, or
    /// response construction fails.
    fn get_campaign_frontier_object(
        &self,
        request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error>;

    /// Returns one exact declaration or domain named by a discovered choice.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// snapshot precondition, opportunity membership, repository access, or
    /// response construction fails.
    fn get_campaign_choice_object(
        &self,
        request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, Self::Error>;

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

    /// Applies one exact idempotent semantic pin command.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific failure when authorization,
    /// graph membership, publication, or response construction fails.
    fn pin_campaign(
        &self,
        request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, Self::Error>;

    /// Submits one exact additive operator or exhaustive-policy branch request.
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

    /// Lists campaigns and validates exact response, order, cursor, and bounds.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different or malformed catalog request.
    pub fn list_campaigns(
        &self,
        request: &ListCampaignsRequest,
    ) -> Result<ListCampaignsResponse, CampaignClientError> {
        let response = match self.service.list_campaigns(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_list_campaigns()
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
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

    /// Gets one proof-bearing planner-ranking page and validates exact binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, planner step, retained request, or proof.
    pub fn get_campaign_planner_rankings(
        &self,
        request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, CampaignClientError> {
        let response = match self.service.get_campaign_planner_rankings(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_get_campaign_planner_rankings(request.snapshot())
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

    /// Queries one snapshot-bound frontier page and validates both Merkle proofs.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, nested index, projection page, or cursor.
    pub fn query_campaign_frontier(
        &self,
        request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, CampaignClientError> {
        let response = match self.service.query_campaign_frontier(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_query_campaign_frontier(request.snapshot())
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Queries one snapshot-bound finding page and validates its Merkle proof.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, finding page, or cursor relation.
    pub fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, CampaignClientError> {
        let response = match self.service.query_campaign_findings(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_query_campaign_findings(request.snapshot())
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Reads one finding dependency and validates its exact Merkle membership.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, finding, dependency kind, or object body.
    pub fn get_campaign_finding_object(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, CampaignClientError> {
        let response = match self.service.get_campaign_finding_object(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_get_campaign_finding_object(request.snapshot())
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Explains one attempt and validates its exact execution provenance.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, attempt, execution basis, proposal, path,
    /// selection, or completion state.
    pub fn explain_campaign_attempt(
        &self,
        request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, CampaignClientError> {
        let response = match self.service.explain_campaign_attempt(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_explain_campaign_attempt(request.snapshot())
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Reads one branch request and validates its exact frontier membership.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, projection, object body, or proof.
    pub fn get_campaign_frontier_object(
        &self,
        request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, CampaignClientError> {
        let response = match self.service.get_campaign_frontier_object(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_get_campaign_frontier_object(request.snapshot())
                    .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
                return Err(failure.into());
            }
        };
        response
            .validate_for(request)
            .map_err(|_| CampaignServiceFailure::ProtocolViolation)?;
        Ok(response)
    }

    /// Reads one choice dependency and validates its exact opportunity binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request, snapshot, opportunity, dependency, or proof.
    pub fn get_campaign_choice_object(
        &self,
        request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, CampaignClientError> {
        let response = match self.service.get_campaign_choice_object(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_get_campaign_choice_object(request.snapshot())
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

    /// Applies one semantic pin command and validates exact response binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignClientError`] when the service fails or answers a
    /// different request.
    pub fn pin_campaign(
        &self,
        request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, CampaignClientError> {
        let response = match self.service.pin_campaign(request) {
            Ok(response) => response,
            Err(error) => {
                let failure = error.campaign_service_failure();
                failure
                    .validate_for_pin_campaign(request.command().expected_snapshot)
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
mod tests;

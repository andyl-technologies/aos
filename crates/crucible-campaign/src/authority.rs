//! Language-neutral planner and debugger submission authorization.
//!
//! These control messages are operational component-boundary contracts, not
//! canonical campaign facts. Their strict binary form is:
//!
//! ```text
//! planner  = version | expected-snapshot | proposal | measured-usage | tag
//! debugger = version | expected-snapshot | debug-session | request | tag
//! ```
//!
//! The tag is a domain-separated keyed BLAKE3 authenticator over every field
//! before it. Large campaign objects remain referenced by their canonical IDs
//! inside the bounded proposal/request records.

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    BranchRequest, BranchRequestCause, CampaignCodecError, CampaignHash, CampaignSnapshotId,
    DebugSessionId, PlannerStepProposal, PlanningUsage,
};

const SUBMISSION_SCHEMA_VERSION: u32 = 1;
const MAX_SUBMISSION_BYTES: usize = 64 * 1024 * 1024;

/// Coordinator-configured secret used to authenticate pure-planner submissions.
///
/// The key is operational configuration. It is never encoded into campaign
/// objects, snapshots, exports, logs, or authorization messages, and it is
/// deliberately distinct from [`DebuggerAuthorityKey`].
#[derive(Clone)]
pub struct PlannerAuthorityKey([u8; 32]);

impl PlannerAuthorityKey {
    /// Builds a nonzero 256-bit planner authority key.
    ///
    /// # Errors
    ///
    /// Returns an error for an all-zero key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CampaignCodecError> {
        if bytes == [0_u8; 32] {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner authority key is all zero",
            });
        }
        Ok(Self(bytes))
    }

    pub(crate) fn has_same_material(&self, debugger: &DebuggerAuthorityKey) -> bool {
        constant_time_bytes_eq(&self.0, &debugger.0)
    }

    pub(crate) fn has_same_planner_material(&self, other: &Self) -> bool {
        constant_time_bytes_eq(&self.0, &other.0)
    }

    pub(crate) fn authenticate_component_basis(&self, domain: &str, basis: &[u8]) -> CampaignHash {
        authenticate(&self.0, domain, basis)
    }

    pub(crate) fn verify_component_basis(
        &self,
        domain: &str,
        basis: &[u8],
        actual: CampaignHash,
    ) -> bool {
        constant_time_hash_eq(self.authenticate_component_basis(domain, basis), actual)
    }
}

/// Coordinator-configured secret used to authenticate debugger submissions.
///
/// The key is operational configuration. It is never encoded into campaign
/// objects, snapshots, exports, logs, or authorization messages, and it is
/// deliberately distinct from [`PlannerAuthorityKey`].
#[derive(Clone)]
pub struct DebuggerAuthorityKey([u8; 32]);

impl DebuggerAuthorityKey {
    /// Builds a nonzero 256-bit debugger authority key.
    ///
    /// # Errors
    ///
    /// Returns an error for an all-zero key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CampaignCodecError> {
        if bytes == [0_u8; 32] {
            return Err(CampaignCodecError::InvalidValue {
                reason: "debugger authority key is all zero",
            });
        }
        Ok(Self(bytes))
    }
}

/// Authenticated pure-planner result submitted to the coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerSubmission {
    schema_version: u32,
    expected_snapshot: CampaignSnapshotId,
    proposal: PlannerStepProposal,
    measured_usage: PlanningUsage,
    authentication_tag: CampaignHash,
}

impl PlannerSubmission {
    /// Authenticates one bounded pure-planner result.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting message exceeds its wire bound.
    pub fn authorize(
        key: &PlannerAuthorityKey,
        expected_snapshot: CampaignSnapshotId,
        proposal: PlannerStepProposal,
        measured_usage: PlanningUsage,
    ) -> Result<Self, CampaignCodecError> {
        let authentication_tag = authenticate(
            &key.0,
            "crucible.campaign.planner-submission.v1",
            &planner_submission_basis(expected_snapshot, &proposal, measured_usage),
        );
        let submission = Self {
            schema_version: SUBMISSION_SCHEMA_VERSION,
            expected_snapshot,
            proposal,
            measured_usage,
            authentication_tag,
        };
        codec::ensure_encoded_size(
            &submission,
            MAX_SUBMISSION_BYTES,
            "planner-submission-encoded-bytes",
        )?;
        Ok(submission)
    }

    /// Returns the snapshot precondition authenticated by the planner adapter.
    #[must_use]
    pub const fn expected_snapshot(&self) -> CampaignSnapshotId {
        self.expected_snapshot
    }

    /// Returns the exact pure planner output.
    #[must_use]
    pub const fn proposal(&self) -> &PlannerStepProposal {
        &self.proposal
    }

    /// Returns coordinator-measurable usage supplied by the adapter.
    #[must_use]
    pub const fn measured_usage(&self) -> PlanningUsage {
        self.measured_usage
    }

    /// Verifies the submission against the coordinator's configured key.
    #[must_use]
    pub fn verify(&self, key: &PlannerAuthorityKey) -> bool {
        let expected = authenticate(
            &key.0,
            "crucible.campaign.planner-submission.v1",
            &planner_submission_basis(self.expected_snapshot, &self.proposal, self.measured_usage),
        );
        constant_time_hash_eq(expected, self.authentication_tag)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, or oversized input. The
    /// caller must still invoke [`Self::verify`] with trusted configuration.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_SUBMISSION_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "planner-submission-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }
}

impl Canonical for PlannerSubmission {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.proposal.encode(encoder);
        self.measured_usage.encode(encoder);
        self.authentication_tag.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_submission_version(u32::decode(decoder)?)?;
        Ok(Self {
            schema_version: SUBMISSION_SCHEMA_VERSION,
            expected_snapshot: CampaignSnapshotId::decode(decoder)?,
            proposal: PlannerStepProposal::decode(decoder)?,
            measured_usage: PlanningUsage::decode(decoder)?,
            authentication_tag: CampaignHash::decode(decoder)?,
        })
    }
}

/// Authenticated debugger branch request submitted to the coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebuggerSubmission {
    schema_version: u32,
    expected_snapshot: CampaignSnapshotId,
    session: DebugSessionId,
    request: BranchRequest,
    authentication_tag: CampaignHash,
}

impl DebuggerSubmission {
    /// Authenticates one declared-choice debugger branch request.
    ///
    /// # Errors
    ///
    /// Returns an error when the request does not name the supplied debugger
    /// session or when the message exceeds its wire bound.
    pub fn authorize(
        key: &DebuggerAuthorityKey,
        expected_snapshot: CampaignSnapshotId,
        session: DebugSessionId,
        request: BranchRequest,
    ) -> Result<Self, CampaignCodecError> {
        if request.cause() != BranchRequestCause::Debugger(session) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "debugger submission session does not match request cause",
            });
        }
        let authentication_tag = authenticate(
            &key.0,
            "crucible.campaign.debugger-submission.v1",
            &debugger_submission_basis(expected_snapshot, session, &request),
        );
        let submission = Self {
            schema_version: SUBMISSION_SCHEMA_VERSION,
            expected_snapshot,
            session,
            request,
            authentication_tag,
        };
        codec::ensure_encoded_size(
            &submission,
            MAX_SUBMISSION_BYTES,
            "debugger-submission-encoded-bytes",
        )?;
        Ok(submission)
    }

    /// Returns the authenticated snapshot precondition.
    #[must_use]
    pub const fn expected_snapshot(&self) -> CampaignSnapshotId {
        self.expected_snapshot
    }

    /// Returns the authenticated debug-session identity.
    #[must_use]
    pub const fn session(&self) -> DebugSessionId {
        self.session
    }

    /// Returns the exact debugger-caused branch request.
    #[must_use]
    pub const fn request(&self) -> &BranchRequest {
        &self.request
    }

    /// Verifies the submission against the coordinator's configured key.
    #[must_use]
    pub fn verify(&self, key: &DebuggerAuthorityKey) -> bool {
        self.request.cause() == BranchRequestCause::Debugger(self.session)
            && constant_time_hash_eq(
                authenticate(
                    &key.0,
                    "crucible.campaign.debugger-submission.v1",
                    &debugger_submission_basis(self.expected_snapshot, self.session, &self.request),
                ),
                self.authentication_tag,
            )
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized
    /// input. The caller must still invoke [`Self::verify`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_SUBMISSION_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "debugger-submission-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }
}

impl Canonical for DebuggerSubmission {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.session.encode(encoder);
        self.request.encode(encoder);
        self.authentication_tag.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_submission_version(u32::decode(decoder)?)?;
        let expected_snapshot = CampaignSnapshotId::decode(decoder)?;
        let session = DebugSessionId::decode(decoder)?;
        let request = BranchRequest::decode(decoder)?;
        if request.cause() != BranchRequestCause::Debugger(session) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "debugger submission session does not match request cause",
            });
        }
        Ok(Self {
            schema_version: SUBMISSION_SCHEMA_VERSION,
            expected_snapshot,
            session,
            request,
            authentication_tag: CampaignHash::decode(decoder)?,
        })
    }
}

fn planner_submission_basis(
    expected_snapshot: CampaignSnapshotId,
    proposal: &PlannerStepProposal,
    measured_usage: PlanningUsage,
) -> Vec<u8> {
    let mut encoder = Encoder::new();
    SUBMISSION_SCHEMA_VERSION.encode(&mut encoder);
    expected_snapshot.encode(&mut encoder);
    proposal.encode(&mut encoder);
    measured_usage.encode(&mut encoder);
    encoder.finish()
}

fn debugger_submission_basis(
    expected_snapshot: CampaignSnapshotId,
    session: DebugSessionId,
    request: &BranchRequest,
) -> Vec<u8> {
    let mut encoder = Encoder::new();
    SUBMISSION_SCHEMA_VERSION.encode(&mut encoder);
    expected_snapshot.encode(&mut encoder);
    session.encode(&mut encoder);
    request.encode(&mut encoder);
    encoder.finish()
}

fn constant_time_hash_eq(left: CampaignHash, right: CampaignHash) -> bool {
    constant_time_bytes_eq(&left.as_bytes(), &right.as_bytes())
}

fn constant_time_bytes_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn authenticate(key: &[u8; 32], domain: &str, bytes: &[u8]) -> CampaignHash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&(domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    CampaignHash::from_bytes(*hasher.finalize().as_bytes())
}

const fn require_submission_version(version: u32) -> Result<(), CampaignCodecError> {
    if version == SUBMISSION_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported component-submission schema version",
        })
    }
}

//! Authenticated restart recovery and single-use incorporation authority.

use super::*;

/// Strict authentication result for one production finding checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedFindingExactCheckpoint {
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    event_count: u64,
    metadata_bytes: u64,
}

impl AuthenticatedFindingExactCheckpoint {
    /// Builds one result after typed production-checkpoint validation succeeds.
    #[must_use]
    pub const fn new(
        scenario: ScenarioDefId,
        configuration: ConfigurationId,
        event_count: u64,
        metadata_bytes: u64,
    ) -> Self {
        Self {
            scenario,
            configuration,
            event_count,
            metadata_bytes,
        }
    }

    /// Returns the authenticated scenario identity.
    #[must_use]
    pub const fn scenario(self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the authenticated configuration identity.
    #[must_use]
    pub const fn configuration(self) -> ConfigurationId {
        self.configuration
    }

    /// Returns the authenticated scheduler event boundary.
    #[must_use]
    pub const fn event_count(self) -> u64 {
        self.event_count
    }

    /// Returns the root, manifest, and index bytes consumed by authentication.
    #[must_use]
    pub const fn metadata_bytes(self) -> u64 {
        self.metadata_bytes
    }
}

/// Stable failure class returned by a production-checkpoint authenticator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingExactCheckpointAuthenticationError {
    /// The checkpoint metadata exceeds the caller's remaining byte budget.
    LimitExceeded,
    /// Typed structure, identity, or execution-model validation failed.
    AuthenticationFailed,
}

/// Authenticates production checkpoints through their owning typed codecs.
pub trait FindingExactCheckpointAuthenticator: Send + Sync {
    /// Authenticates one checkpoint against the exact finding basis.
    ///
    /// Implementations must reject before allocation when root, manifest,
    /// index, scheduler, or scenario-derived object limits are exceeded.
    ///
    /// # Errors
    ///
    /// Returns a stable limit or authentication failure without accepting a
    /// partial, unknown-field, or merely structurally plausible checkpoint.
    fn authenticate_finding_exact_checkpoint(
        &self,
        checkpoint: crate::ExactCheckpointId,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        maximum_metadata_bytes: u64,
    ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>;

    /// Opens one authenticated object named by a selected checkpoint closure.
    ///
    /// The repository calls this only for the selected root or for a child
    /// discovered from an authenticated exact-manifest envelope. Implementors
    /// may defer content authentication until the returned stream reaches EOF.
    ///
    /// # Errors
    ///
    /// Returns an authentication failure when the object is absent, corrupt,
    /// or unavailable from the owning checkpoint store.
    fn read_finding_exact_checkpoint_object(
        &self,
        _object: ContentId,
    ) -> Result<BlobHandle, FindingExactCheckpointAuthenticationError> {
        Err(FindingExactCheckpointAuthenticationError::AuthenticationFailed)
    }
}

pub(in crate::repository) struct BoundFindingCandidateIncorporationAuthorization {
    pub(super) context_digest: CampaignHash,
    pub(super) operation_digest: CampaignHash,
}

pub(super) fn finding_candidate_incorporation_operation_digest(
    campaign: &str,
    expected_snapshot: CampaignSnapshotId,
    bundle: FindingCandidateBundleId,
    observation: ObservationId,
    context_digest: CampaignHash,
) -> CampaignHash {
    let mut material = Vec::with_capacity(768);
    for bytes in [
        campaign.as_bytes(),
        expected_snapshot.to_text().as_bytes(),
        bundle.to_text().as_bytes(),
        observation.to_text().as_bytes(),
    ] {
        material.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        material.extend_from_slice(bytes);
    }
    material.extend_from_slice(&context_digest.as_bytes());
    CampaignHash::derive(
        "crucible.campaign.finding-candidate-incorporation-operation.v1",
        &material,
    )
}

#[derive(Clone, Copy)]
pub(in crate::repository) enum FindingCandidateValidation<'a> {
    Publication(Option<&'a dyn FindingExactCheckpointAuthenticator>),
    Load,
}

/// Opaque proof that one snapshot directly retains a finding candidate bundle.
///
/// Values can be obtained only through
/// [`CampaignRepository::authenticate_current_finding_candidate_incorporation`],
/// which authenticates the named campaign's current authoritative head and the
/// finding's direct bundle reference before constructing the proof.
///
/// The proof records a point-in-time read. It does not pin the campaign head or
/// any immutable object and does not authorize a later unfenced root release.
/// A ledger owner must immediately reauthenticate the current head while
/// holding the operational GC/ledger-generation fence that covers its release
/// compare-and-swap.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedFindingCandidateIncorporation {
    pub(super) campaign: CampaignName,
    pub(super) bundle: FindingCandidateBundleId,
    pub(super) snapshot: CampaignSnapshotId,
    pub(super) finding: FindingId,
}

impl AuthenticatedFindingCandidateIncorporation {
    /// Returns the campaign whose authoritative head retains the finding.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact candidate bundle retained by the finding.
    #[must_use]
    pub const fn bundle(&self) -> FindingCandidateBundleId {
        self.bundle
    }

    /// Returns the authenticated snapshot containing the finding closure.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the finding that directly retains the candidate bundle.
    #[must_use]
    pub const fn finding(&self) -> FindingId {
        self.finding
    }
}

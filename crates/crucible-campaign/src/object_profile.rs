//! Canonical campaign object-profile derivation for composed stores.
//!
//! Campaign envelopes are decoded from complete authenticated bytes before
//! classification. Opaque extent kinds use their content-ID domain and exact
//! authenticated length. No request, caller, or placement hint participates.

use crucible_cas::content_store::{
    BlobHandle, ContentId, ObjectKind, ObjectProfile, Reconstructibility, RetentionRole,
    SensitivityClass, StoreError, StoreObjectProfiler,
};

use crate::object::{CampaignRecordKind, ObjectEnvelope};

const MAX_CAMPAIGN_ENVELOPE_BYTES: u64 = 64 * 1024 * 1024;

/// Stable policy identifier for the first canonical campaign profile mapping.
pub const CAMPAIGN_OBJECT_PROFILE_POLICY_V1: &str = "crucible.campaign.object-profile.v1";

/// Stateless canonical campaign object profiler.
#[derive(Clone, Copy, Debug, Default)]
pub struct CampaignObjectProfiler;

impl StoreObjectProfiler for CampaignObjectProfiler {
    fn derive_profile(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<ObjectProfile, StoreError> {
        if is_campaign_envelope_kind(id.kind()) {
            let bytes = source.read_all(MAX_CAMPAIGN_ENVELOPE_BYTES)?;
            let envelope = ObjectEnvelope::from_canonical_bytes_for_profile(&bytes)
                .map_err(|_| StoreError::Corrupt { id })?;
            if envelope.content_id() != id {
                return Err(StoreError::Incompatible);
            }
            return Ok(profile_record(
                envelope.record_kind(),
                source.logical_length(),
            ));
        }

        Ok(profile_opaque(id.kind(), source.logical_length()))
    }
}

fn is_campaign_envelope_kind(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::CampaignFact
            | ObjectKind::CampaignSnapshot
            | ObjectKind::MerkleNode
            | ObjectKind::Scenario
            | ObjectKind::Configuration
            | ObjectKind::Policy
            | ObjectKind::Observation
            | ObjectKind::Finding
            | ObjectKind::Projection
    )
}

fn profile_record(kind: CampaignRecordKind, logical_length: u64) -> ObjectProfile {
    use CampaignRecordKind as Record;

    if matches!(kind, Record::ConfigurationArtifact) {
        return ObjectProfile::new(
            kind.object_kind(),
            logical_length,
            SensitivityClass::GuestState,
            Reconstructibility::Canonical,
            RetentionRole::ExactState,
        );
    }
    if matches!(
        kind,
        Record::MeasurementSet
            | Record::PropertyVerdictSet
            | Record::Observation
            | Record::ObjectiveEvaluation
            | Record::ReproductionArtifact
            | Record::Finding
    ) {
        return ObjectProfile::new(
            kind.object_kind(),
            logical_length,
            SensitivityClass::Evidence,
            Reconstructibility::Canonical,
            RetentionRole::Evidence,
        );
    }
    if matches!(
        kind,
        Record::ExpansionState
            | Record::ContinuationProjection
            | Record::PlannerCandidateGuidance
            | Record::PlannerCandidateBudget
            | Record::CoverageProjection
            | Record::RankingExplanation
    ) {
        let sensitivity = if matches!(
            kind,
            Record::CoverageProjection | Record::RankingExplanation
        ) {
            SensitivityClass::Evidence
        } else {
            SensitivityClass::Metadata
        };
        return ObjectProfile::new(
            kind.object_kind(),
            logical_length,
            sensitivity,
            Reconstructibility::Rebuildable,
            RetentionRole::ProjectionCache,
        );
    }

    ObjectProfile::new(
        kind.object_kind(),
        logical_length,
        SensitivityClass::Metadata,
        Reconstructibility::Canonical,
        RetentionRole::CampaignMetadata,
    )
}

fn profile_opaque(kind: ObjectKind, logical_length: u64) -> ObjectProfile {
    match kind {
        ObjectKind::ExactManifest
        | ObjectKind::RamExtent
        | ObjectKind::DiskExtent
        | ObjectKind::DeviceState => ObjectProfile::new(
            kind,
            logical_length,
            SensitivityClass::GuestState,
            Reconstructibility::Canonical,
            RetentionRole::ExactState,
        ),
        ObjectKind::Trace => ObjectProfile::new(
            kind,
            logical_length,
            SensitivityClass::Evidence,
            Reconstructibility::Canonical,
            RetentionRole::Evidence,
        ),
        ObjectKind::Projection => ObjectProfile::new(
            kind,
            logical_length,
            SensitivityClass::Metadata,
            Reconstructibility::Rebuildable,
            RetentionRole::ProjectionCache,
        ),
        ObjectKind::Observation | ObjectKind::Finding => ObjectProfile::new(
            kind,
            logical_length,
            SensitivityClass::Evidence,
            Reconstructibility::Canonical,
            RetentionRole::Evidence,
        ),
        ObjectKind::Configuration => ObjectProfile::new(
            kind,
            logical_length,
            SensitivityClass::GuestState,
            Reconstructibility::Canonical,
            RetentionRole::ExactState,
        ),
        ObjectKind::CampaignFact
        | ObjectKind::CampaignSnapshot
        | ObjectKind::MerkleNode
        | ObjectKind::Scenario
        | ObjectKind::Policy => ObjectProfile::new(
            kind,
            logical_length,
            SensitivityClass::Metadata,
            Reconstructibility::Canonical,
            RetentionRole::CampaignMetadata,
        ),
    }
}

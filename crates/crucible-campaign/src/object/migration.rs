//! Structural envelope admission used only by offline campaign migration.
//!
//! Record body decoders for historical schemas live under
//! `repository::migration`. This module only admits the matching envelope
//! versions so that their authenticated child tables can be traversed before
//! any translation is staged. Normal object decoding does not call this path.

use crucible_cas::content_envelope::ContentEnvelope;

use super::{CampaignRecordKind, ObjectEnvelope};
use crate::CampaignCodecError;

/// Decodes a current envelope or one migration-owned historical envelope.
pub(crate) fn decode_historical_envelope(
    bytes: &[u8],
) -> Result<ObjectEnvelope, CampaignCodecError> {
    let envelope = ContentEnvelope::from_canonical_bytes(bytes)?;
    let record_kind = CampaignRecordKind::parse_schema_name(envelope.schema_name()).ok_or(
        CampaignCodecError::InvalidValue {
            reason: "unknown campaign record schema name",
        },
    )?;
    let historical = matches!(
        (record_kind, envelope.schema_version()),
        (CampaignRecordKind::Snapshot, 2)
            | (CampaignRecordKind::BudgetLedger, 1)
            | (CampaignRecordKind::AttemptAdmission, 1..=2)
            | (CampaignRecordKind::MeasurementSet, 1)
            | (CampaignRecordKind::Fact, 2..=14)
            | (CampaignRecordKind::BranchRequest, 1)
            | (CampaignRecordKind::PlannerStep, 3)
            | (CampaignRecordKind::BranchPath, 1)
            | (CampaignRecordKind::Finding, 1 | 3)
            | (CampaignRecordKind::PlannerCandidateBudget, 1)
            | (CampaignRecordKind::PlannerCandidateGuidance, 1)
    );
    if historical {
        return Ok(ObjectEnvelope {
            record_kind,
            envelope,
        });
    }
    ObjectEnvelope::from_canonical_bytes(bytes)
}

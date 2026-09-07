//! Reference validation for command-bearing campaign facts.

use super::*;

impl CampaignRepository {
    pub(super) fn validate_command_fact_references(
        &self,
        fact: &CampaignFact,
    ) -> Result<(), CampaignRepositoryError> {
        match fact {
            CampaignFact::ControlRequested(request) => {
                self.require_record_kind(
                    request.expected_snapshot.content_id(),
                    crate::CampaignRecordKind::Snapshot,
                )?;
                if let CampaignControlAction::ActivatePolicy(policy) = request.action {
                    self.require_record_kind(
                        policy.content_id(),
                        crate::CampaignRecordKind::Policy,
                    )?;
                }
            }
            CampaignFact::PinCommandAccepted(request) => {
                self.require_record_kind(
                    request.expected_snapshot.content_id(),
                    crate::CampaignRecordKind::Snapshot,
                )?;
            }
            CampaignFact::DiscoveryRequested(request) => {
                self.require_record_kind(
                    request.expected_snapshot.content_id(),
                    crate::CampaignRecordKind::Snapshot,
                )?;
                self.require_record_kind(
                    request.configuration.content_id(),
                    crate::CampaignRecordKind::ConfigurationArtifact,
                )?;
            }
            CampaignFact::SavepointCaptureRequested(request) => {
                self.require_record_kind(
                    request.expected_snapshot.content_id(),
                    crate::CampaignRecordKind::Snapshot,
                )?;
                self.require_record_kind(
                    request.attempt.content_id(),
                    crate::CampaignRecordKind::Attempt,
                )?;
                self.require_record_kind(
                    request.configuration.content_id(),
                    crate::CampaignRecordKind::ConfigurationArtifact,
                )?;
            }
            CampaignFact::SavepointCaptureResolved(resolution) => {
                self.require_record_kind(
                    resolution.expected_snapshot.content_id(),
                    crate::CampaignRecordKind::Snapshot,
                )?;
                self.require_record_kind(
                    resolution.request.content_id(),
                    crate::CampaignRecordKind::Fact,
                )?;
            }
            _ => return Err(integrity("campaign-fact-is-not-a-command-fact")),
        }
        Ok(())
    }
}

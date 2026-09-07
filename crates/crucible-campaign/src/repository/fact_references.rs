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
            _ => return Err(integrity("campaign-fact-is-not-a-command-fact")),
        }
        Ok(())
    }
}

//! Decode contracts.

use super::*;

impl CampaignFact {
    pub(super) fn decode_current(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::ChoiceOpportunityDiscovered {
                parent: ConfigurationArtifactId::decode(decoder)?,
                branch_point: BranchPointId::decode(decoder)?,
                opportunity: ChoiceOpportunityId::decode(decoder)?,
            }),
            1 => PlannerStepId::decode(decoder).map(Self::PlannerAdvanced),
            2 => ProposalId::decode(decoder).map(Self::ProposalIssued),
            3 => AttemptAdmissionId::decode(decoder).map(Self::AttemptAdmitted),
            4 => FindingId::decode(decoder).map(Self::FindingPublished),
            5 => PolicyActivation::decode(decoder).map(Self::PolicyActivated),
            6 => BudgetGrant::decode(decoder).map(Self::BudgetGranted),
            7 => ControlRequest::decode(decoder).map(Self::ControlRequested),
            8 => PinChange::decode(decoder).map(Self::PinChanged),
            9 => {
                let attempt = AttemptId::decode(decoder)?;
                let ordinal = AdmissionOrdinal::decode(decoder)?;
                let disposition = NonModeledAttemptDisposition::decode(decoder)?;
                Ok(Self::AttemptClosed {
                    attempt,
                    ordinal,
                    disposition,
                })
            }
            10 => CampaignDerivation::decode(decoder).map(Self::CampaignDerived),
            11 => ObservationId::decode(decoder).map(Self::ObservationCredited),
            12 => PinRequest::decode(decoder).map(Self::PinCommandAccepted),
            13 => ObjectiveEvaluationId::decode(decoder).map(Self::ObjectiveEvaluationPublished),
            14 => Ok(Self::BranchRequestAccepted {
                request: BranchRequestId::decode(decoder)?,
                summary: BranchAcceptanceSummary::decode(decoder)?,
            }),
            15 => DiscoveryRequest::decode(decoder).map(Self::DiscoveryRequested),
            16 => SavepointCaptureRequest::decode(decoder).map(Self::SavepointCaptureRequested),
            17 => SavepointCaptureResolution::decode(decoder).map(Self::SavepointCaptureResolved),
            18 => SavepointContinuationSelection::decode(decoder)
                .map(Self::SavepointContinuationSelected),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-fact",
                tag,
            }),
        }
    }
}

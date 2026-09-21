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
            1 => Err(CampaignCodecError::InvalidValue {
                reason: "unrecorded branch acceptance facts are not valid in the current schema",
            }),
            2 => PlannerStepId::decode(decoder).map(Self::PlannerAdvanced),
            3 => ProposalId::decode(decoder).map(Self::ProposalIssued),
            4 => AttemptAdmissionId::decode(decoder).map(Self::AttemptAdmitted),
            5 => Err(CampaignCodecError::InvalidValue {
                reason: "unscoped observation facts are not valid in the current schema",
            }),
            6 => FindingId::decode(decoder).map(Self::FindingPublished),
            7 => PolicyActivation::decode(decoder).map(Self::PolicyActivated),
            8 => BudgetGrant::decode(decoder).map(Self::BudgetGranted),
            9 => ControlRequest::decode(decoder).map(Self::ControlRequested),
            10 => PinChange::decode(decoder).map(Self::PinChanged),
            11 => {
                let attempt = AttemptId::decode(decoder)?;
                let ordinal = AdmissionOrdinal::decode(decoder)?;
                let disposition = NonModeledAttemptDisposition::decode(decoder)?;
                Ok(Self::AttemptClosed {
                    attempt,
                    ordinal,
                    disposition,
                })
            }
            12 => CampaignDerivation::decode(decoder).map(Self::CampaignDerived),
            13 => ObservationId::decode(decoder).map(Self::ObservationCredited),
            14 => PinRequest::decode(decoder).map(Self::PinCommandAccepted),
            15 => ObjectiveEvaluationId::decode(decoder).map(Self::ObjectiveEvaluationPublished),
            16 => Ok(Self::BranchRequestAccepted {
                request: BranchRequestId::decode(decoder)?,
                summary: BranchAcceptanceSummary::decode(decoder)?,
            }),
            17 => DiscoveryRequest::decode(decoder).map(Self::DiscoveryRequested),
            18 => SavepointCaptureRequest::decode(decoder).map(Self::SavepointCaptureRequested),
            19 => SavepointCaptureResolution::decode(decoder).map(Self::SavepointCaptureResolved),
            20 => SavepointContinuationSelection::decode(decoder)
                .map(Self::SavepointContinuationSelected),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-fact",
                tag,
            }),
        }
    }
}

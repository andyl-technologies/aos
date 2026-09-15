//! Decode contracts.

use super::*;

impl CampaignFact {
    pub(super) fn decode_versioned(
        decoder: &mut Decoder<'_>,
        extension: CampaignFactDecodeExtension,
    ) -> Result<Self, CampaignCodecError> {
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
                if disposition == NonModeledAttemptDisposition::TerminalWorkerFailure
                    && !matches!(
                        extension,
                        CampaignFactDecodeExtension::TerminalWorkerFailure
                            | CampaignFactDecodeExtension::All
                    )
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "terminal worker failure disposition requires campaign fact v10",
                    });
                }
                Ok(Self::AttemptClosed {
                    attempt,
                    ordinal,
                    disposition,
                })
            }
            12 if matches!(
                extension,
                CampaignFactDecodeExtension::Derivation | CampaignFactDecodeExtension::All
            ) =>
            {
                CampaignDerivation::decode(decoder).map(Self::CampaignDerived)
            }
            13 if matches!(
                extension,
                CampaignFactDecodeExtension::CreditedObservation | CampaignFactDecodeExtension::All
            ) =>
            {
                ObservationId::decode(decoder).map(Self::ObservationCredited)
            }
            14 if matches!(
                extension,
                CampaignFactDecodeExtension::PinCommand | CampaignFactDecodeExtension::All
            ) =>
            {
                PinRequest::decode(decoder).map(Self::PinCommandAccepted)
            }
            15 if matches!(
                extension,
                CampaignFactDecodeExtension::ObjectiveEvaluation | CampaignFactDecodeExtension::All
            ) =>
            {
                ObjectiveEvaluationId::decode(decoder).map(Self::ObjectiveEvaluationPublished)
            }
            16 if matches!(
                extension,
                CampaignFactDecodeExtension::BranchAcceptance | CampaignFactDecodeExtension::All
            ) =>
            {
                Ok(Self::BranchRequestAccepted {
                    request: BranchRequestId::decode(decoder)?,
                    summary: BranchAcceptanceSummary::decode(decoder)?,
                })
            }
            17 if matches!(
                extension,
                CampaignFactDecodeExtension::DiscoveryRequest | CampaignFactDecodeExtension::All
            ) =>
            {
                DiscoveryRequest::decode(decoder).map(Self::DiscoveryRequested)
            }
            18 if matches!(
                extension,
                CampaignFactDecodeExtension::SavepointCapture | CampaignFactDecodeExtension::All
            ) =>
            {
                SavepointCaptureRequest::decode(decoder).map(Self::SavepointCaptureRequested)
            }
            19 if matches!(
                extension,
                CampaignFactDecodeExtension::SavepointCaptureResolution
                    | CampaignFactDecodeExtension::All
            ) =>
            {
                SavepointCaptureResolution::decode(decoder).map(Self::SavepointCaptureResolved)
            }
            20 if matches!(
                extension,
                CampaignFactDecodeExtension::SavepointContinuationSelection
                    | CampaignFactDecodeExtension::All
            ) =>
            {
                SavepointContinuationSelection::decode(decoder)
                    .map(Self::SavepointContinuationSelected)
            }
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-fact",
                tag,
            }),
        }
    }
}

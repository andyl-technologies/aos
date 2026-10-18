//! Versioned constraint-result evidence for atomic group proposals.

use crate::CampaignCodecError;
use crate::choice::group::{CHOICE_GROUP_SCHEMA_VERSION, ChoiceGroup, ChoiceGroupValue};
use crate::codec::{Canonical, Decoder, Encoder};

const GROUP_CONSTRAINT_SCHEMA_VERSION: u32 = 1;

/// Result of checking a complete group tuple against its exact domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChoiceGroupConstraintResult {
    /// Every member domain and relational constraint admitted the tuple.
    Admitted,
}

impl Canonical for ChoiceGroupConstraintResult {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(1);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            1 => Ok(Self::Admitted),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "choice-group-constraint-result",
                tag,
            }),
        }
    }
}

/// Schema-bound result carried by each atomic group proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChoiceGroupConstraintEvidence {
    group_schema_version: u32,
    constraint_schema_version: u32,
    result: ChoiceGroupConstraintResult,
}

impl ChoiceGroupConstraintEvidence {
    pub(crate) const fn admitted() -> Self {
        Self {
            group_schema_version: CHOICE_GROUP_SCHEMA_VERSION,
            constraint_schema_version: GROUP_CONSTRAINT_SCHEMA_VERSION,
            result: ChoiceGroupConstraintResult::Admitted,
        }
    }

    /// Returns the exact group schema used to interpret the tuple.
    #[must_use]
    pub const fn group_schema_version(self) -> u32 {
        self.group_schema_version
    }

    /// Returns the constraint-result schema version.
    #[must_use]
    pub const fn constraint_schema_version(self) -> u32 {
        self.constraint_schema_version
    }

    /// Returns the recorded result of checking the complete tuple.
    #[must_use]
    pub const fn result(self) -> ChoiceGroupConstraintResult {
        self.result
    }

    /// Recomputes the result against the exact group definition.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a version mismatch, different group,
    /// incomplete tuple, or failed member or relational constraint.
    pub fn validate_resolved(
        self,
        value: &ChoiceGroupValue,
        group: &ChoiceGroup,
    ) -> Result<(), CampaignCodecError> {
        if self != Self::admitted() || group.schema_version() != self.group_schema_version {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group constraint evidence uses an unsupported schema",
            });
        }
        value.validate_resolved(group)
    }
}

impl Canonical for ChoiceGroupConstraintEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.group_schema_version.encode(encoder);
        self.constraint_schema_version.encode(encoder);
        self.result.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let evidence = Self {
            group_schema_version: u32::decode(decoder)?,
            constraint_schema_version: u32::decode(decoder)?,
            result: ChoiceGroupConstraintResult::decode(decoder)?,
        };
        if evidence != Self::admitted() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group constraint evidence uses an unsupported schema",
            });
        }
        Ok(evidence)
    }
}

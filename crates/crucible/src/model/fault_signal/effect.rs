//! Validated executable effect requests and resolved replay records.

use super::{
    ContentHash, EFFECT_SEMANTIC_VERSION, EffectKind, EffectLifetime, FaultCapabilityId,
    FaultContractError, FaultCoordinate, FaultObjectId, FaultPhase, NetworkEffectSpecification,
    NodeEffectSpecification, ResolvedFaultTarget, StorageEffectSpecification,
};

/// The complete closed parameter union accepted by production adapters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "adapter", content = "parameters", rename_all = "snake_case")]
pub enum EffectSpecification {
    /// A network effect.
    Network(NetworkEffectSpecification),
    /// A block, flash, array, or 9p effect.
    Storage(StorageEffectSpecification),
    /// A node or QEMU-backed effect.
    Node(NodeEffectSpecification),
}

impl EffectSpecification {
    /// Returns the exact registry kind selected by this parameter schema.
    #[must_use]
    pub const fn kind(&self) -> EffectKind {
        match self {
            Self::Network(effect) => effect.kind(),
            Self::Storage(effect) => effect.kind(),
            Self::Node(effect) => effect.kind(),
        }
    }

    /// Validates cross-field invariants in the selected closed schema.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError`] when dependent fields violate the effect
    /// kind's parameter contract.
    pub fn validate(&self) -> Result<(), FaultContractError> {
        match self {
            Self::Network(effect) => effect.validate(),
            Self::Storage(effect) => effect.validate(),
            Self::Node(effect) => effect.validate(),
        }
    }
}

/// A validated effect template selected by one fault binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "EffectRequestWire", deny_unknown_fields)]
pub struct EffectRequest {
    specification: EffectSpecification,
    lifetime: EffectLifetime,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectRequestWire {
    specification: EffectSpecification,
    lifetime: EffectLifetime,
}

impl TryFrom<EffectRequestWire> for EffectRequest {
    type Error = FaultContractError;

    fn try_from(value: EffectRequestWire) -> Result<Self, Self::Error> {
        Self::new(EFFECT_SEMANTIC_VERSION, value.lifetime, value.specification)
    }
}

impl EffectRequest {
    /// Validates an effect schema version, parameters, and lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::EffectVersionMismatch`] for any semantic
    /// version other than the exact implemented version,
    /// [`FaultContractError::UnsupportedLifetime`] when the lifetime is absent
    /// from the registry descriptor, or a parameter validation error.
    pub fn new(
        semantic_version: u16,
        lifetime: EffectLifetime,
        specification: EffectSpecification,
    ) -> Result<Self, FaultContractError> {
        let kind = specification.kind();
        if semantic_version != EFFECT_SEMANTIC_VERSION {
            return Err(FaultContractError::EffectVersionMismatch {
                effect: kind,
                expected: EFFECT_SEMANTIC_VERSION,
                actual: semantic_version,
            });
        }
        specification.validate()?;
        if !kind.descriptor().lifetimes.contains(&lifetime) {
            return Err(FaultContractError::UnsupportedLifetime {
                effect: kind,
                lifetime,
            });
        }
        Ok(Self {
            specification,
            lifetime,
        })
    }

    /// Returns the exact registered effect kind.
    #[must_use]
    pub const fn kind(&self) -> EffectKind {
        self.specification.kind()
    }

    /// Returns the validated effect lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> EffectLifetime {
        self.lifetime
    }

    /// Returns the closed typed parameters.
    #[must_use]
    pub const fn specification(&self) -> &EffectSpecification {
        &self.specification
    }

    /// Returns the production capability required by this effect kind.
    #[must_use]
    pub const fn capability(&self) -> &'static str {
        self.kind().descriptor().capability
    }
}

/// One contributor to a resolved, combined effect.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct EffectContributor {
    /// Binding identity used for deterministic ordering.
    pub binding: FaultObjectId,
    /// Digest of the mapped contribution before composition.
    pub contribution_digest: ContentHash,
}

/// Exact effect evidence consumed by recomputed and locked replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedEffectRecord {
    /// Stable effect kind.
    pub effect: EffectKind,
    /// Exact effect semantic version.
    pub semantic_version: u16,
    /// Binding that requested the effect before composition.
    pub binding: FaultObjectId,
    /// Concrete resolved target.
    pub target: ResolvedFaultTarget,
    /// Opportunity identity for opportunity-scoped effects.
    pub opportunity: Option<ContentHash>,
    /// Scheduler coordinate at application.
    pub coordinate: FaultCoordinate,
    /// Exact adapter application phase.
    pub phase: FaultPhase,
    /// Effect lifetime.
    pub lifetime: EffectLifetime,
    /// Digest of canonical mapped parameters.
    pub parameters_digest: ContentHash,
    /// Contributors in canonical binding order.
    pub contributors: Vec<EffectContributor>,
    /// Production capability used to apply the effect.
    pub capability: FaultCapabilityId,
    /// Optional before-state digest required for destructive locked replay.
    pub precondition_digest: Option<ContentHash>,
    /// Digest of all effect-specific replay evidence.
    pub evidence_digest: ContentHash,
}

impl ResolvedEffectRecord {
    /// Validates record ordering, capability version, target, and opportunity
    /// requirements before it may be retained or replayed.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError`] for a semantic-version mismatch, illegal
    /// target, missing opportunity identity, duplicate/unsorted contributors,
    /// or capability mismatch.
    pub fn validate(&self) -> Result<(), FaultContractError> {
        if self.semantic_version != EFFECT_SEMANTIC_VERSION {
            return Err(FaultContractError::EffectVersionMismatch {
                effect: self.effect,
                expected: EFFECT_SEMANTIC_VERSION,
                actual: self.semantic_version,
            });
        }
        self.target.validate()?;
        let descriptor = self.effect.descriptor();
        if !descriptor.targets.contains(&self.target.kind()) {
            return Err(FaultContractError::EffectTargetMismatch {
                effect: self.effect,
                target: self.target.kind(),
            });
        }
        if !descriptor.phases.contains(&self.phase) {
            return Err(FaultContractError::EffectPhaseMismatch {
                effect: self.effect,
                phase: self.phase,
            });
        }
        if !descriptor.lifetimes.contains(&self.lifetime) {
            return Err(FaultContractError::UnsupportedLifetime {
                effect: self.effect,
                lifetime: self.lifetime,
            });
        }
        if descriptor.lifetimes.contains(&EffectLifetime::Opportunity)
            && self.lifetime == EffectLifetime::Opportunity
            && self.opportunity.is_none()
        {
            return Err(FaultContractError::MissingOpportunity {
                effect: self.effect,
            });
        }
        if self
            .contributors
            .windows(2)
            .any(|pair| pair[0].binding >= pair[1].binding)
        {
            return Err(FaultContractError::NonCanonicalContributors);
        }
        if self.capability.as_str() != descriptor.capability {
            return Err(FaultContractError::CapabilityMismatch {
                effect: self.effect,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fault_signal::FaultDirection;

    fn availability_record() -> ResolvedEffectRecord {
        let binding = match FaultObjectId::parse("network-outage") {
            Ok(value) => value,
            Err(error) => panic!("test binding must be valid: {error}"),
        };
        let segment = match FaultObjectId::parse("wan-segment") {
            Ok(value) => value,
            Err(error) => panic!("test segment must be valid: {error}"),
        };
        let capability = match FaultCapabilityId::parse("network.availability.v1") {
            Ok(value) => value,
            Err(error) => panic!("test capability must be valid: {error}"),
        };
        ResolvedEffectRecord {
            effect: EffectKind::NetworkAvailability,
            semantic_version: EFFECT_SEMANTIC_VERSION,
            binding,
            target: ResolvedFaultTarget::NetworkSegment {
                segment,
                direction: FaultDirection::AToB,
            },
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 1,
                retired_instructions: None,
            },
            phase: FaultPhase::Admit,
            lifetime: EffectLifetime::Persistent,
            parameters_digest: ContentHash::from_bytes(b"parameters"),
            contributors: Vec::new(),
            capability,
            precondition_digest: None,
            evidence_digest: ContentHash::from_bytes(b"evidence"),
        }
    }

    #[test]
    fn resolved_record_rejects_an_illegal_phase() {
        let mut record = availability_record();
        record.phase = FaultPhase::Deliver;
        assert_eq!(
            record.validate(),
            Err(FaultContractError::EffectPhaseMismatch {
                effect: EffectKind::NetworkAvailability,
                phase: FaultPhase::Deliver,
            })
        );
    }

    #[test]
    fn resolved_record_rejects_an_illegal_lifetime() {
        let mut record = availability_record();
        record.lifetime = EffectLifetime::Impulse;
        assert_eq!(
            record.validate(),
            Err(FaultContractError::UnsupportedLifetime {
                effect: EffectKind::NetworkAvailability,
                lifetime: EffectLifetime::Impulse,
            })
        );
    }
}

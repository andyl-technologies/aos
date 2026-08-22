//! Validated executable effect requests and resolved replay records.

use super::{
    BindingActionCause, BindingActionKind, ContentHash, EFFECT_SEMANTIC_VERSION, EffectKind,
    EffectLifetime, FaultCapabilityId, FaultContractError, FaultCoordinate, FaultDirection,
    FaultObjectId, FaultOperation, FaultOpportunity, FaultPhase, NetworkEffectSpecification,
    NodeEffectSpecification, ResolvedBindingAction, ResolvedFaultTarget, ResolvedMappingOutput,
    StorageEffectSpecification,
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
        let clock_impulse_supported = !matches!(
            (&specification, lifetime),
            (
                EffectSpecification::Node(NodeEffectSpecification::ClockTransform {
                    mutation: super::ClockMutation::Freeze { .. }
                        | super::ClockMutation::Jitter { .. }
                        | super::ClockMutation::Wander { .. },
                    ..
                }),
                EffectLifetime::Impulse
            )
        );
        if !kind.descriptor().lifetimes.contains(&lifetime) || !clock_impulse_supported {
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedEffectRecord {
    /// Stable effect kind.
    pub effect: EffectKind,
    /// Exact effect semantic version.
    pub semantic_version: u16,
    /// Exact adapter action lifecycle operation.
    pub action_kind: BindingActionKind,
    /// Binding that requested the effect before composition.
    pub binding: FaultObjectId,
    /// Concrete resolved target.
    pub target: ResolvedFaultTarget,
    /// Opportunity identity for opportunity-scoped effects.
    pub opportunity: Option<ContentHash>,
    /// Exact adapter operation, when this is an opportunity outcome.
    pub operation: Option<FaultOperation>,
    /// Exact link direction, when this is a directional opportunity outcome.
    pub direction: Option<FaultDirection>,
    /// Coordinate-independent immutable network-frame identity.
    pub network_frame_key: Option<ContentHash>,
    /// Stable producer/direction/sequence network alignment identity.
    pub network_producer_direction_key: Option<ContentHash>,
    /// Scheduler coordinate refined with the backend application coordinate.
    pub coordinate: FaultCoordinate,
    /// Stable order among scheduler work at the same coordinate.
    pub same_coordinate_sequence: u64,
    /// Exact adapter application phase.
    pub phase: FaultPhase,
    /// Effect lifetime.
    pub lifetime: EffectLifetime,
    /// Complete admitted typed effect used by locked replay.
    pub request: EffectRequest,
    /// Complete typed mapping result used by locked replay.
    pub mapping_output: ResolvedMappingOutput,
    /// Digest of canonical mapped parameters.
    pub parameters_digest: ContentHash,
    /// Binding transition sequence carried by the resolved action.
    pub transition_sequence: u64,
    /// Exact transition identity carried by the resolved action.
    pub cause: BindingActionCause,
    /// Fingerprint of the complete post-derivation signal/binding continuation.
    ///
    /// This authenticates sampled signal state, state-machine transitions,
    /// keyed choices, event-log cursors, and binding execution state for
    /// recomputed-cause replay.
    pub derivation_fingerprint: ContentHash,
    /// Contributors in canonical binding order.
    pub contributors: Vec<EffectContributor>,
    /// Production capability used to apply the effect.
    pub capability: FaultCapabilityId,
    /// Backend-observed before-state digest required for every replayed effect.
    pub precondition_digest: Option<ContentHash>,
    /// Digest of all effect-specific replay evidence.
    pub evidence_digest: ContentHash,
}

impl ResolvedEffectRecord {
    /// Reports whether `coordinate` is the scheduler coordinate for this record.
    pub(super) fn refines_work_item_coordinate(&self, coordinate: FaultCoordinate) -> bool {
        if self.effect.descriptor().adapter == super::FaultAdapter::Node {
            coordinate.accepts_backend_refinement(self.coordinate)
        } else {
            coordinate == self.coordinate
        }
    }

    /// Captures one committed typed action and its backend evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError`] if the action capability identifier is
    /// invalid or the resulting record violates the effect registry.
    pub fn from_committed_action(
        action: &ResolvedBindingAction,
        opportunity: Option<&FaultOpportunity>,
        same_coordinate_sequence: u64,
        derivation_fingerprint: ContentHash,
        precondition_digest: Option<ContentHash>,
        evidence_digest: ContentHash,
    ) -> Result<Self, FaultContractError> {
        if opportunity.map(FaultOpportunity::id) != action.opportunity {
            return Err(FaultContractError::MissingOpportunity {
                effect: action.effect.kind(),
            });
        }
        let record = Self {
            effect: action.effect.kind(),
            semantic_version: EFFECT_SEMANTIC_VERSION,
            action_kind: action.kind,
            binding: action.binding.clone(),
            target: action.target.clone(),
            opportunity: action.opportunity,
            operation: opportunity.map(FaultOpportunity::operation),
            direction: opportunity.and_then(FaultOpportunity::direction),
            network_frame_key: opportunity.and_then(FaultOpportunity::network_frame_key),
            network_producer_direction_key: opportunity
                .and_then(FaultOpportunity::network_producer_direction_key),
            coordinate: action.coordinate,
            same_coordinate_sequence,
            phase: action.phase,
            lifetime: action.effect.lifetime(),
            request: action.effect.as_ref().clone(),
            mapping_output: action.mapping_output.as_ref().clone(),
            parameters_digest: action.mapped_digest,
            transition_sequence: action.transition_sequence,
            cause: action.cause.clone(),
            derivation_fingerprint,
            contributors: vec![EffectContributor {
                binding: action.binding.clone(),
                contribution_digest: action.mapped_digest,
            }],
            capability: FaultCapabilityId::parse(action.effect.capability())?,
            precondition_digest,
            evidence_digest,
        };
        record.validate()?;
        Ok(record)
    }

    /// Reconstructs the exact typed action retained for locked replay.
    #[must_use]
    pub fn locked_action(&self) -> ResolvedBindingAction {
        ResolvedBindingAction {
            kind: self.action_kind,
            binding: self.binding.clone(),
            target: self.target.clone(),
            phase: self.phase,
            effect: std::sync::Arc::new(self.request.clone()),
            mapping_output: std::sync::Arc::new(self.mapping_output.clone()),
            mapped_digest: self.parameters_digest,
            transition_sequence: self.transition_sequence,
            opportunity: self.opportunity,
            coordinate: self.coordinate,
            cause: self.cause.clone(),
            expected_precondition: self.precondition_digest,
        }
    }

    /// Returns whether a recomputed action exactly matches the recorded resolution.
    #[must_use]
    pub fn matches_recomputed_action(&self, action: &ResolvedBindingAction) -> bool {
        let coordinate_matches = action.accepts_observation_coordinate(self.coordinate);
        let mut action = action.clone();
        action.coordinate = self.coordinate;
        coordinate_matches
            && self.locked_action()
                == ResolvedBindingAction {
                    expected_precondition: self.precondition_digest,
                    ..action
                }
    }

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
        if self.request.kind() != self.effect
            || self.request.lifetime() != self.lifetime
            || matches!(self.action_kind, BindingActionKind::Apply)
                == matches!(self.lifetime, EffectLifetime::Persistent)
        {
            return Err(FaultContractError::UnsupportedLifetime {
                effect: self.effect,
                lifetime: self.lifetime,
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
        if self.precondition_digest.is_none() {
            return Err(FaultContractError::MissingReplayPrecondition {
                effect: self.effect,
            });
        }
        if self.opportunity.is_none()
            && (self.operation.is_some()
                || self.direction.is_some()
                || self.network_frame_key.is_some()
                || self.network_producer_direction_key.is_some())
        {
            return Err(FaultContractError::InvalidPayload);
        }
        if self.network_frame_key.is_some() != self.network_producer_direction_key.is_some() {
            return Err(FaultContractError::InvalidPayload);
        }
        if self.network_frame_key.is_some()
            && (self.operation.is_none()
                || self.opportunity.is_none()
                || self.effect.descriptor().adapter != super::FaultAdapter::Network)
        {
            return Err(FaultContractError::InvalidPayload);
        }
        if descriptor.adapter == super::FaultAdapter::Node
            && self.coordinate.retired_instructions.is_none()
        {
            return Err(FaultContractError::InvalidPayload);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fault_signal::{
        ClockFreezeReleasePolicy, ClockMonotonicityPolicy, ClockMutation, ClockOverdueTimerPolicy,
        FaultDirection, NetworkAvailabilityState, NetworkInFlightPolicy,
    };

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
            action_kind: BindingActionKind::UpsertPersistent,
            binding,
            target: ResolvedFaultTarget::NetworkSegment {
                segment,
                direction: FaultDirection::AToB,
            },
            opportunity: None,
            operation: None,
            direction: None,
            network_frame_key: None,
            network_producer_direction_key: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 1,
                retired_instructions: None,
            },
            same_coordinate_sequence: 0,
            phase: FaultPhase::Admit,
            lifetime: EffectLifetime::Persistent,
            request: EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Persistent,
                EffectSpecification::Network(NetworkEffectSpecification::Availability {
                    state: NetworkAvailabilityState::Down,
                    queued_policy: NetworkInFlightPolicy::Drop,
                    in_flight_policy: NetworkInFlightPolicy::Drop,
                }),
            )
            .unwrap_or_else(|error| panic!("test request must be valid: {error}")),
            mapping_output: ResolvedMappingOutput::Activation { active: true },
            parameters_digest: ContentHash::from_bytes(b"parameters"),
            transition_sequence: 1,
            cause: BindingActionCause::Signal,
            derivation_fingerprint: ContentHash::from_bytes(b"derivation"),
            contributors: Vec::new(),
            capability,
            precondition_digest: Some(ContentHash::from_bytes(b"before")),
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

    #[test]
    fn clock_impulse_rejects_mutations_that_require_retained_state() {
        let source = FaultObjectId::parse("x86-tsc-vcpu-0")
            .unwrap_or_else(|error| panic!("test source must be valid: {error}"));
        let specification = |mutation| {
            EffectSpecification::Node(NodeEffectSpecification::ClockTransform {
                source: source.clone(),
                mutation,
                monotonicity: ClockMonotonicityPolicy::ClampMonotonic,
                overdue_timer_policy: ClockOverdueTimerPolicy::FireAtBoundary,
            })
        };
        assert!(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Impulse,
                specification(ClockMutation::Offset { offset_nanos: 1 }),
            )
            .is_ok()
        );
        assert_eq!(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Impulse,
                specification(ClockMutation::Freeze {
                    value_nanos: 7,
                    release: ClockFreezeReleasePolicy::ResumeFromFrozen,
                }),
            ),
            Err(FaultContractError::UnsupportedLifetime {
                effect: EffectKind::ClockTransform,
                lifetime: EffectLifetime::Impulse,
            })
        );
    }

    #[test]
    fn resolved_record_requires_before_state_for_every_replay_action() {
        let mut record = availability_record();
        record.precondition_digest = None;
        assert_eq!(
            record.validate(),
            Err(FaultContractError::MissingReplayPrecondition {
                effect: EffectKind::NetworkAvailability,
            })
        );
    }
}

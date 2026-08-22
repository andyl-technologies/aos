//! Stable fault-observation vocabulary and canonical event-log material.

use super::*;

/// Stable event classes emitted by signal-driven fault execution.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum FaultObservationKind {
    /// A signal changed value.
    SignalTransition,
    /// A retained signal sample was evaluated.
    SignalSample,
    /// A stateful signal node changed state.
    SignalStateTransition,
    /// A binding installed a persistent contribution.
    BindingActivation,
    /// A binding removed its contribution.
    BindingDeactivation,
    /// An adapter exposed an opportunity.
    FaultOpportunity,
    /// A keyed hazard or search choice was resolved.
    EffectChoice,
    /// Simultaneous contributions were combined.
    EffectCombined,
    /// A production adapter committed an impulse or opportunity action.
    EffectCommitted,
    /// A production adapter applied an effect.
    EffectApplied,
    /// Application failed closed.
    EffectRejected,
    /// A directional network profile changed.
    NetworkProfile,
    /// A route, attachment, beam, or contact changed.
    AssociationTransition,
    /// A recorded outcome aligned with an opportunity.
    TraceAlignment,
}

impl FaultObservationKind {
    /// Returns the stable unified-event-log kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignalTransition => "signal_transition",
            Self::SignalSample => "signal_sample",
            Self::SignalStateTransition => "signal_state_transition",
            Self::BindingActivation => "binding_activation",
            Self::BindingDeactivation => "binding_deactivation",
            Self::FaultOpportunity => "fault_opportunity",
            Self::EffectChoice => "effect_choice",
            Self::EffectCombined => "effect_combined",
            Self::EffectCommitted => "effect_committed",
            Self::EffectApplied => "effect_applied",
            Self::EffectRejected => "effect_rejected",
            Self::NetworkProfile => "network_profile",
            Self::AssociationTransition => "association_transition",
            Self::TraceAlignment => "trace_alignment",
        }
    }
}

/// One stable typed fault-observation record.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FaultObservation {
    /// Event schema semantic version.
    pub semantic_version: u16,
    /// Event class.
    pub kind: FaultObservationKind,
    /// Scheduler coordinate.
    pub coordinate: FaultCoordinate,
    /// Optional binding identity.
    pub binding: Option<FaultObjectId>,
    /// Optional concrete target.
    pub target: Option<ResolvedFaultTarget>,
    /// Optional opportunity identity.
    pub opportunity: Option<ContentHash>,
    /// Content-addressed typed evidence payload.
    pub evidence: ContentHash,
}

impl FaultObservation {
    /// Returns the stable material authenticated by event-log entries.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        [
            format!("semantic_version={}", self.semantic_version),
            format!("kind={}", self.kind.as_str()),
            format!("coordinate.virtual_nanos={}", self.coordinate.virtual_nanos),
            format!(
                "coordinate.retired_instructions={}",
                self.coordinate
                    .retired_instructions
                    .map_or_else(|| String::from("none"), |value| value.to_string())
            ),
            format!(
                "binding={}",
                self.binding
                    .as_ref()
                    .map_or("none", |binding| binding.as_str())
            ),
            format!(
                "target={}",
                self.target.as_ref().map_or_else(
                    || String::from("none"),
                    ResolvedFaultTarget::canonical_material,
                )
            ),
            format!(
                "opportunity={}",
                self.opportunity
                    .map_or_else(|| String::from("none"), |value| value.to_hex())
            ),
            format!("evidence={}", self.evidence.to_hex()),
        ]
        .join("\n")
    }
}

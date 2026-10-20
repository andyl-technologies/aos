//! Wraps canonical portable evidence with the original Native completion type.
//!
//! The lower engine returns ordinary Core completion DATA. Only these original
//! constructors create this module's opaque journal-completion value.

use aos_sandbox_core::runtime_backend::{BackendExecutionInspectionV1,
    BackendExecutionInventoryV1, DurableExecutionEffectV1, EffectCompletionV1};
pub use aos_sandbox_protocol::execution_evidence::{ObserveCompletionEvidenceV1,
    RuntimeExecutionEvidenceError, decode_cancel_completion_phase_v1,
    decode_control_completion_phase_v1, decode_authorize_completion_running_v1,
    decode_authorize_completion_binding_v1, decode_observe_completion_running_v1,
    decode_observe_completion_phase_v1, decode_observe_completion_evidence_v1};
pub(crate) use aos_sandbox_protocol::execution_evidence::{
    validate_completion, completion_observes_terminal_execution};

/// Owns a completion derived from an exact backend observation.
///
/// Its fields are private so callers cannot substitute arbitrary result bytes
/// at the protected journal completion boundary.
pub struct JournalExecutionCompletionV1 {
    completion: EffectCompletionV1,
}

impl JournalExecutionCompletionV1 {
    /// Borrows the exact portable completion for an atomic journal commit.
    #[must_use]
    pub const fn completion(&self) -> &EffectCompletionV1 {
        &self.completion
    }
}

/// Derives the original Native completion from exact typed backend evidence.
///
/// # Errors
/// Rejects foreign observation bindings or a phase that cannot complete this effect.
pub fn completion_from_backend_observation_v1(
    effect: &DurableExecutionEffectV1,
    observation: BackendExecutionInspectionV1,
) -> Result<JournalExecutionCompletionV1, RuntimeExecutionEvidenceError> {
    aos_sandbox_protocol::execution_evidence::completion_from_backend_observation_v1(effect, observation)
        .map(|completion| JournalExecutionCompletionV1 { completion })
}

pub(crate) fn completion_from_authenticated_absence_v1(
    effect: &DurableExecutionEffectV1,
    inventory: &BackendExecutionInventoryV1,
) -> Result<JournalExecutionCompletionV1, RuntimeExecutionEvidenceError> {
    aos_sandbox_protocol::execution_evidence::completion_from_authenticated_absence_v1(effect, inventory)
        .map(|completion| JournalExecutionCompletionV1 { completion })
}

pub(crate) fn completion_from_authenticated_quarantine_v1(
    effect: &DurableExecutionEffectV1,
    inventory: &BackendExecutionInventoryV1,
) -> Result<JournalExecutionCompletionV1, RuntimeExecutionEvidenceError> {
    aos_sandbox_protocol::execution_evidence::completion_from_authenticated_quarantine_v1(effect, inventory)
        .map(|completion| JournalExecutionCompletionV1 { completion })
}


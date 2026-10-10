//! Fixed failure boundaries in authenticated qualification Enqueue replies.
//!
//! Diagnostics retain no error value and authorize no recovery or dispatch.
//! The original Result determines fallback exactly as before. A recovery phase
//! names the last probe operation entered before its error was swallowed; it is
//! separate from the later operation that refused Enqueue. Missing fields do not
//! establish successful recovery or provider settlement.
//!
//! ```text
//! {"state":"refused_or_unknown","failurePhase":"fallback_begin",
//!  "recoveryFailurePhase":"read_lease"}
//! ```

use std::cell::Cell;

use serde::{Deserialize, Serialize};

/// Names the existing Enqueue operation entered before a refused result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EnqueuePhase {
    OriginalContext,
    InstalledConfiguration,
    ClosedRecord,
    RecoveryPreparation,
    FallbackPreparation,
    FallbackBegin,
    QueuePreparation,
    QueueBinding,
    QueueSend,
}

/// Names the existing stage creation step entered before a refused result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BeginPhase {
    OriginalContext,
    AdmissionJournal,
    ProtectedMaterial,
    StageEffect,
    ExternalPreparation,
    ExternalExecution,
}

/// Names the existing recovery probe operation entered before fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryPhase {
    Preparation,
    Lookup,
    TerminalValidation,
    RecoveryRead,
    ReadLease,
    Authentication,
}

/// Retains closed categories only, without retaining any failure payload.
pub(crate) struct Diagnostics {
    begin_phase: Cell<Option<BeginPhase>>,
    phase: Cell<EnqueuePhase>,
    recovery_phase: Cell<RecoveryPhase>,
    recovery_failure: Cell<Option<RecoveryPhase>>,
}

impl Diagnostics {
    /// Starts before the existing original/runtime checks for Enqueue only.
    pub(crate) fn new() -> Self {
        Self {
            begin_phase: Cell::new(None),
            phase: Cell::new(EnqueuePhase::OriginalContext),
            recovery_phase: Cell::new(RecoveryPhase::Preparation),
            recovery_failure: Cell::new(None),
        }
    }

    /// Starts a stage creation trace without reporting an Enqueue phase.
    pub(crate) fn for_begin() -> Self {
        let diagnostics = Self::new();
        diagnostics
            .begin_phase
            .set(Some(BeginPhase::OriginalContext));
        diagnostics
    }

    /// Starts a new object's recovery probe without borrowing a previous failure.
    pub(crate) fn begin_recovery(&self) {
        self.phase.set(EnqueuePhase::RecoveryPreparation);
        self.recovery_phase.set(RecoveryPhase::Preparation);
        self.recovery_failure.set(None);
    }

    /// Marks an existing recovery operation before it can fail.
    pub(crate) fn recovery(&self, phase: RecoveryPhase) {
        self.recovery_phase.set(phase);
    }
}

/// Marks optional Enqueue diagnostics without changing ordinary callers.
pub(crate) fn enter(diagnostics: Option<&Diagnostics>, phase: EnqueuePhase) {
    if let Some(diagnostics) = diagnostics {
        diagnostics.phase.set(phase);
    }
}

/// Records only the fixed step name on an explicitly selected Begin trace.
pub(crate) fn enter_begin(diagnostics: Option<&Diagnostics>, phase: BeginPhase) {
    if let Some(diagnostics) = diagnostics {
        diagnostics.begin_phase.set(Some(phase));
    }
}

/// Preserves the existing fallback decision and observes only its fixed boundary.
///
/// Neither the successful value nor the error is consumed, formatted or stored.
pub(crate) fn needs_fresh<T, E>(
    diagnostics: Option<&Diagnostics>,
    recovery: &Result<T, E>,
) -> bool {
    if recovery.is_err() {
        if let Some(diagnostics) = diagnostics {
            diagnostics
                .recovery_failure
                .set(Some(diagnostics.recovery_phase.get()));
        }
        true
    } else {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    RefusedOrUnknown,
}

/// Adds optional fixed diagnostics inside the already authenticated result.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Refusal {
    state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    begin_failure_phase: Option<BeginPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_phase: Option<EnqueuePhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_failure_phase: Option<RecoveryPhase>,
}

/// Snapshots only observation state; the caller's actual error remains unknown.
pub(crate) fn refused(diagnostics: Option<&Diagnostics>) -> Refusal {
    Refusal {
        state: State::RefusedOrUnknown,
        begin_failure_phase: diagnostics.and_then(|diagnostics| diagnostics.begin_phase.get()),
        failure_phase: diagnostics
            .filter(|diagnostics| diagnostics.begin_phase.get().is_none())
            .map(|diagnostics| diagnostics.phase.get()),
        recovery_failure_phase: diagnostics
            .and_then(|diagnostics| diagnostics.recovery_failure.get()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_reports_only_its_selected_step() {
        let diagnostics = Diagnostics::for_begin();
        enter_begin(Some(&diagnostics), BeginPhase::ExternalPreparation);

        assert_eq!(
            serde_json::to_value(refused(Some(&diagnostics))).unwrap(),
            serde_json::json!({"state":"refused_or_unknown",
                "beginFailurePhase":"external_preparation"})
        );
        assert_eq!(refused(None).begin_failure_phase, None);
    }

    // Deliberately not Serialize: the production helper cannot capture errors.
    struct OpaqueFault(&'static str);

    #[test]
    fn failed_probe_preserves_error_and_phase_through_fresh_failure() {
        let diagnostics = Diagnostics::new();
        diagnostics.begin_recovery();
        diagnostics.recovery(RecoveryPhase::ReadLease);
        let recovery: Result<(), _> = Err(OpaqueFault("unit-only-secret https://unit.invalid"));

        assert!(needs_fresh(Some(&diagnostics), &recovery));
        enter(Some(&diagnostics), EnqueuePhase::FallbackPreparation);
        enter(Some(&diagnostics), EnqueuePhase::FallbackBegin);
        let failure = refused(Some(&diagnostics));

        assert_eq!(
            recovery.err().unwrap().0,
            "unit-only-secret https://unit.invalid"
        );
        assert_eq!(failure.failure_phase, Some(EnqueuePhase::FallbackBegin));
        assert_eq!(
            failure.recovery_failure_phase,
            Some(RecoveryPhase::ReadLease)
        );
        let encoded = serde_json::to_string(&failure).unwrap();
        assert!(!encoded.contains("unit-only-secret"));
        assert!(!encoded.contains("https://"));
        assert!(encoded.len() < 256);
        assert_eq!(serde_json::from_str::<Refusal>(&encoded).unwrap(), failure);
    }

    #[test]
    fn successful_probe_skips_fresh_and_none_preserves_old_result() {
        let diagnostics = Diagnostics::new();
        diagnostics.begin_recovery();
        diagnostics.recovery(RecoveryPhase::TerminalValidation);
        let recovery: Result<_, OpaqueFault> = Ok(7);

        assert!(!needs_fresh(Some(&diagnostics), &recovery));
        assert!(!needs_fresh(None, &recovery));
        assert_eq!(recovery.ok(), Some(7));
        assert_eq!(refused(Some(&diagnostics)).recovery_failure_phase, None);
        assert!(needs_fresh(
            None,
            &Err::<(), _>(OpaqueFault("not serialized"))
        ));
        assert_eq!(
            serde_json::to_value(refused(None)).unwrap(),
            serde_json::json!({"state":"refused_or_unknown"})
        );
    }

    #[test]
    fn new_probe_cannot_attribute_previous_failure_and_schema_is_closed() {
        let diagnostics = Diagnostics::new();
        diagnostics.begin_recovery();
        diagnostics.recovery(RecoveryPhase::RecoveryRead);
        assert!(needs_fresh(
            Some(&diagnostics),
            &Err::<(), _>(OpaqueFault("first"))
        ));

        diagnostics.begin_recovery();
        diagnostics.recovery(RecoveryPhase::Lookup);
        assert!(needs_fresh(
            Some(&diagnostics),
            &Err::<(), _>(OpaqueFault("second"))
        ));
        enter(Some(&diagnostics), EnqueuePhase::QueueSend);
        let result = serde_json::to_value(refused(Some(&diagnostics))).unwrap();

        assert_eq!(
            result,
            serde_json::json!({"state":"refused_or_unknown",
            "failurePhase":"queue_send","recoveryFailurePhase":"lookup"})
        );
        let mut unknown = result.clone();
        unknown["error"] = "raw input".into();
        assert!(serde_json::from_value::<Refusal>(unknown).is_err());
        let mut invalid = result;
        invalid["recoveryFailurePhase"] = "provider exception".into();
        assert!(serde_json::from_value::<Refusal>(invalid).is_err());
    }
}

//! Value-free progress after an authenticated qualification queue Begin.
//!
//! Fixed phases locate an unfinished attempt without exposing errors or material.
//! Missing telemetry is unknown. A positive finish records only the actual queue
//! Finish reply, not independent provider settlement or runtime qualification.
//!
//! ```text
//! direct_qualification_attempt {"version":1,"phase":"semantic_source_proof",...
//!   "outcome":"unknown","commitments":{"attemptNonce":"<64 lowerhex>",...}}
//! ```

use std::cell::Cell;

use serde::{Deserialize, Serialize};

/// Bounds each diagnostic independently of provider or exception text.
const MAX_RECORD_BYTES: usize = 2048;

/// Reports a fixed read-failure category without provider or credential text.
#[cfg(feature = "do-e2e")]
pub(crate) fn record_read_failure(error: &anyhow::Error) {
    use aos_hub_core::storage_work::StorageWorkError;

    let category = error
        .chain()
        .find_map(|cause| {
            if let Some(StorageWorkError::InvalidSnapshot) =
                cause.downcast_ref::<StorageWorkError>()
            {
                return Some("binding_snapshot_invalid");
            }

            match cause.to_string().as_str() {
                "immutable read resource window expired or unbounded" => {
                    Some("read_window_expired")
                }
                "configured request original deadline elapsed" => Some("request_deadline_elapsed"),
                "immutable read canceled" => Some("read_canceled"),
                "direct external Native publication permission expired" => {
                    Some("publication_permission_expired")
                }
                "private stage binding differs from independent publication" => {
                    Some("binding_changed")
                }
                "original logical stage eligibility expired" => {
                    Some("original_eligibility_expired")
                }
                _ => None,
            }
        })
        .unwrap_or("unclassified");

    worker::console_log!("direct_verification_read_failed {}", category);
}

/// Names the existing operation being entered, without claiming it completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    InstalledMaterial,
    CurrentMaterial,
    ImmutableIntegrityRead,
    ImmutableParts,
    ImmutableStagePreparation,
    ImmutableStageDispatch,
    SemanticCapacity,
    SemanticMaterial,
    SemanticLease,
    SemanticSourceProof,
    SemanticRequestValidation,
    SemanticDispatch,
    SemanticResponseChecks,
    SemanticBodyIntegrity,
    SemanticProjection,
    RetainedProof,
    Finish,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Pending,
    Unknown,
    Positive,
}

/// Commits the authenticated Begin and exact immutable queue input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Commitments {
    /// Exact nonce already retained by the durable qualification Begin.
    pub(crate) attempt_nonce: String,
    /// Original commitment already authenticated by the queue owner.
    pub(crate) original_digest: String,
    /// Existing canonical journal digest of the actual verification job.
    pub(crate) job_digest: String,
    /// SHA-256 of the selected run identifier, without its raw value.
    pub(crate) run_digest: String,
    /// SHA-256 of the selected object identifier, without its raw value.
    pub(crate) object_digest: String,
    /// SHA-256 of the actual source identity's UTF-8 representation.
    pub(crate) source_digest: String,
    /// SHA-256 of the actual script version's UTF-8 representation.
    pub(crate) script_digest: String,
}

impl Commitments {
    fn bounded(&self) -> bool {
        [
            &self.attempt_nonce,
            &self.original_digest,
            &self.job_digest,
            &self.run_digest,
            &self.object_digest,
            &self.source_digest,
            &self.script_digest,
        ]
        .into_iter()
        .all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    }
}

/// Contains only fixed categories, original commitments and observed time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Record {
    version: u32,
    commitments: Commitments,
    started_at_millis: u64,
    at_millis: u64,
    phase: Phase,
    outcome: Outcome,
}

impl Record {
    fn encoded(&self) -> Option<String> {
        let text = serde_json::to_string(self).ok()?;
        (self.commitments.bounded() && text.len() <= MAX_RECORD_BYTES).then_some(text)
    }
}

/// Retains the last entered phase until an actual Finish reply or local drop.
pub(crate) struct Attempt {
    record: Record,
    phase: Cell<Phase>,
    finished: Cell<bool>,
    sink: fn(&Record),
}

impl Attempt {
    /// Starts bounded diagnostics only after the real Begin has been retained.
    ///
    /// Invalid observation commitments disable telemetry without changing work.
    pub(crate) fn new(commitments: Commitments, started_at_millis: u64) -> Option<Self> {
        Self::with_sink(commitments, started_at_millis, emit)
    }

    fn with_sink(
        commitments: Commitments,
        started_at_millis: u64,
        sink: fn(&Record),
    ) -> Option<Self> {
        if !commitments.bounded() {
            return None;
        }
        let attempt = Self {
            record: Record {
                version: 1,
                commitments,
                started_at_millis,
                at_millis: started_at_millis,
                phase: Phase::InstalledMaterial,
                outcome: Outcome::Pending,
            },
            phase: Cell::new(Phase::InstalledMaterial),
            finished: Cell::new(false),
            sink,
        };
        attempt.publish(Outcome::Pending);
        Some(attempt)
    }

    /// Marks an existing operation before it can wait or fail.
    pub(crate) fn enter(&self, phase: Phase) {
        if !self.finished.get() && self.phase.replace(phase) != phase {
            self.publish(Outcome::Pending);
        }
    }

    /// Marks positive only after the authenticated Finish call returns success.
    pub(crate) fn finished(&self) {
        if self.phase.get() == Phase::Finish && !self.finished.replace(true) {
            self.publish(Outcome::Positive);
        }
    }

    fn publish(&self, outcome: Outcome) {
        let mut record = self.record.clone();
        record.phase = self.phase.get();
        record.outcome = outcome;
        (self.sink)(&record);
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.finished.get() {
            self.publish(Outcome::Unknown);
        }
    }
}

/// Advances optional fixture diagnostics without changing ordinary verification.
pub(crate) fn enter(attempt: Option<&Attempt>, phase: Phase) {
    if let Some(attempt) = attempt {
        attempt.enter(phase);
    }
}

fn emit(record: &Record) {
    #[cfg(target_arch = "wasm32")]
    {
        let mut record = record.clone();
        record.at_millis = worker::Date::now().as_millis();
        if let Some(text) = record.encoded() {
            worker::console_log!("direct_qualification_attempt {}", text);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = record.encoded();
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    thread_local! {
        static RECORDS: RefCell<Vec<Record>> = const { RefCell::new(Vec::new()) };
    }

    fn capture(record: &Record) {
        RECORDS.with(|records| records.borrow_mut().push(record.clone()));
    }

    fn commitments() -> Commitments {
        Commitments {
            attempt_nonce: "11".repeat(32),
            original_digest: "22".repeat(32),
            job_digest: "33".repeat(32),
            run_digest: "44".repeat(32),
            object_digest: "55".repeat(32),
            source_digest: "66".repeat(32),
            script_digest: "77".repeat(32),
        }
    }

    fn take() -> Vec<Record> {
        RECORDS.with(|records| std::mem::take(&mut *records.borrow_mut()))
    }

    #[test]
    fn entered_phase_and_drop_preserve_unknown_without_finish() {
        take();
        let binding = commitments();
        {
            let attempt = Attempt::with_sink(binding.clone(), 123, capture).unwrap();
            attempt.enter(Phase::CurrentMaterial);
            attempt.enter(Phase::ImmutableIntegrityRead);
            attempt.enter(Phase::SemanticLease);
            attempt.enter(Phase::SemanticSourceProof);
            attempt.enter(Phase::SemanticSourceProof);
            // Completing another phase cannot manufacture an accepted Finish.
            attempt.finished();
        }

        let records = take();
        assert_eq!(records.len(), 6);
        assert_eq!(records.last().unwrap().phase, Phase::SemanticSourceProof);
        assert_eq!(records.last().unwrap().outcome, Outcome::Unknown);
        assert!(records.iter().all(|record| record.commitments == binding));
        assert!(!records
            .iter()
            .any(|record| record.outcome == Outcome::Positive));
    }

    #[test]
    fn actual_finish_is_positive_once_and_optional_tracking_is_inert() {
        take();
        {
            let attempt = Attempt::with_sink(commitments(), 123, capture).unwrap();
            attempt.enter(Phase::RetainedProof);
            attempt.enter(Phase::Finish);
            attempt.finished();
            attempt.finished();
            attempt.enter(Phase::SemanticDispatch);
        }
        enter(None, Phase::SemanticDispatch);

        let records = take();
        assert_eq!(records.len(), 4);
        assert_eq!(records.last().unwrap().phase, Phase::Finish);
        assert_eq!(records.last().unwrap().outcome, Outcome::Positive);
        assert!(!records
            .iter()
            .any(|record| record.outcome == Outcome::Unknown));
    }

    #[test]
    fn closed_serialization_refuses_unbounded_or_value_bearing_fields() {
        take();
        let attempt = Attempt::with_sink(commitments(), 123, capture).unwrap();
        for phase in [
            Phase::ImmutableParts,
            Phase::ImmutableStagePreparation,
            Phase::ImmutableStageDispatch,
            Phase::SemanticMaterial,
            Phase::SemanticRequestValidation,
            Phase::SemanticDispatch,
            Phase::SemanticResponseChecks,
            Phase::SemanticBodyIntegrity,
            Phase::SemanticProjection,
        ] {
            attempt.enter(phase);
        }
        drop(attempt);

        for record in take() {
            let text = record.encoded().unwrap();
            assert!(text.len() <= MAX_RECORD_BYTES);
            assert_eq!(serde_json::from_str::<Record>(&text).unwrap(), record);
            let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
            value["error"] = "provider credential or response".into();
            assert!(serde_json::from_value::<Record>(value).is_err());
            assert!(!text.contains("credential"));
            assert!(!text.contains("http"));
        }
        let mut invalid = commitments();
        invalid.job_digest = "https://provider.invalid/secret".into();
        assert!(Attempt::with_sink(invalid, 123, capture).is_none());
        let mut oversized = commitments();
        oversized.script_digest = "a".repeat(MAX_RECORD_BYTES);
        assert!(Attempt::with_sink(oversized, 123, capture).is_none());
        assert!(take().is_empty());
    }
}

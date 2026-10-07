//! Bounded summaries of separate, completed publication Commit phases.
//!
//! A summary is request-local source evidence, including when a later operation
//! returns an error. It never claims one atomic transaction, current SQL reader
//! authority, payload classification, or publication visibility. Counts and
//! commitments aggregate repeated placement events without retaining an object
//! list or one child per manifest object.
//!
//! ```text
//! {"version":1,"terminalOutcome":"returned_error","phases":[...]}
//! ```

use super::{canonical, canonical_image, EncodedImage};
use crate::clock::{observation_unix_nanos, Instant};
use anyhow::{ensure, Result};
use aos_proto_types::CommitRegistryPublicationRequest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_BYTES: u64 = 16 * 1024;
const MAX_PHASES: usize = 16;

/// Names only actual successful boundaries in the ordinary Commit path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The ordinary claims and registry Publish permission checks succeeded.
    Authorized,
    /// Both required object classes passed their existing completeness queries.
    CompletenessChecked,
    /// The preparing publication entered or was observed in writing-pointers.
    PointerPhaseOpened,
    /// One selected placement's existing pointer-advance operation returned.
    PointerAdvanceBegun,
    /// One selected placement's existing pointer-finalization operation returned.
    PointerAdvanceFinalized,
    /// The real checked mutable-object promotion batch completed.
    MutableObjectsPromoted,
    /// The writing-pointers to ready transition completed successfully.
    PublicationReady,
    /// The current-publication head CAS returned successfully.
    CurrentHeadSet,
    /// The actual delivery-manifest refresh returned successfully.
    DeliveryRefreshed,
    /// The ordinary lease-release call returned.
    LeaseReleaseReturned,
    /// The index refresh invocation returned, without claiming index readiness.
    IndexRefreshReturned,
    /// Existing ready-publication recovery restored its retained object evidence.
    ReadyEvidenceRestored,
    /// The actual final publication response was materialized successfully.
    ResponseMaterialized,
}

/// Separates handler return from overall publication or index qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    /// The ordinary handler returned its successful result.
    ReturnedSuccess,
    /// The ordinary handler returned an error after zero or more phases.
    ReturnedError,
    /// No final handler result was observed by the source scope.
    Incomplete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedPhase {
    phase: Phase,
    completed_calls: String,
    completed_items: String,
    chain_sha256: String,
    first_completed_unix_nanos: String,
    last_completed_unix_nanos: String,
}

/// Retains bounded phase facts without granting metadata or SQL authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Summary {
    version: u8,
    producer_sha256: String,
    publication_id: String,
    request: EncodedImage,
    source_before_unix_nanos: String,
    source_after_unix_nanos: Option<String>,
    source_elapsed_nanos: Option<String>,
    terminal_outcome: TerminalOutcome,
    phases: Vec<CompletedPhase>,
}

impl Summary {
    /// Checks a bounded summary against the exact selected typed request.
    ///
    /// This validates the source DTO and commitments only. It does not establish
    /// log custody, authentication, SQL authority, atomicity or visibility.
    ///
    /// # Errors
    ///
    /// Rejects a foreign request/source, unsupported or duplicate phase, invalid
    /// decimal/count/time commitment, incomplete return fields or excess size.
    pub fn validate_original(&self, request: &CommitRegistryPublicationRequest) -> Result<()> {
        ensure!(
            self.version == 1 && self.phases.len() <= MAX_PHASES && self.encoded().is_some(),
            "publication phase schema/bound differs"
        );
        let image = canonical_image(request, 32 * 1024)
            .ok_or_else(|| anyhow::anyhow!("publication original exceeds bound"))?;
        ensure!(
            self.publication_id == request.publication_id
                && self.request.byte_size == image.byte_size
                && self.request.sha256 == image.sha256
                && self.producer_sha256 == producer_sha256(),
            "publication phase original/source differs"
        );
        let before = decimal::<u128>(&self.source_before_unix_nanos)?;
        let after = match self.terminal_outcome {
            TerminalOutcome::Incomplete => {
                ensure!(
                    self.source_after_unix_nanos.is_none() && self.source_elapsed_nanos.is_none(),
                    "incomplete phase summary invents a returned boundary"
                );
                None
            }
            TerminalOutcome::ReturnedSuccess | TerminalOutcome::ReturnedError => {
                let after = decimal::<u128>(
                    self.source_after_unix_nanos
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("missing publication terminal clock"))?,
                )?;
                decimal::<u128>(
                    self.source_elapsed_nanos
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("missing publication elapsed clock"))?,
                )?;
                ensure!(after >= before, "publication source clock rolled backwards");
                Some(after)
            }
        };
        let mut seen = Vec::new();
        for phase in &self.phases {
            ensure!(!seen.contains(&phase.phase), "duplicate publication phase");
            seen.push(phase.phase);
            ensure!(
                decimal::<u64>(&phase.completed_calls)? > 0,
                "empty completed phase"
            );
            decimal::<u64>(&phase.completed_items)?;
            let first = decimal::<u128>(&phase.first_completed_unix_nanos)?;
            let last = decimal::<u128>(&phase.last_completed_unix_nanos)?;
            ensure!(
                first >= before && last >= first && after.is_none_or(|after| last <= after),
                "phase boundary lies outside original source bracket"
            );
            ensure!(
                phase.chain_sha256.len() == 64
                    && phase
                        .chain_sha256
                        .bytes()
                        .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value)),
                "phase commitment differs"
            );
        }
        Ok(())
    }

    /// Encodes only a complete bounded summary, including returned errors.
    #[must_use]
    pub fn encoded(&self) -> Option<Vec<u8>> {
        let raw = serde_json::to_vec(self).ok()?;
        (raw.len() as u64 <= MAX_BYTES).then_some(raw)
    }

    /// Returns the observed handler outcome without asserting publication success.
    #[must_use]
    pub fn terminal_outcome(&self) -> TerminalOutcome {
        self.terminal_outcome
    }
}

fn decimal<T: std::str::FromStr + ToString>(value: &str) -> Result<T> {
    let parsed = value
        .parse::<T>()
        .map_err(|_| anyhow::anyhow!("invalid phase decimal"))?;
    ensure!(parsed.to_string() == value, "noncanonical phase decimal");
    Ok(parsed)
}

fn producer_sha256() -> String {
    let mut producer = Sha256::new();
    producer.update(include_bytes!("publication.rs"));
    producer.update(include_bytes!("../application_body_observation.rs"));
    producer.update(include_bytes!("../service.rs"));
    producer.update(include_bytes!("../db/mod.rs"));
    producer.update(include_bytes!("../db/publication_delivery.rs"));
    hex::encode(producer.finalize())
}

pub(super) struct Accumulator {
    summary: Summary,
    start: Instant,
    invalid: bool,
}

/// Begins a single actual Commit request inside the existing optional scope.
pub(crate) fn begin(request: &CommitRegistryPublicationRequest) {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = super::ENABLED.try_with(|scope| {
        let Ok(mut scope) = scope.try_borrow_mut() else {
            return;
        };
        if let Some(existing) = scope.publication.as_mut() {
            existing.invalid = true;
            return;
        }
        let (Some(image), Some(before)) = (canonical(request, 32 * 1024), observation_unix_nanos())
        else {
            return;
        };
        scope.publication = Some(Accumulator {
            summary: Summary {
                version: 1,
                producer_sha256: producer_sha256(),
                publication_id: request.publication_id.clone(),
                request: image,
                source_before_unix_nanos: before.to_string(),
                source_after_unix_nanos: None,
                source_elapsed_nanos: None,
                terminal_outcome: TerminalOutcome::Incomplete,
                phases: Vec::new(),
            },
            start: Instant::now(),
            invalid: false,
        });
    });
    #[cfg(target_arch = "wasm32")]
    let _ = request;
}

/// Aggregates only an already successful call's actual selected values.
pub(crate) fn completed<T: Serialize>(publication_id: &str, phase: Phase, items: u64, values: &T) {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = super::ENABLED.try_with(|scope| {
        let Ok(mut scope) = scope.try_borrow_mut() else {
            return;
        };
        let Some(accumulator) = scope.publication.as_mut() else {
            return;
        };
        if accumulator.invalid || accumulator.summary.publication_id != publication_id {
            accumulator.invalid = true;
            return;
        }
        let (Some(image), Some(now)) =
            (canonical(values, 8 * 1024 * 1024), observation_unix_nanos())
        else {
            accumulator.invalid = true;
            return;
        };
        if accumulator
            .summary
            .source_before_unix_nanos
            .parse::<u128>()
            .ok()
            .is_none_or(|before| now < before)
        {
            accumulator.invalid = true;
            return;
        }
        let phases = &mut accumulator.summary.phases;
        let position = phases.iter().position(|entry| entry.phase == phase);
        let entry = match position {
            Some(index) => &mut phases[index],
            None if phases.len() < MAX_PHASES => {
                phases.push(CompletedPhase {
                    phase,
                    completed_calls: "0".into(),
                    completed_items: "0".into(),
                    chain_sha256: hex::encode([0_u8; 32]),
                    first_completed_unix_nanos: now.to_string(),
                    last_completed_unix_nanos: now.to_string(),
                });
                let Some(entry) = phases.last_mut() else {
                    accumulator.invalid = true;
                    return;
                };
                entry
            }
            None => {
                accumulator.invalid = true;
                return;
            }
        };
        let counts = entry.completed_calls.parse::<u64>().ok().and_then(|calls| {
            Some((
                calls.checked_add(1)?,
                entry
                    .completed_items
                    .parse::<u64>()
                    .ok()?
                    .checked_add(items)?,
            ))
        });
        let Some((calls, items)) = counts else {
            accumulator.invalid = true;
            return;
        };
        let Some(previous_time) = entry.last_completed_unix_nanos.parse::<u128>().ok() else {
            accumulator.invalid = true;
            return;
        };
        if now < previous_time {
            accumulator.invalid = true;
            return;
        }
        let mut chain = Sha256::new();
        chain.update(entry.chain_sha256.as_bytes());
        chain.update(image.sha256.as_bytes());
        chain.update(image.byte_size.as_bytes());
        chain.update(calls.to_be_bytes());
        chain.update(items.to_be_bytes());
        entry.chain_sha256 = hex::encode(chain.finalize());
        entry.completed_calls = calls.to_string();
        entry.completed_items = items.to_string();
        entry.last_completed_unix_nanos = now.to_string();
    });
    #[cfg(target_arch = "wasm32")]
    let _ = (publication_id, phase, items, values);
}

/// Records the actual returned result; no production error is intercepted.
pub(crate) fn returned(success: bool) {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = super::ENABLED.try_with(|scope| {
        let Ok(mut scope) = scope.try_borrow_mut() else {
            return;
        };
        let Some(accumulator) = scope.publication.as_mut() else {
            return;
        };
        let Some(after) = observation_unix_nanos() else {
            accumulator.invalid = true;
            return;
        };
        let before = accumulator
            .summary
            .source_before_unix_nanos
            .parse::<u128>()
            .ok();
        if before.is_none_or(|before| after < before) {
            accumulator.invalid = true;
            return;
        }
        accumulator.summary.source_after_unix_nanos = Some(after.to_string());
        accumulator.summary.source_elapsed_nanos =
            Some(accumulator.start.elapsed().as_nanos().to_string());
        accumulator.summary.terminal_outcome = if success {
            TerminalOutcome::ReturnedSuccess
        } else {
            TerminalOutcome::ReturnedError
        };
    });
    #[cfg(target_arch = "wasm32")]
    let _ = success;
}

impl Accumulator {
    pub(super) fn into_summary(self) -> Option<Summary> {
        (!self.invalid && self.summary.encoded().is_some()).then_some(self.summary)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn partial_error_keeps_completed_phases_without_a_success_constructor() {
        let original = CommitRegistryPublicationRequest {
            publication_id: "original-publication".into(),
        };
        let (result, sql, summary) = super::super::observe_with_publication_phases(async {
            begin(&original);
            completed(
                &original.publication_id,
                Phase::Authorized,
                0,
                &"actual selected actor image",
            );
            super::super::invalidate_sql_projection();
            returned(false);
            Err::<(), _>("later operation refused")
        })
        .await;

        assert_eq!(result, Err("later operation refused"));
        assert!(sql.is_none());
        let summary = summary.unwrap();
        summary.validate_original(&original).unwrap();
        assert_eq!(summary.terminal_outcome(), TerminalOutcome::ReturnedError);
        assert_eq!(summary.phases.len(), 1);
        assert_eq!(summary.phases[0].phase, Phase::Authorized);
        assert_eq!(summary.phases[0].completed_items, "0");

        let foreign = CommitRegistryPublicationRequest {
            publication_id: "foreign-publication".into(),
        };
        assert!(summary.validate_original(&foreign).is_err());
        let mut changed = summary.clone();
        changed.producer_sha256 = "f".repeat(64);
        assert!(changed.validate_original(&original).is_err());
    }

    #[tokio::test]
    async fn repeated_actual_boundaries_are_counted_without_expanding_checkpoint_count() {
        let original = CommitRegistryPublicationRequest {
            publication_id: "bounded-publication".into(),
        };
        let (_, sql, summary) = super::super::observe_with_publication_phases(async {
            begin(&original);
            for index in 0..12_535_u64 {
                completed(
                    &original.publication_id,
                    Phase::PointerAdvanceFinalized,
                    1,
                    &index,
                );
            }
            returned(true);
        })
        .await;

        assert!(sql.is_none());
        let summary = summary.unwrap();
        summary.validate_original(&original).unwrap();
        assert_eq!(summary.phases.len(), 1);
        assert_eq!(summary.phases[0].completed_calls, "12535");
        assert_eq!(summary.phases[0].completed_items, "12535");
        assert!(summary.encoded().unwrap().len() < 1024);
        assert_eq!(summary.terminal_outcome(), TerminalOutcome::ReturnedSuccess);
    }

    #[tokio::test]
    async fn foreign_phase_or_restarted_original_never_produces_a_summary() {
        let original = CommitRegistryPublicationRequest {
            publication_id: "original-publication".into(),
        };
        let (_, _, foreign) = super::super::observe_with_publication_phases(async {
            begin(&original);
            completed("foreign-publication", Phase::Authorized, 0, &0);
            returned(false);
        })
        .await;
        assert!(foreign.is_none());

        let (_, _, restarted) = super::super::observe_with_publication_phases(async {
            begin(&original);
            begin(&original);
            returned(true);
        })
        .await;
        assert!(restarted.is_none());
    }
}

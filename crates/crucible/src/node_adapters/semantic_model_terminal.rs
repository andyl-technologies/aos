//! Selected semantic edition-two finalization under original opaque admission.

use super::*;

use crate::node_contract::{OperationAdmission, OperationRequest, WorldTerminalRecord};
use crate::node_scheduling::InputPayload;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostSemanticTerminal {
    record: WorldTerminalRecord,
    receipt: crucible_node_contract::ContentRef,
    source_position: Position,
    source_prefix: EventLogOffset,
    prior_reported: Vec<String>,
    report: InputPayload,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalReport {
    format: String,
    version: u16,
    barrier: crucible_node_contract::ContentRef,
    definition: HashRef,
    cut: Position,
    prefix: EventLogOffset,
    failed: bool,
    outcomes: Vec<OutcomePayload>,
    newly_terminal: Vec<String>,
}

impl HostSemanticModel {
    /// Finalizes actual assertions through an original whole-world admission.
    ///
    /// Selected native adapters must authenticate the admission's original live
    /// barrier and their installed program before calling this method. The
    /// public admission has no caller-created constructor. Repeating the same
    /// admission returns retained original bytes without reevaluation; capture,
    /// restore and read operations never perform finalization.
    ///
    /// # Errors
    /// Refuses legacy semantic editions, foreign barrier context, pending
    /// semantic work, changed original receipts and exhausted state credit.
    pub fn finalize(
        &mut self,
        admission: &OperationAdmission,
    ) -> Result<InputPayload, OperationFailure> {
        let OperationRequest::FinalizeAssertions { barrier, receipt } = admission.request() else {
            return Err(failure(
                "semantic finalization requires original terminal admission",
            ));
        };
        if self.definition.version != 2
            || barrier.operation != *admission.token().operation()
            || barrier.node != admission.token().route().node
            || barrier.source != admission.activation().record().into()
            || admission.inputs().is_some()
        {
            return Err(failure(
                "semantic terminal admission differs from original scope",
            ));
        }
        validate_barrier_bytes(barrier, receipt, self.maximum_bytes)?;
        if let Some(terminal) = &self.terminal {
            return if terminal.record == **barrier && terminal.receipt == *receipt {
                Ok(terminal.report.clone())
            } else {
                Err(failure("semantic terminal operation is already finalized"))
            };
        }
        if !self.pending.is_empty() || self.next_position().is_some() || barrier.cut < self.position
        {
            return Err(failure(
                "semantic original work remains before finalization",
            ));
        }
        let source = barrier
            .native
            .iter()
            .find(|inventory| inventory.node == barrier.node)
            .ok_or_else(|| failure("semantic terminal barrier omits actual participant"))?;
        if source.boundary != self.position || source.owners != admission.token().route().owners {
            return Err(failure(
                "semantic terminal barrier differs from actual source cut",
            ));
        }
        let mut staged = self.clone();
        let source_position = staged.position;
        let source_prefix = staged.log.offset();
        let prior_reported = staged.reported.iter().cloned().collect();
        if staged.segments.len() >= staged.maximum_events {
            return Err(failure("semantic terminal prefix credit exhausted"));
        }
        // This is host assertion evaluation at the authenticated terminal cut;
        // the retained barrier supplies its meaning, not a fabricated CPU RUN.
        let appended = staged
            .log
            .append_observations_at_boundary(
                Vec::new(),
                VirtualTime {
                    ticks: barrier.cut.time_ps.get(),
                },
                SchedulerEvaluationBoundaryKind::Quantum,
            )
            .map_err(|error| failure(&error.to_string()))?;
        staged.segments.push(Segment {
            position: barrier.cut,
            input: None,
            entries: appended.entries,
        });
        staged.position = barrier.cut;
        staged.evaluator = staged
            .evaluator
            .with_terminal_scheduler_quiescence(crate::SchedulerQuiescence::default());
        let actual = staged
            .evaluator
            .finalize_prefix(staged.log.condition_prefix(), &mut BlackBoxHostOracle);
        let mut newly_terminal = Vec::new();
        let outcomes = actual
            .outcomes()
            .iter()
            .map(|outcome| {
                if staged.reported.insert(outcome.assertion.name.clone()) {
                    newly_terminal.push(outcome.assertion.name.clone());
                }
                outcome_payload(outcome, barrier.cut)
            })
            .collect();
        let report = TerminalReport {
            format: "crucible.host-terminal-assertion-report".into(),
            version: 1,
            barrier: receipt.clone(),
            definition: staged.definition_hash.clone(),
            cut: barrier.cut,
            prefix: staged.log.offset(),
            failed: actual.verdict().is_failed(),
            outcomes,
            newly_terminal,
        };
        let bytes = canonical::canonical_json(
            &serde_json::to_value(report).map_err(|error| failure(&error.to_string()))?,
        )
        .map_err(|error| failure(&error.to_string()))?;
        let report = InputPayload {
            reference: canonical::content_ref(&bytes, "application/json")
                .map_err(|error| failure(&error.to_string()))?,
            bytes,
        };
        staged.terminal = Some(HostSemanticTerminal {
            record: (**barrier).clone(),
            receipt: receipt.clone(),
            source_position,
            source_prefix,
            prior_reported,
            report: report.clone(),
        });
        staged.capture()?;
        *self = staged;
        Ok(report)
    }

    /// Returns original terminal context and report without issuing authority.
    pub fn terminal_report(&self) -> Option<&InputPayload> {
        self.terminal.as_ref().map(|terminal| &terminal.report)
    }

    /// Borrows unchanged original terminal context without reconstructing authority.
    pub fn terminal_context(
        &self,
    ) -> Option<(&WorldTerminalRecord, &crucible_node_contract::ContentRef)> {
        self.terminal
            .as_ref()
            .map(|terminal| (&terminal.record, &terminal.receipt))
    }

    pub(super) fn require_open(&self) -> Result<(), OperationFailure> {
        if self.terminal.is_some() {
            Err(failure(
                "semantic finalized state cannot accept new effects",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn validate_terminal_saved(
        &self,
        terminal: &HostSemanticTerminal,
    ) -> Result<(), OperationFailure> {
        validate_barrier_bytes(&terminal.record, &terminal.receipt, self.maximum_bytes)?;
        terminal
            .report
            .reference
            .verify(&terminal.report.bytes)
            .map_err(|_| failure("semantic original terminal report bytes changed"))?;
        let value = canonical::parse_json(&terminal.report.bytes, self.maximum_bytes)
            .map_err(|error| failure(&error.to_string()))?;
        if canonical::canonical_json(&value).map_err(|error| failure(&error.to_string()))?
            != terminal.report.bytes.as_slice()
        {
            return Err(failure("semantic terminal report is not canonical"));
        }
        let report: TerminalReport =
            serde_json::from_value(value).map_err(|error| failure(&error.to_string()))?;
        let retained = self.evaluator.retained_terminal_outcomes();
        let expected: Vec<_> = retained
            .iter()
            .map(|outcome| outcome_payload(outcome, self.position))
            .collect();
        if report.format != "crucible.host-terminal-assertion-report"
            || report.version != 1
            || report.barrier != terminal.receipt
            || report.definition != self.definition_hash
            || report.cut != self.position
            || report.cut != terminal.record.cut
            || report.prefix != self.log.offset()
            || report.outcomes != expected
            || report.failed
                != retained.iter().any(|outcome| {
                    matches!(
                        outcome.kind,
                        crate::HostAssertionOutcomeKind::Violated
                            | crate::HostAssertionOutcomeKind::NeverReachedFail
                    )
                })
            || terminal.source_position > self.position
            || report.newly_terminal.iter().collect::<BTreeSet<_>>().len()
                != report.newly_terminal.len()
            || report
                .newly_terminal
                .iter()
                .any(|name| !self.reported.contains(name))
        {
            return Err(failure(
                "semantic terminal report differs from retained evaluator context",
            ));
        }
        let prior: BTreeSet<_> = terminal.prior_reported.iter().cloned().collect();
        let expected_new: Vec<_> = expected
            .iter()
            .filter(|outcome| !prior.contains(&outcome.assertion))
            .map(|outcome| outcome.assertion.clone())
            .collect();
        let expected_reported: BTreeSet<_> = prior
            .iter()
            .cloned()
            .chain(expected.iter().map(|outcome| outcome.assertion.clone()))
            .collect();
        if terminal
            .prior_reported
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || report.newly_terminal != expected_new
            || self.reported != expected_reported
        {
            return Err(failure("semantic terminal emitted registry changed"));
        }
        let Some(last) = self.segments.last() else {
            return Err(failure("semantic terminal evaluation prefix absent"));
        };
        let mut original = EventLog::new();
        for segment in self.segments.iter().take(self.segments.len() - 1) {
            original
                .append_entries(segment.entries.clone())
                .map_err(|error| failure(&error.to_string()))?;
        }
        if last.position != self.position
            || last.input.is_some()
            || original.offset() != terminal.source_prefix
        {
            return Err(failure("semantic terminal original prefix binding changed"));
        }
        Ok(())
    }
}

fn validate_barrier_bytes(
    record: &WorldTerminalRecord,
    reference: &crucible_node_contract::ContentRef,
    maximum: usize,
) -> Result<(), OperationFailure> {
    record
        .cut
        .validate()
        .map_err(|_| failure("semantic terminal cut invalid"))?;
    let bytes = canonical::canonical_json(
        &serde_json::to_value(record).map_err(|error| failure(&error.to_string()))?,
    )
    .map_err(|error| failure(&error.to_string()))?;
    if record.version != 1 || bytes.len() > maximum || reference.verify(&bytes).is_err() {
        return Err(failure("semantic original terminal barrier bytes invalid"));
    }
    Ok(())
}

fn outcome_payload(outcome: &crate::HostAssertionOutcome, evaluation: Position) -> OutcomePayload {
    OutcomePayload {
        format: "crucible.host-assertion-outcome".into(),
        version: 1,
        assertion: outcome.assertion.name.clone(),
        quantifier: outcome.quantifier,
        outcome_time_ps: outcome.at.ticks,
        evaluation,
        kind: outcome.kind,
        lifecycle: outcome.lifecycle,
        message: outcome.message.clone(),
        reason: outcome.reason.clone(),
    }
}

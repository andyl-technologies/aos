//! Retains real Clock admission refusals and their unchanged original state.
//!
//! These probes run on the same prepared and activated owners as the exact
//! programme. They never manufacture a token or activation. An unexpectedly
//! issued scheduler admission stays owned here and prevents later execution.

use crucible_engine::node_contract::{
    ActivationRecord, FacetKind, Lifecycle, NodeStatus, PhysicalState, RuntimeError,
};
use crucible_engine::node_scheduling::{ExecutionAdmission, SchedulingError};
use serde::Serialize;

use super::*;

// Matches the actual Host retirement reader's predeclared per-owner credit.
const MAXIMUM_ADMISSION_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RuntimeProbe {
    UnsupportedQuantizedFacet,
    UnknownNodeFacet,
}

struct RuntimeRefusal {
    probe: RuntimeProbe,
    original: RuntimeError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SchedulerProbe {
    NonadvancingHorizon,
    ReusedSettlement,
    UnknownNode,
    DuplicateOperation,
}

struct SchedulerRefusal {
    probe: SchedulerProbe,
    original: SchedulingError,
}

/// Borrows actual refusal and before/after evidence without supplying a verdict.
///
/// Only the called original programme constructs this view. The owning source
/// still authenticates each exact obligation, full original population and
/// complete six-class scope before normal enrollment can accept anything.
#[derive(Serialize)]
pub struct ClockAdmissionObservationData<'a> {
    schema: &'static str,
    prepared_before: &'a ContentRef,
    prepared_after: &'a ContentRef,
    closed_before: &'a ContentRef,
    closed_after: &'a ContentRef,
    prepared_status: (Lifecycle, PhysicalState, Option<Position>),
    prepared_after_status: (Lifecycle, PhysicalState, Option<Position>),
    closed_status: (Lifecycle, PhysicalState, Option<Position>),
    closed_after_status: (Lifecycle, PhysicalState, Option<Position>),
    runtime_refusals: Vec<(RuntimeProbe, &'static str)>,
    scheduler_refusals: Vec<(SchedulerProbe, &'static str)>,
}

pub(super) struct OriginalClockAdmissionCases {
    prepared_attempted: bool,
    closed_attempted: bool,
    prepared_complete: bool,
    closed_complete: bool,
    prepared_before: Option<InputPayload>,
    prepared_after: Option<InputPayload>,
    prepared_status: Option<NodeStatus>,
    prepared_after_status: Option<NodeStatus>,
    closed_before: Option<InputPayload>,
    closed_after: Option<InputPayload>,
    closed_status: Option<NodeStatus>,
    closed_after_status: Option<NodeStatus>,
    runtime_refusals: Vec<RuntimeRefusal>,
    scheduler_refusals: Vec<SchedulerRefusal>,
    unexpected: Vec<ExecutionAdmission>,
}

impl OriginalClockAdmissionCases {
    pub(super) fn new() -> Result<Self, NodeObservedError> {
        let mut runtime_refusals = Vec::new();
        let mut scheduler_refusals = Vec::new();
        let mut unexpected = Vec::new();
        runtime_refusals
            .try_reserve_exact(2)
            .map_err(|_| refused("Clock runtime refusal bank reservation failed"))?;
        scheduler_refusals
            .try_reserve_exact(4)
            .map_err(|_| refused("Clock scheduler refusal bank reservation failed"))?;
        unexpected
            .try_reserve_exact(1)
            .map_err(|_| refused("Clock unexpected admission reservation failed"))?;
        Ok(Self {
            prepared_attempted: false,
            closed_attempted: false,
            prepared_complete: false,
            closed_complete: false,
            prepared_before: None,
            prepared_after: None,
            prepared_status: None,
            prepared_after_status: None,
            closed_before: None,
            closed_after: None,
            closed_status: None,
            closed_after_status: None,
            runtime_refusals,
            scheduler_refusals,
            unexpected,
        })
    }

    pub(super) fn inspect_prepublication(
        &mut self,
        runtime: &mut NodeRuntime,
        graph: &AdmittedGraph,
        node: &Id,
        proposal: &ActivationRecord,
    ) -> Result<(), NodeObservedError> {
        if self.prepared_attempted {
            return Err(refused("Clock prepublication probes already attempted"));
        }
        self.prepared_attempted = true;
        self.prepared_before =
            Some(runtime.initial_coordinator_snapshot(graph, MAXIMUM_ADMISSION_BODY_BYTES)?);
        self.prepared_status = Some(runtime.status(node)?);
        if !status_is(
            self.prepared_status.as_ref(),
            Lifecycle::Prepared,
            proposal.boundary,
        ) || proposal
            .owners
            .iter()
            .any(|owner| runtime.owner_lifecycle(&owner.owner) != Some(Lifecycle::Prepared))
        {
            return Err(refused(
                "Clock prepared lifecycle differs before commitment",
            ));
        }

        let unsupported = match runtime.facet(node, FacetKind::QuantizedExecution) {
            Err(error) => error,
            Ok(_) => return Err(refused("Clock unexpectedly exposes quantized execution")),
        };
        self.runtime_refusals.push(RuntimeRefusal {
            probe: RuntimeProbe::UnsupportedQuantizedFacet,
            original: unsupported,
        });
        let absent = Id::new("clock/absent-source-node")?;
        if graph.descriptor(&absent).is_some() {
            return Err(refused("Clock negative node unexpectedly belongs to graph"));
        }
        let unknown = match runtime.facet(&absent, FacetKind::ExactExecution) {
            Err(error) => error,
            Ok(_) => return Err(refused("Clock unknown node acquired a native facet")),
        };
        self.runtime_refusals.push(RuntimeRefusal {
            probe: RuntimeProbe::UnknownNodeFacet,
            original: unknown,
        });
        self.prepared_after =
            Some(runtime.initial_coordinator_snapshot(graph, MAXIMUM_ADMISSION_BODY_BYTES)?);
        self.prepared_after_status = Some(runtime.status(node)?);
        if self.prepared_before != self.prepared_after
            || self.prepared_status != self.prepared_after_status
            || !runtime_refusals_match(&self.runtime_refusals)
        {
            return Err(refused(
                "Clock prepublication refusal changed original state",
            ));
        }
        self.prepared_complete = true;
        Ok(())
    }

    pub(super) fn inspect_closed_frontier(
        &mut self,
        runtime: &mut NodeRuntime,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        node: &Id,
        cases: &[ClockCase],
    ) -> Result<(), NodeObservedError> {
        if !self.prepared_complete || self.closed_attempted {
            return Err(refused("Clock closed admission probes unavailable"));
        }
        self.closed_attempted = true;
        let boundary = runtime.scheduler(graph, activation)?.position(node)?;
        self.closed_status = Some(runtime.status(node)?);
        if !status_is(self.closed_status.as_ref(), Lifecycle::Stopped, boundary) {
            return Err(refused(
                "Clock closed lifecycle differs from original frontier",
            ));
        }
        self.closed_before = Some(closed_body(runtime, activation, boundary)?);
        let absent = Id::new("clock/absent-source-node")?;
        let future = boundary
            .time_ps
            .get()
            .checked_add(2)
            .map(U64::new)
            .ok_or_else(|| refused("Clock negative horizon overflow"))?;
        let duplicate = cases
            .first()
            .filter(|case| case.acknowledged)
            .ok_or_else(|| refused("Clock original acknowledged operation absent"))?
            .operation
            .clone();

        let result = runtime.scheduler(graph, activation)?.admit_exact(
            node,
            Id::new("clock/refused-nonadvancing-horizon")?,
            boundary.time_ps,
        );
        self.retain_scheduler_result(SchedulerProbe::NonadvancingHorizon, result)?;
        let result = runtime
            .scheduler(graph, activation)?
            .admit_boundary_settlement(node, Id::new("clock/refused-reused-settlement")?, boundary);
        self.retain_scheduler_result(SchedulerProbe::ReusedSettlement, result)?;
        let result = runtime.scheduler(graph, activation)?.admit_exact(
            &absent,
            Id::new("clock/refused-unknown-node")?,
            future,
        );
        self.retain_scheduler_result(SchedulerProbe::UnknownNode, result)?;
        let result = runtime
            .scheduler(graph, activation)?
            .admit_exact(node, duplicate, future);
        self.retain_scheduler_result(SchedulerProbe::DuplicateOperation, result)?;

        self.closed_after = Some(closed_body(runtime, activation, boundary)?);
        self.closed_after_status = Some(runtime.status(node)?);
        if self.closed_before != self.closed_after
            || self.closed_status != self.closed_after_status
            || !scheduler_refusals_match(&self.scheduler_refusals)
        {
            return Err(refused(
                "Clock refused admission changed complete closed state",
            ));
        }
        self.closed_complete = true;
        Ok(())
    }

    fn retain_scheduler_result(
        &mut self,
        probe: SchedulerProbe,
        result: Result<ExecutionAdmission, SchedulingError>,
    ) -> Result<(), NodeObservedError> {
        match result {
            Ok(original) => {
                // The original reservation remains in the scheduler, and this
                // actual issued handle stays owned before the programme fails.
                self.unexpected.push(original);
                Err(refused("Clock negative probe unexpectedly issued a grant"))
            }
            Err(original) => {
                let matches = scheduler_refusal_matches(probe, &original);
                self.scheduler_refusals
                    .push(SchedulerRefusal { probe, original });
                if matches {
                    Ok(())
                } else {
                    Err(refused("Clock original scheduling refusal differs"))
                }
            }
        }
    }

    pub(super) fn complete(&self) -> bool {
        self.prepared_attempted
            && self.closed_attempted
            && self.prepared_complete
            && self.closed_complete
            && self.unexpected.is_empty()
            && runtime_refusals_match(&self.runtime_refusals)
            && scheduler_refusals_match(&self.scheduler_refusals)
            && self.prepared_before.is_some()
            && self.prepared_before == self.prepared_after
            && self.closed_before.is_some()
            && self.closed_before == self.closed_after
            && self.prepared_status == self.prepared_after_status
            && self.closed_status == self.closed_after_status
    }

    pub(super) fn retained_objects(&self) -> impl Iterator<Item = &InputPayload> {
        [
            self.prepared_before.as_ref(),
            self.prepared_after.as_ref(),
            self.closed_before.as_ref(),
            self.closed_after.as_ref(),
        ]
        .into_iter()
        .flatten()
    }

    pub(super) fn observation(
        &self,
    ) -> Result<ClockAdmissionObservationData<'_>, NodeObservedError> {
        if !self.complete() {
            return Err(refused("Clock actual admission population is incomplete"));
        }
        Ok(ClockAdmissionObservationData {
            schema: "crucible.original-clock-admission/1",
            prepared_before: &self
                .prepared_before
                .as_ref()
                .ok_or_else(|| refused("Clock prepared before absent"))?
                .reference,
            prepared_after: &self
                .prepared_after
                .as_ref()
                .ok_or_else(|| refused("Clock prepared after absent"))?
                .reference,
            closed_before: &self
                .closed_before
                .as_ref()
                .ok_or_else(|| refused("Clock closed before absent"))?
                .reference,
            closed_after: &self
                .closed_after
                .as_ref()
                .ok_or_else(|| refused("Clock closed after absent"))?
                .reference,
            prepared_status: status_data(self.prepared_status.as_ref())?,
            prepared_after_status: status_data(self.prepared_after_status.as_ref())?,
            closed_status: status_data(self.closed_status.as_ref())?,
            closed_after_status: status_data(self.closed_after_status.as_ref())?,
            runtime_refusals: self
                .runtime_refusals
                .iter()
                .map(|row| {
                    (
                        row.probe,
                        match row.original {
                            RuntimeError::UnsupportedFacet => "unsupported-facet",
                            RuntimeError::UnknownNode => "unknown-node",
                            _ => "unexpected-original-refusal",
                        },
                    )
                })
                .collect(),
            scheduler_refusals: self
                .scheduler_refusals
                .iter()
                .map(|row| {
                    (
                        row.probe,
                        match row.original {
                            SchedulingError::NoSafeProgress => "no-safe-progress",
                            SchedulingError::UnknownNode => "unknown-node",
                            SchedulingError::DuplicateOperation => "duplicate-operation",
                            _ => "unexpected-original-refusal",
                        },
                    )
                })
                .collect(),
        })
    }
}

fn status_data(
    status: Option<&NodeStatus>,
) -> Result<(Lifecycle, PhysicalState, Option<Position>), NodeObservedError> {
    let status = status.ok_or_else(|| refused("Clock original lifecycle observation absent"))?;
    Ok((status.lifecycle, status.physical, status.boundary))
}

fn status_is(status: Option<&NodeStatus>, lifecycle: Lifecycle, boundary: Position) -> bool {
    status.is_some_and(|status| {
        status.lifecycle == lifecycle
            && status.physical == PhysicalState::Suspended
            && status.boundary == Some(boundary)
    })
}

fn runtime_refusals_match(rows: &[RuntimeRefusal]) -> bool {
    matches!(
        rows,
        [
            RuntimeRefusal {
                probe: RuntimeProbe::UnsupportedQuantizedFacet,
                original: RuntimeError::UnsupportedFacet
            },
            RuntimeRefusal {
                probe: RuntimeProbe::UnknownNodeFacet,
                original: RuntimeError::UnknownNode
            }
        ]
    )
}

fn scheduler_refusal_matches(probe: SchedulerProbe, original: &SchedulingError) -> bool {
    matches!(
        (probe, original),
        (
            SchedulerProbe::NonadvancingHorizon | SchedulerProbe::ReusedSettlement,
            SchedulingError::NoSafeProgress
        ) | (SchedulerProbe::UnknownNode, SchedulingError::UnknownNode)
            | (
                SchedulerProbe::DuplicateOperation,
                SchedulingError::DuplicateOperation
            )
    )
}

fn scheduler_refusals_match(rows: &[SchedulerRefusal]) -> bool {
    rows.len() == 4
        && rows
            .iter()
            .zip([
                SchedulerProbe::NonadvancingHorizon,
                SchedulerProbe::ReusedSettlement,
                SchedulerProbe::UnknownNode,
                SchedulerProbe::DuplicateOperation,
            ])
            .all(|(row, expected)| {
                row.probe == expected && scheduler_refusal_matches(row.probe, &row.original)
            })
}

fn closed_body(
    runtime: &NodeRuntime,
    activation: &WorldActivation,
    boundary: Position,
) -> Result<InputPayload, NodeObservedError> {
    let scheduler = runtime.retirement_scheduler_snapshot(activation, boundary, U64::new(0))?;
    let histories = runtime.retirement_histories(activation, MAXIMUM_ADMISSION_BODY_BYTES)?;
    let histories = histories
        .iter()
        .map(|history| (&history.route, &history.bodies))
        .collect::<Vec<_>>();
    let value = (&scheduler, &histories);
    let mut credit = BodyCredit(MAXIMUM_ADMISSION_BODY_BYTES);
    serde_json::to_writer(&mut credit, &value)?;
    let bytes = canonical::canonical_json(&serde_json::to_value(value)?)?;
    Ok(InputPayload {
        reference: canonical::content_ref(&bytes, "application/json")?,
        bytes,
    })
}

struct BodyCredit(usize);

impl std::io::Write for BodyCredit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("Clock admission record ceiling"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_lifecycle_oracle_rejects_unknown_physical_and_changed_boundary() {
        let boundary = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
        let mut status = NodeStatus {
            lifecycle: Lifecycle::Prepared,
            physical: PhysicalState::Suspended,
            boundary: Some(boundary),
        };
        assert!(status_is(Some(&status), Lifecycle::Prepared, boundary));

        status.physical = PhysicalState::Unknown;
        assert!(!status_is(Some(&status), Lifecycle::Prepared, boundary));
        status.physical = PhysicalState::Suspended;
        status.boundary = None;
        assert!(!status_is(Some(&status), Lifecycle::Prepared, boundary));
        status.boundary = Some(Position::new(1.into(), 0.into(), Phase::BoundaryControl));
        assert!(!status_is(Some(&status), Lifecycle::Prepared, boundary));
    }

    #[test]
    fn prepared_lifecycle_never_substitutes_native_stop_for_execution_lifecycle() {
        let boundary = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
        let status = NodeStatus {
            lifecycle: Lifecycle::Stopped,
            physical: PhysicalState::Suspended,
            boundary: Some(boundary),
        };
        assert!(!status_is(Some(&status), Lifecycle::Prepared, boundary));
        assert!(status_is(Some(&status), Lifecycle::Stopped, boundary));
        assert!(!status_is(None, Lifecycle::Stopped, boundary));
    }

    #[test]
    fn native_facet_oracle_preserves_original_refusal_kind_and_population() {
        let mut rows = vec![
            RuntimeRefusal {
                probe: RuntimeProbe::UnsupportedQuantizedFacet,
                original: RuntimeError::UnsupportedFacet,
            },
            RuntimeRefusal {
                probe: RuntimeProbe::UnknownNodeFacet,
                original: RuntimeError::UnknownNode,
            },
        ];
        assert!(runtime_refusals_match(&rows));
        rows[0].original = RuntimeError::UnknownNode;
        assert!(!runtime_refusals_match(&rows));
        rows[0].original = RuntimeError::UnsupportedFacet;
        rows.swap(0, 1);
        assert!(!runtime_refusals_match(&rows));
        rows.clear();
        assert!(!runtime_refusals_match(&rows));
    }

    fn scheduling_rows() -> Vec<SchedulerRefusal> {
        vec![
            SchedulerRefusal {
                probe: SchedulerProbe::NonadvancingHorizon,
                original: SchedulingError::NoSafeProgress,
            },
            SchedulerRefusal {
                probe: SchedulerProbe::ReusedSettlement,
                original: SchedulingError::NoSafeProgress,
            },
            SchedulerRefusal {
                probe: SchedulerProbe::UnknownNode,
                original: SchedulingError::UnknownNode,
            },
            SchedulerRefusal {
                probe: SchedulerProbe::DuplicateOperation,
                original: SchedulingError::DuplicateOperation,
            },
        ]
    }

    #[test]
    fn scheduling_oracle_refuses_different_error_and_rewritten_case_identity() {
        let mut rows = scheduling_rows();
        assert!(scheduler_refusals_match(&rows));
        rows[3].original = SchedulingError::NoSafeProgress;
        assert!(!scheduler_refusals_match(&rows));
        rows[3].original = SchedulingError::DuplicateOperation;
        rows[2].probe = SchedulerProbe::DuplicateOperation;
        assert!(!scheduler_refusals_match(&rows));
    }

    #[test]
    fn scheduling_oracle_refuses_omission_duplicate_and_reordering() {
        let mut rows = scheduling_rows();
        rows.pop();
        assert!(!scheduler_refusals_match(&rows));

        let mut rows = scheduling_rows();
        rows.push(SchedulerRefusal {
            probe: SchedulerProbe::DuplicateOperation,
            original: SchedulingError::DuplicateOperation,
        });
        assert!(!scheduler_refusals_match(&rows));

        let mut rows = scheduling_rows();
        rows.swap(0, 1);
        assert!(!scheduler_refusals_match(&rows));
    }

    #[test]
    fn original_metadata_writer_consumes_exact_extent_and_refuses_one_extra_byte() {
        use std::io::Write;
        let mut credit = BodyCredit(3);
        assert_eq!(credit.write(b"abc").ok(), Some(3));
        assert!(credit.write(b"x").is_err());
        assert_eq!(credit.0, 0);
    }
}

impl crate::node_qualification::RetainedMetadataOwned for OriginalClockAdmissionCases {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        use std::mem::size_of;
        let Self {
            prepared_attempted: _,
            closed_attempted: _,
            prepared_complete: _,
            closed_complete: _,
            prepared_before,
            prepared_after,
            prepared_status: _,
            prepared_after_status: _,
            closed_before,
            closed_after,
            closed_status: _,
            closed_after_status: _,
            runtime_refusals,
            scheduler_refusals,
            unexpected,
        } = self;
        if !unexpected.is_empty() {
            return Err(QualificationError::Refused(
                "unsupported unexpected Clock admission owner",
            ));
        }
        counter.charge(prepared_before)?;
        counter.charge(prepared_after)?;
        counter.charge(closed_before)?;
        counter.charge(closed_after)?;
        counter.add(
            runtime_refusals
                .capacity()
                .checked_mul(size_of::<RuntimeRefusal>())
                .ok_or(QualificationError::Refused(
                    "Clock refusal capacity overflow",
                ))?,
        )?;
        for RuntimeRefusal { probe: _, original } in runtime_refusals {
            counter.charge(original)?;
        }
        counter.add(
            scheduler_refusals
                .capacity()
                .checked_mul(size_of::<SchedulerRefusal>())
                .ok_or(QualificationError::Refused(
                    "Clock refusal capacity overflow",
                ))?,
        )?;
        // These actual six probes produce only these unit refusals. An
        // unexpected owned Contract/InputBlocked error is retained but unknown.
        for SchedulerRefusal { probe: _, original } in scheduler_refusals {
            if !matches!(
                original,
                SchedulingError::NoSafeProgress
                    | SchedulingError::UnknownNode
                    | SchedulingError::DuplicateOperation
            ) {
                return Err(QualificationError::Refused(
                    "unsupported Clock scheduler refusal owner",
                ));
            }
        }
        counter.add(
            unexpected
                .capacity()
                .checked_mul(size_of::<ExecutionAdmission>())
                .ok_or(QualificationError::Refused(
                    "Clock unexpected admission capacity overflow",
                ))?,
        )
    }
}

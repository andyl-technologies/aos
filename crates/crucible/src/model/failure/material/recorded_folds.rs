//! Streamed folds over a recorded event log for failure signatures.
//!
//! Every function here reads a [`FailureRecordedEventLog`] as a stream and
//! keeps only what its answer needs: a matched index, at most two witnesses,
//! or a running hash. The causal cone is folded in three passes, because its
//! canonical material is length-prefixed and starts with its entry count:
//!
//! ```text
//! pass 1  locate the anchor and its dependency keys
//! pass 2  count cone entries and their material length
//! pass 3  hash "causal_cone_events=N" and each entry's lines, then any suffix
//! ```
//!
//! The hash equals the one the complete material would produce, so streaming
//! changes no causal-slice hash.

use std::ops::ControlFlow;

use super::*;
use crate::model::canonical::CanonicalMaterialStream;
use crate::scheduler::is_causal_event_log_entry;
use crate::trigger::{HostAssertionReport, OfflineAssertionCheckError};

pub(in crate::model) fn validate_divergence_point(
    event_log: &FailureRecordedEventLog,
    divergence: &EventLogCausalDivergencePoint,
) -> Result<usize, EngineError> {
    let mut found = None;
    event_log.try_for_each_causal(|index, entry| {
        if entry.raw_index == divergence.raw_index
            && entry.entry.time().stamp == divergence.at
            && entry.entry.source() == &divergence.source
            && entry.entry.event_payload().kind() == divergence.kind
        {
            found = Some(index);
            return Ok(ControlFlow::Break(()));
        }
        Ok(ControlFlow::Continue(()))
    })?;

    found.ok_or(EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.divergence",
        reason: "divergence bisection point is absent from recorded causal projection",
    })
}

pub(in crate::model) fn validate_timeout_point(
    event_log: &FailureRecordedEventLog,
    timeout: &FailureTimeoutRecord,
) -> Result<usize, EngineError> {
    if timeout.reproduction_artifact != event_log.artifact() {
        return Err(EngineError::ReplayTargetMismatch {
            expected: event_log.artifact(),
            actual: timeout.reproduction_artifact,
        });
    }

    let mut found = None;
    event_log.try_for_each_causal(|index, entry| {
        let entry = &entry.entry;
        if entry.event_payload().kind() == timeout.event_kind
            && entry.at() == timeout.at_virtual_time
            && entry.event_payload().string("budget_kind")
                == Some(failure_timeout_budget_kind_label(timeout.budget_kind))
            && entry.time().stamp.node == timeout.node
            && timeout
                .at_icount
                .map(|icount| entry.time().stamp.retired == Some(icount))
                .unwrap_or(true)
        {
            found = Some(index);
            return Ok(ControlFlow::Break(()));
        }
        Ok(ControlFlow::Continue(()))
    })?;

    found.ok_or(EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.timeout",
        reason: "timeout boundary is absent from recorded causal projection",
    })
}

pub(in crate::model) struct ValidatedPropertyViolation {
    pub(in crate::model) causal_cone: FailureCausalCone,
    pub(in crate::model) anchor: Option<usize>,
}

/// One retained guest-marker coordinate that witnesses a violation.
struct MarkerWitness {
    raw_index: usize,
    at: VirtualTime,
    node: NodeId,
    marker: MarkerId,
    icount: Icount,
}

/// What one pass over the log learns about a claimed property violation.
#[derive(Default)]
struct ViolationScan {
    // The first projected assertion transition matching the violation, its
    // causal index, and whether a second one exists.
    transition: Option<(usize, crate::scheduler::EventLogCausalProjectionEntry)>,
    ambiguous_transition: bool,
    // The last causal entry at or before the violation time.
    latest_before: Option<usize>,
    // At most two witnesses; a second one already fails the check.
    marker_witnesses: Vec<MarkerWitness>,
}

pub(in crate::model) fn validated_property_violation(
    finding: &FindingReproductionArtifact,
    event_log: &FailureRecordedEventLog,
    violation: &FailurePropertyViolationRecord,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Result<ValidatedPropertyViolation, EngineError> {
    let mismatch = || EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.violation",
        reason: "violation record is absent from recorded causal projection and host assertion replay",
    };

    let report = recheck_host_assertions(finding, event_log)?.map_err(|_| mismatch())?;
    let matches_expected = |replayed: &HostAssertionViolation| {
        let mut replayed = replayed.clone();
        replayed.reproduction_artifact = finding.artifact.id();
        replayed == violation.violation
    };
    if !report.violations().iter().any(&matches_expected) {
        return Err(mismatch());
    }

    let scan = scan_property_violation(event_log, violation)?;
    let transition = validated_transition(&scan).map_err(|_| mismatch())?;
    let outcome_is_violated = report.outcomes().iter().any(|outcome| {
        outcome.assertion == violation.violation.assertion
            && outcome.at == violation.violation.at_virtual_time
            && outcome.quantifier == violation.violation.quantifier
            && matches!(
                outcome.kind,
                HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail
            )
    });
    // A host-only recorded log can omit the runtime's derived transition.
    // When one is retained, it must agree with the rechecked verdict.
    if transition.is_some() && !outcome_is_violated {
        return Err(mismatch());
    }
    let anchor = transition
        .as_ref()
        .map(|(index, _)| *index)
        .or(scan.latest_before);

    // The checker establishes the failed predicate from the exact raw log.
    // Retain the physical marker coordinate independently of the scheduler
    // boundary so replay cannot substitute a different guest observation. The
    // detail was regenerated and compared above, so its witness label is
    // checker-owned rather than an unchecked claim from the replay payload.
    let claims_guest_marker = claims_guest_marker(violation);
    let witnesses = &scan.marker_witnesses;
    if witnesses.len() > 1 || (claims_guest_marker && witnesses.len() != 1) {
        return Err(mismatch());
    }
    if let (Some((_, transition_raw)), Some(witness)) = (&transition, witnesses.first())
        && witness.raw_index >= *transition_raw
    {
        return Err(mismatch());
    }

    let mut suffix = Vec::new();
    if let Some(witness) = witnesses.first() {
        let node = canonicalizer.canonical_node(&witness.node);
        suffix.push(format!(
            "guest_marker_witness=marker:{:?};node:{:?};icount:{};at:{}",
            witness.marker.name, node.name, witness.icount.retired, witness.at.ticks
        ));
    }
    suffix.push(format!(
        "host_assertion_violation=assertion:{:?};quantifier:{:?};at:{};detail:{:?}",
        violation.violation.assertion.name,
        violation.violation.quantifier,
        violation.violation.at_virtual_time.ticks,
        violation.violation.detail
    ));

    let causal_cone = match anchor {
        Some(index) => failure_causal_cone_through_index(event_log, index, canonicalizer, &suffix)?,
        None => hash_cone_material(event_log, None, canonicalizer, &suffix)?,
    };
    Ok(ValidatedPropertyViolation {
        causal_cone,
        anchor,
    })
}

/// Regrades the scenario's properties over the streamed raw log.
///
/// The outer error is a log read failure; the inner one is the checker's
/// verdict that the log does not grade.
fn recheck_host_assertions(
    finding: &FindingReproductionArtifact,
    event_log: &FailureRecordedEventLog,
) -> Result<Result<HostAssertionReport, OfflineAssertionCheckError>, EngineError> {
    let scenario = finding.artifact.scenario_form();
    let mut oracle = BlackBoxHostOracle;
    let mut check = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&scenario.world)
        .start_check(&scenario.properties, event_log.shape);
    event_log.try_for_each_entry(|entry| {
        check.push(entry.clone(), &mut oracle);
        Ok(())
    })?;
    Ok(check.finish(&mut oracle))
}

fn claims_guest_marker(violation: &FailurePropertyViolationRecord) -> bool {
    violation.violation.node.is_some()
        && violation.violation.detail.contains("guest marker marker=")
}

/// Collects the transition, anchor fallback, and marker witnesses in one pass.
fn scan_property_violation(
    event_log: &FailureRecordedEventLog,
    violation: &FailurePropertyViolationRecord,
) -> Result<ViolationScan, EngineError> {
    let claims_guest_marker = claims_guest_marker(violation);
    let at = violation.violation.at_virtual_time;
    let mut scan = ViolationScan::default();
    let mut causal_index = 0_usize;

    event_log.try_for_each_raw(|raw_index, entry| {
        if is_causal_event_log_entry(entry) {
            let projected = crate::scheduler::EventLogCausalProjectionEntry {
                raw_index,
                entry: crate::scheduler::causal_projection_entry(causal_index as u64, entry),
            };
            if projected.entry.event_payload().kind() == violation.violation.event_kind
                && projected.entry.at() == at
                && violation_event_assertion_matches(
                    projected.entry.event_payload(),
                    &violation.violation,
                )
            {
                if scan.transition.is_some() {
                    scan.ambiguous_transition = true;
                } else {
                    scan.transition = Some((causal_index, projected.clone()));
                }
            }
            if projected.entry.at() <= at {
                scan.latest_before = Some(causal_index);
            }
            causal_index += 1;
        }

        if claims_guest_marker
            && scan.marker_witnesses.len() < 2
            && let Some(witness) = marker_witness(raw_index, entry, violation)
        {
            scan.marker_witnesses.push(witness);
        }
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(scan)
}

fn marker_witness(
    raw_index: usize,
    entry: &SchedulerEventLogEntry,
    violation: &FailurePropertyViolationRecord,
) -> Option<MarkerWitness> {
    let SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
        retired_icount,
        node,
        marker,
    }) = entry.payload()
    else {
        return None;
    };
    let matches = violation.violation.at_icount == Some(*retired_icount)
        && violation.violation.node.as_ref() == Some(node)
        && entry.at() <= violation.violation.at_virtual_time
        && violation
            .violation
            .detail
            .contains(&format!("guest marker marker={} matched", marker.name));
    matches.then(|| MarkerWitness {
        raw_index,
        at: entry.at(),
        node: node.clone(),
        marker: marker.clone(),
        icount: *retired_icount,
    })
}

/// Returns the unique, well-formed host assertion transition, if any, as its
/// causal index and raw position.
fn validated_transition(scan: &ViolationScan) -> Result<Option<(usize, usize)>, EngineError> {
    let mismatch = || EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.violation",
        reason: "host assertion transition is ambiguous or inconsistent",
    };
    let Some((index, transition)) = &scan.transition else {
        return Ok(None);
    };
    if scan.ambiguous_transition {
        return Err(mismatch());
    }

    let entry = &transition.entry;
    let boundary_stamp = entry.time().stamp.node.is_none()
        && entry.time().stamp.tick.ticks == entry.at().ticks
        && entry.time().stamp.retired.is_none();
    if entry.source() != &EventSource::Engine
        || !boundary_stamp
        || !matches!(
            entry.payload(),
            SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionStateChanged {
                state: AssertionPhase::Violated,
                ..
            })
        )
    {
        return Err(mismatch());
    }
    Ok(Some((*index, transition.raw_index)))
}

pub(in crate::model) fn violation_event_assertion_matches(
    payload: &crate::scheduler::EventPayload,
    violation: &HostAssertionViolation,
) -> bool {
    matches!(
        payload.attribute("id"),
        Some(EventAttributeValue::String(value)) if value == &violation.assertion.name
    )
}

pub(in crate::model) fn divergence_faulting_node(
    divergence: &EventLogCausalDivergencePoint,
) -> Option<NodeId> {
    match &divergence.source {
        EventSource::Node { node } | EventSource::Guest { node } => Some(node.clone()),
        EventSource::Scenario { .. } | EventSource::Engine | EventSource::Command { .. } => {
            divergence.at.node.clone()
        }
    }
}

/// Folds the causal cone through `causal_index` into its identity.
///
/// `suffix` lines follow the cone's own material, as a property violation
/// appends its witness and verdict.
pub(in crate::model) fn failure_causal_cone_through_index(
    event_log: &FailureRecordedEventLog,
    causal_index: usize,
    canonicalizer: &FailureSymmetryCanonicalizer,
    suffix: &[String],
) -> Result<FailureCausalCone, EngineError> {
    hash_cone_material(event_log, Some(causal_index), canonicalizer, suffix)
}

/// Visits the cone entries through `causal_index`, numbered within the cone.
///
/// The cone is every causal entry up to the anchor that is the anchor or
/// shares one of its dependency keys.
pub(in crate::model) fn try_for_each_cone_entry(
    event_log: &FailureRecordedEventLog,
    causal_index: usize,
    canonicalizer: &FailureSymmetryCanonicalizer,
    mut visit: impl FnMut(usize, &crate::scheduler::EventLogCausalProjectionEntry),
) -> Result<(), EngineError> {
    let anchor = event_log.causal_entry(causal_index)?.ok_or(
        EngineError::UnifiedOperationEvidenceMismatch {
            operation: "failure-signature.causal-cone",
            reason: "causal cone anchor is absent from recorded causal projection",
        },
    )?;
    let anchor_keys = failure_causal_dependency_keys(&anchor, canonicalizer);

    let mut cone_index = 0_usize;
    event_log.try_for_each_causal(|index, entry| {
        let in_cone = entry.raw_index == anchor.raw_index
            || failure_causal_dependency_keys(entry, canonicalizer)
                .iter()
                .any(|key| anchor_keys.contains(key));
        if in_cone {
            visit(cone_index, entry);
            cone_index += 1;
        }
        Ok(if index >= causal_index {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        })
    })
}

/// Hashes `causal_cone_events=N`, each cone entry's lines, and `suffix`,
/// joined by newlines, without retaining the material.
fn hash_cone_material(
    event_log: &FailureRecordedEventLog,
    causal_index: Option<usize>,
    canonicalizer: &FailureSymmetryCanonicalizer,
    suffix: &[String],
) -> Result<FailureCausalCone, EngineError> {
    let mut events = 0_usize;
    let mut body_bytes = 0_u64;
    let mut lines = Vec::new();
    if let Some(causal_index) = causal_index {
        try_for_each_cone_entry(
            event_log,
            causal_index,
            canonicalizer,
            |cone_index, entry| {
                lines.clear();
                push_failure_causal_slice_entry_lines(cone_index, entry, canonicalizer, &mut lines);
                body_bytes = lines
                    .iter()
                    .fold(body_bytes, |total, line| total + 1 + line.len() as u64);
                events += 1;
            },
        )?;
    }

    let header = format!("causal_cone_events={events}");
    let suffix_bytes = suffix
        .iter()
        .fold(0_u64, |total, line| total + 1 + line.len() as u64);
    let mut stream = CanonicalMaterialStream::new(
        FAILURE_CAUSAL_SLICE_DOMAIN,
        header.len() as u64 + body_bytes + suffix_bytes,
    );
    stream.write(header.as_bytes());
    if let Some(causal_index) = causal_index {
        try_for_each_cone_entry(
            event_log,
            causal_index,
            canonicalizer,
            |cone_index, entry| {
                lines.clear();
                push_failure_causal_slice_entry_lines(cone_index, entry, canonicalizer, &mut lines);
                for line in &lines {
                    stream.write(b"\n");
                    stream.write(line.as_bytes());
                }
            },
        )?;
    }
    for line in suffix {
        stream.write(b"\n");
        stream.write(line.as_bytes());
    }

    let content_hash = stream.finish().ok_or_else(|| {
        scenario_serialization_error("recorded causal cone changed between its passes")
    })?;
    Ok(FailureCausalCone::new(content_hash, events))
}

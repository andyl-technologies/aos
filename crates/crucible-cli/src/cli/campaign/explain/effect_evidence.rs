//! Bounded public views of canonical attempt effect and event-log evidence.

use super::*;
use crucible_campaign::{
    CampaignTraceKind, GetCampaignTraceChunkRequest, MAX_CAMPAIGN_TRACE_BYTES,
    MAX_CAMPAIGN_TRACE_CHUNK_BYTES,
};
use crucible_cas::content_store::{ContentId, ObjectKind};
use crucible_core::model::{
    EffectSpecification, FaultResourceLimits, NetworkEffectSpecification, ResolvedEffectTrace,
    ResolvedFaultTarget,
};
use crucible_core::{ObservableEventPayload, SchedulerEventLogEntry, SchedulerEventLogPayload};
use crucible_daemon::CrucibleMeasurementReplayEvidence;
use serde::Serialize;

const MAX_PROJECTED_ITEMS: usize = 4096;

/// Loads both observation-owned leaves and projects only public typed evidence.
///
/// # Errors
///
/// Returns an error when a chunk is unauthorized, mismatched, incomplete,
/// noncanonical, or outside the bounded trace and event-log contracts.
#[allow(clippy::too_many_arguments)]
pub(super) fn load_and_project_attempt_effect_evidence<S>(
    client: &CampaignClient<S>,
    principal: &CampaignPrincipal,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    attempt: AttemptId,
    observation: &Observation,
) -> Result<CampaignAttemptEffectEvidence, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let (event_id, event_bytes) = download_attempt_trace(
        client,
        principal,
        campaign,
        snapshot,
        attempt,
        observation,
        CampaignTraceKind::MeasurementEventLog,
    )?;
    let events =
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&event_bytes).map_err(|error| {
            backend_error(format!(
                "authenticated attempt event log is invalid: {error}"
            ))
        })?;
    let (trace_id, trace) = if observation.resolved_effect_trace().is_some() {
        let (id, bytes) = download_attempt_trace(
            client,
            principal,
            campaign,
            snapshot,
            attempt,
            observation,
            CampaignTraceKind::ResolvedEffect,
        )?;
        let trace = ResolvedEffectTrace::from_canonical_bytes(
            &bytes,
            FaultResourceLimits::compiled_maximum(),
        )
        .map_err(|error| {
            backend_error(format!(
                "authenticated attempt effect trace is invalid: {error}"
            ))
        })?;
        (Some(id.to_string()), Some(trace))
    } else {
        (None, None)
    };

    Ok(project_attempt_effect_evidence(
        trace_id,
        trace.as_ref(),
        event_id.to_string(),
        events.entries(),
    ))
}

/// Public metadata and safe typed projections from authenticated trace leaves.
#[derive(Debug, Serialize)]
pub(super) struct CampaignAttemptEffectEvidence {
    /// Versioned public projection schema.
    pub(super) schema: &'static str,
    /// Observation-owned canonical effect trace, when execution retained one.
    pub(super) resolved_effect_trace: Option<String>,
    /// Measurement-set-owned canonical scheduler event log.
    pub(super) measurement_event_log: String,
    /// Total applied network records before projection truncation.
    pub(super) network_effect_count: usize,
    /// Whether the record list reached its public response limit.
    pub(super) network_effects_truncated: bool,
    /// Bounded applied records with safe typed parameters.
    pub(super) network_effects: Vec<CampaignNetworkEffect>,
    /// Total guest semantic markers before projection truncation.
    pub(super) semantic_marker_count: usize,
    /// Whether the marker list reached its public response limit.
    pub(super) semantic_markers_truncated: bool,
    /// Bounded marker identities without guest details.
    pub(super) semantic_markers: Vec<CampaignSemanticMarker>,
}

#[derive(Debug, Serialize)]
pub(super) struct CampaignNetworkEffect {
    work_item_index: usize,
    record_index: usize,
    binding: String,
    effect: String,
    kind: &'static str,
    target: ResolvedFaultTarget,
    operation: Option<crucible_core::model::FaultOperation>,
    direction: Option<crucible_core::model::FaultDirection>,
    coordinate: crucible_core::model::FaultCoordinate,
    evidence_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct CampaignSemanticMarker {
    sequence: u64,
    entry: String,
    node: String,
    name: String,
    instance: String,
}

/// Projects only bounded typed fields from the canonical replay and event leaves.
pub(super) fn project_attempt_effect_evidence(
    trace_id: Option<String>,
    trace: Option<&ResolvedEffectTrace>,
    measurement_event_log: String,
    events: &[SchedulerEventLogEntry],
) -> CampaignAttemptEffectEvidence {
    let mut network_effect_count = 0;
    let mut network_effects = Vec::new();
    if let Some(trace) = trace {
        for (work_item_index, work_item) in trace.work_items.iter().enumerate() {
            for (record_index, record) in work_item.records.iter().enumerate() {
                let EffectSpecification::Network(specification) = record.request.specification()
                else {
                    continue;
                };
                network_effect_count += 1;
                if network_effects.len() >= MAX_PROJECTED_ITEMS {
                    continue;
                }
                network_effects.push(CampaignNetworkEffect {
                    work_item_index,
                    record_index,
                    binding: record.binding.to_string(),
                    effect: record.effect.to_string(),
                    kind: network_effect_kind(specification),
                    target: record.target.clone(),
                    operation: record.operation,
                    direction: record.direction,
                    coordinate: record.coordinate,
                    evidence_digest: record.evidence_digest.to_hex(),
                    parameters: network_parameters(specification),
                });
            }
        }
    }

    let mut semantic_marker_count = 0;
    let mut semantic_markers = Vec::new();
    for entry in events {
        let SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestSemanticMarker {
            node,
            marker,
            instance,
            ..
        }) = entry.payload()
        else {
            continue;
        };
        semantic_marker_count += 1;
        if semantic_markers.len() >= MAX_PROJECTED_ITEMS {
            continue;
        }
        semantic_markers.push(CampaignSemanticMarker {
            sequence: entry.sequence(),
            entry: entry.content_hash().to_hex(),
            node: node.name.clone(),
            name: marker.clone(),
            instance: instance.clone(),
        });
    }

    CampaignAttemptEffectEvidence {
        schema: "crucible.cli.campaign-attempt-effect-evidence.v1",
        resolved_effect_trace: trace_id,
        measurement_event_log,
        network_effect_count,
        network_effects_truncated: network_effect_count > network_effects.len(),
        network_effects,
        semantic_marker_count,
        semantic_markers_truncated: semantic_marker_count > semantic_markers.len(),
        semantic_markers,
    }
}

fn network_parameters(specification: &NetworkEffectSpecification) -> Option<serde_json::Value> {
    match specification {
        NetworkEffectSpecification::Availability {
            state,
            queued_policy,
            in_flight_policy,
        } => Some(serde_json::json!({
            "state": state,
            "queued_policy": queued_policy,
            "in_flight_policy": in_flight_policy,
        })),
        NetworkEffectSpecification::FrameLoss {
            probability,
            outcome,
        } => Some(serde_json::json!({
            "probability": probability,
            "outcome": outcome,
        })),
        NetworkEffectSpecification::PropagationDelay {
            delay_nanos,
            distance_velocity_lookup,
        } => Some(serde_json::json!({
            "delay_nanos": delay_nanos.map(|value| value.get()),
            "distance_velocity_lookup": distance_velocity_lookup.as_ref().map(ToString::to_string),
        })),
        _ => None,
    }
}

fn network_effect_kind(specification: &NetworkEffectSpecification) -> &'static str {
    match specification {
        NetworkEffectSpecification::Availability { .. } => "availability",
        NetworkEffectSpecification::FrameLoss { .. } => "frame-loss",
        NetworkEffectSpecification::PropagationDelay { .. } => "propagation-delay",
        _ => "other",
    }
}

#[allow(clippy::too_many_arguments)]
fn download_attempt_trace<S>(
    client: &CampaignClient<S>,
    principal: &CampaignPrincipal,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    attempt: AttemptId,
    observation: &Observation,
    kind: CampaignTraceKind,
) -> Result<(ContentId, Vec<u8>), CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let mut bytes = Vec::new();
    let mut expected_leaf = None;
    let mut expected_length = None;

    loop {
        let offset = u64::try_from(bytes.len())
            .map_err(|_| backend_error("attempt trace length exceeds addressable memory"))?;
        let request = GetCampaignTraceChunkRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            attempt,
            kind,
            offset,
            MAX_CAMPAIGN_TRACE_CHUNK_BYTES,
        )
        .map_err(|error| backend_error(format!("attempt trace request is invalid: {error}")))?;
        let response = client.get_campaign_trace_chunk(&request).map_err(|error| {
            backend_error(format!("authenticated attempt trace read failed: {error}"))
        })?;
        if response.observation().id().map_err(|error| {
            backend_error(format!(
                "authenticated trace observation identity is invalid: {error}"
            ))
        })? != observation.id().map_err(|error| {
            backend_error(format!(
                "explained observation identity is invalid: {error}"
            ))
        })? {
            return Err(backend_error(
                "attempt trace observation changed during read",
            ));
        }
        if response.total_bytes() > MAX_CAMPAIGN_TRACE_BYTES
            || expected_leaf.is_some_and(|leaf| leaf != response.trace())
            || expected_length.is_some_and(|length| length != response.total_bytes())
        {
            return Err(backend_error("attempt trace changed during chunked read"));
        }
        expected_leaf = Some(response.trace());
        expected_length = Some(response.total_bytes());
        bytes.extend_from_slice(response.chunk());

        if bytes.len() as u64 == response.total_bytes() {
            let actual =
                ContentId::for_bytes(ObjectKind::Trace, response.trace().schema_version(), &bytes);
            if actual != response.trace() {
                return Err(backend_error(
                    "attempt trace bytes do not match the authenticated leaf",
                ));
            }
            return Ok((actual, bytes));
        }
        if response.chunk().is_empty() {
            return Err(backend_error("attempt trace chunk did not advance"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_core::model::FaultReplayMode;
    use crucible_core::{GuestMeasurementValue, GuestSemanticMarkerDetail, Icount, NodeId};

    #[test]
    fn projects_authenticated_marker_identity_without_guest_details() {
        let trace = ResolvedEffectTrace {
            mode: FaultReplayMode::LockedEffect,
            work_items: Vec::new(),
            cursor: 0,
        };
        let marker = SchedulerEventLogEntry::guest_semantic_marker_observation(
            0,
            Icount { retired: 7 },
            NodeId {
                name: String::from("router-a"),
            },
            String::from("network.failover.observed"),
            String::from("instance-1"),
            vec![GuestSemanticMarkerDetail {
                key: String::from("payload"),
                value: GuestMeasurementValue::Enumerated(String::from("do-not-publish")),
            }],
        );

        let projected = project_attempt_effect_evidence(
            Some(String::from("trace-id")),
            Some(&trace),
            String::from("event-id"),
            &[marker],
        );
        let value = serde_json::to_value(projected).expect("public evidence JSON");

        assert_eq!(
            value["schema"],
            "crucible.cli.campaign-attempt-effect-evidence.v1"
        );
        assert_eq!(value["resolved_effect_trace"], "trace-id");
        assert_eq!(value["measurement_event_log"], "event-id");
        assert_eq!(value["semantic_marker_count"], 1);
        assert_eq!(value["semantic_markers"][0]["node"], "router-a");
        assert_eq!(
            value["semantic_markers"][0]["name"],
            "network.failover.observed"
        );
        assert_eq!(value["semantic_markers"][0]["instance"], "instance-1");
        assert!(value["semantic_markers"][0].get("details").is_none());
        assert!(!value.to_string().contains("do-not-publish"));
    }
}

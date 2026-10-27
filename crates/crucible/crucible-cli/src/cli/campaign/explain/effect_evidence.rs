//! Bounded public views of canonical attempt effect and event-log evidence.

use super::*;
use crucible_campaign::{
    CampaignTraceKind, GetCampaignTraceChunkRequest, MAX_CAMPAIGN_TRACE_CHUNK_BYTES,
};
use crucible_daemon::campaign_store_composition::{ContentId, ObjectKind};
use crucible_daemon::{
    AttemptLogSegmentSource, CrucibleMeasurementError, CrucibleMeasurementReplayEvidence,
};
use crucible_session::engine::{
    EffectSpecification, FaultCoordinate, FaultDirection, FaultOperation, GuestMeasurementEvent,
    GuestMeasurementValue, GuestSemanticMarkerDetail, NetworkEffectSpecification,
    ObservableEventPayload, ResolvedEffectTraceManifest, ResolvedFaultTarget,
    ResolvedReplayWorkItem, SchedulerEventLogEntry, SchedulerEventLogPayload,
    decode_resolved_effect_trace_segment,
};
use serde::Serialize;

const MAX_PROJECTED_ITEMS: usize = 4096;

/// Loads both observation-owned leaves and projects only public typed evidence.
///
/// # Errors
///
/// Returns an error when a chunk is unauthorized, mismatched, incomplete,
/// noncanonical, or outside the bounded trace and event-log contracts.
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
    // Segments are fetched one at a time and authenticated against the
    // leaf's manifest before their entries are projected.
    let segments = DownloadedSegments {
        client,
        principal,
        campaign,
        snapshot,
        attempt,
        observation,
    };
    let mut projection = EventLogProjection::default();
    events
        .try_for_each_entry(&segments, |entry| {
            projection.observe(entry);
            Ok::<_, CrucibleMeasurementError>(())
        })
        .map_err(|error| {
            backend_error(format!(
                "authenticated attempt event log is invalid: {error}"
            ))
        })?;
    let trace_id = if observation.resolved_effect_trace().is_some() {
        let id = project_resolved_effect_trace(
            client,
            principal,
            campaign,
            snapshot,
            attempt,
            observation,
            &mut projection,
        )?;
        Some(id.to_string())
    } else {
        None
    };

    Ok(projection.finish(trace_id, event_id.to_string()))
}

/// Streams an attempt's segmented resolved-effect trace into `projection`.
///
/// The manifest must reference exactly the segments the observation lists.
/// Each segment is downloaded, authenticated against its manifest reference,
/// projected, and dropped before the next one is read.
fn project_resolved_effect_trace<S>(
    client: &CampaignClient<S>,
    principal: &CampaignPrincipal,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    attempt: AttemptId,
    observation: &Observation,
    projection: &mut EventLogProjection,
) -> Result<ContentId, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let invalid = |error: &dyn std::fmt::Display| {
        backend_error(format!(
            "authenticated attempt effect trace is invalid: {error}"
        ))
    };
    let listed = observation
        .resolved_effect_trace()
        .ok_or_else(|| backend_error("attempt observation has no resolved-effect trace"))?;

    let (manifest_id, manifest_bytes) = download_attempt_trace(
        client,
        principal,
        campaign,
        snapshot,
        attempt,
        observation,
        CampaignTraceKind::ResolvedEffect,
    )?;
    let manifest = ResolvedEffectTraceManifest::from_canonical_bytes(&manifest_bytes)
        .map_err(|error| invalid(&error))?;
    if !manifest.segment_ids().eq(listed.segments().iter().copied()) {
        return Err(backend_error(
            "attempt effect trace manifest differs from the observation's segments",
        ));
    }

    let mut work_item_index = 0_usize;
    for segment in manifest.segments() {
        let (id, bytes) = download_attempt_trace(
            client,
            principal,
            campaign,
            snapshot,
            attempt,
            observation,
            CampaignTraceKind::ResolvedEffectSegment(segment.id),
        )?;
        if id != segment.id {
            return Err(backend_error("attempt trace returned another segment"));
        }
        let items = decode_resolved_effect_trace_segment(segment, &bytes)
            .map_err(|error| invalid(&error))?;
        for item in &items {
            projection.observe_work_item(work_item_index, item);
            work_item_index += 1;
        }
    }
    Ok(manifest_id)
}

/// Reads one attempt's event-log segments through the campaign service.
struct DownloadedSegments<'request, S> {
    client: &'request CampaignClient<S>,
    principal: &'request CampaignPrincipal,
    campaign: &'request CampaignName,
    snapshot: CampaignSnapshotId,
    attempt: AttemptId,
    observation: &'request Observation,
}

impl<S> AttemptLogSegmentSource for DownloadedSegments<'_, S>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    fn segment(&self, id: ContentId) -> std::io::Result<Vec<u8>> {
        let (trace, bytes) = download_attempt_trace(
            self.client,
            self.principal,
            self.campaign,
            self.snapshot,
            self.attempt,
            self.observation,
            CampaignTraceKind::MeasurementEventLogSegment(id),
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        if trace != id {
            return Err(std::io::Error::other(
                "attempt trace returned another segment",
            ));
        }
        Ok(bytes)
    }
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
    /// Total typed route observations before projection truncation.
    pub(super) route_event_count: usize,
    /// Whether the route observation list reached its public response limit.
    pub(super) route_events_truncated: bool,
    /// Bounded route observations bound to their event-log entries.
    pub(super) route_events: Vec<CampaignRouteEvent>,
    /// Total unsigned metric samples before projection truncation.
    pub(super) metric_sample_count: usize,
    /// Whether the unsigned sample list reached its public response limit.
    pub(super) metric_samples_truncated: bool,
    /// Bounded unsigned guest metric samples with no raw packet data.
    pub(super) metric_samples: Vec<CampaignUnsignedMetricSample>,
}

#[derive(Debug, Serialize)]
pub(super) struct CampaignNetworkEffect {
    work_item_index: usize,
    record_index: usize,
    binding: String,
    effect: String,
    kind: &'static str,
    target: ResolvedFaultTarget,
    operation: Option<FaultOperation>,
    direction: Option<FaultDirection>,
    coordinate: FaultCoordinate,
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

#[derive(Debug, Serialize)]
pub(super) struct CampaignRouteEvent {
    event_sequence: u64,
    entry: String,
    node: String,
    name: String,
    instance: String,
    path: String,
    route_sequence: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct CampaignUnsignedMetricSample {
    event_sequence: u64,
    entry: String,
    node: String,
    measurement: String,
    instance: String,
    name: String,
    value_kind: &'static str,
    value: u64,
}

/// Projects only bounded typed fields from an in-memory event log and trace.
#[cfg(test)]
fn project_attempt_effect_evidence(
    trace_id: Option<String>,
    work_items: &[ResolvedReplayWorkItem],
    measurement_event_log: String,
    events: &[SchedulerEventLogEntry],
) -> CampaignAttemptEffectEvidence {
    let mut projection = EventLogProjection::default();
    for entry in events {
        projection.observe(entry);
    }
    for (index, item) in work_items.iter().enumerate() {
        projection.observe_work_item(index, item);
    }
    projection.finish(trace_id, measurement_event_log)
}

/// Bounded public projections accumulated one entry or work item at a time.
///
/// Counts cover every entry and record; retained items stop at the public
/// limit. The event log and the resolved-effect trace can therefore both be
/// streamed segment by segment.
#[derive(Default)]
pub(super) struct EventLogProjection {
    network_effect_count: usize,
    network_effects: Vec<CampaignNetworkEffect>,
    semantic_marker_count: usize,
    semantic_markers: Vec<CampaignSemanticMarker>,
    route_event_count: usize,
    route_events: Vec<CampaignRouteEvent>,
    metric_sample_count: usize,
    metric_samples: Vec<CampaignUnsignedMetricSample>,
}

impl EventLogProjection {
    pub(super) fn observe(&mut self, entry: &SchedulerEventLogEntry) {
        match entry.payload() {
            SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestSemanticMarker {
                node,
                marker,
                instance,
                details,
                ..
            }) => {
                self.semantic_marker_count += 1;
                if self.semantic_markers.len() < MAX_PROJECTED_ITEMS {
                    self.semantic_markers.push(CampaignSemanticMarker {
                        sequence: entry.sequence(),
                        entry: entry.content_hash().to_hex(),
                        node: node.name.clone(),
                        name: marker.clone(),
                        instance: instance.clone(),
                    });
                }
                if marker == "network.failover.observed"
                    && let Some((path, route_sequence)) = route_details(details)
                {
                    self.route_event_count += 1;
                    if self.route_events.len() < MAX_PROJECTED_ITEMS {
                        self.route_events.push(CampaignRouteEvent {
                            event_sequence: entry.sequence(),
                            entry: entry.content_hash().to_hex(),
                            node: node.name.clone(),
                            name: marker.clone(),
                            instance: instance.clone(),
                            path: path.to_owned(),
                            route_sequence,
                        });
                    }
                }
            }
            SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMeasurement {
                node,
                event:
                    GuestMeasurementEvent::Sample {
                        measurement,
                        instance,
                        metric,
                        value: GuestMeasurementValue::Unsigned(value),
                    },
                ..
            }) => {
                self.metric_sample_count += 1;
                if self.metric_samples.len() < MAX_PROJECTED_ITEMS {
                    self.metric_samples.push(CampaignUnsignedMetricSample {
                        event_sequence: entry.sequence(),
                        entry: entry.content_hash().to_hex(),
                        node: node.name.clone(),
                        measurement: measurement.clone(),
                        instance: instance.clone(),
                        name: metric.clone(),
                        value_kind: "u64",
                        value: *value,
                    });
                }
            }
            _ => {}
        }
    }

    /// Projects the applied network records of one resolved-effect work item.
    pub(super) fn observe_work_item(
        &mut self,
        work_item_index: usize,
        work_item: &ResolvedReplayWorkItem,
    ) {
        for (record_index, record) in work_item.records.iter().enumerate() {
            let EffectSpecification::Network(specification) = record.request.specification() else {
                continue;
            };
            self.network_effect_count += 1;
            if self.network_effects.len() >= MAX_PROJECTED_ITEMS {
                continue;
            }
            self.network_effects.push(CampaignNetworkEffect {
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

    pub(super) fn finish(
        self,
        trace_id: Option<String>,
        measurement_event_log: String,
    ) -> CampaignAttemptEffectEvidence {
        CampaignAttemptEffectEvidence {
            schema: "crucible.cli.campaign-attempt-effect-evidence.v2",
            resolved_effect_trace: trace_id,
            measurement_event_log,
            network_effect_count: self.network_effect_count,
            network_effects_truncated: self.network_effect_count > self.network_effects.len(),
            network_effects: self.network_effects,
            semantic_marker_count: self.semantic_marker_count,
            semantic_markers_truncated: self.semantic_marker_count > self.semantic_markers.len(),
            semantic_markers: self.semantic_markers,
            route_event_count: self.route_event_count,
            route_events_truncated: self.route_event_count > self.route_events.len(),
            route_events: self.route_events,
            metric_sample_count: self.metric_sample_count,
            metric_samples_truncated: self.metric_sample_count > self.metric_samples.len(),
            metric_samples: self.metric_samples,
        }
    }
}

fn route_details(details: &[GuestSemanticMarkerDetail]) -> Option<(&str, u64)> {
    if details.len() != 2 {
        return None;
    }
    let path = details.iter().find(|detail| detail.key == "path")?;
    let sequence = details.iter().find(|detail| detail.key == "sequence")?;
    match (&path.value, &sequence.value) {
        (GuestMeasurementValue::Enumerated(path), GuestMeasurementValue::Unsigned(sequence))
            if !path.is_empty() && *sequence > 0 =>
        {
            Some((path, *sequence))
        }
        _ => None,
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
        if response.total_bytes() > kind.max_leaf_bytes()
            || expected_leaf.is_some_and(|leaf| leaf != response.trace())
            || expected_length.is_some_and(|length| length != response.total_bytes())
        {
            return Err(backend_error("attempt trace changed during chunked read"));
        }
        expected_leaf = Some(response.trace());
        expected_length = Some(response.total_bytes());
        bytes.extend_from_slice(response.chunk());

        if bytes.len() as u64 == response.total_bytes() {
            verify_complete_trace_content_id(response.trace(), &bytes)?;
            return Ok((response.trace(), bytes));
        }
        if response.chunk().is_empty() {
            return Err(backend_error("attempt trace chunk did not advance"));
        }
    }
}

fn verify_complete_trace_content_id(trace: ContentId, bytes: &[u8]) -> Result<(), CliError> {
    let actual = ContentId::for_bytes(ObjectKind::Trace, trace.schema_version(), bytes);
    if actual != trace {
        return Err(backend_error(
            "attempt trace bytes do not match the authenticated leaf",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_core::{GuestMeasurementValue, GuestSemanticMarkerDetail, Icount, NodeId};

    #[test]
    fn projects_authenticated_marker_identity_without_guest_details()
    -> Result<(), serde_json::Error> {
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
            &[],
            String::from("event-id"),
            &[marker],
        );
        let value = serde_json::to_value(projected)?;

        assert_eq!(
            value["schema"],
            "crucible.cli.campaign-attempt-effect-evidence.v2"
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
        assert_eq!(value["route_event_count"], 0);
        Ok(())
    }

    #[test]
    fn projects_route_details_and_unsigned_samples_in_event_order() -> Result<(), serde_json::Error>
    {
        let node = NodeId {
            name: String::from("traffic-west"),
        };
        let sample = |event_sequence, retired, name, value| {
            SchedulerEventLogEntry::guest_measurement_observation(
                event_sequence,
                Icount { retired },
                node.clone(),
                GuestMeasurementEvent::Sample {
                    measurement: String::from("traffic-window"),
                    instance: String::from("instance-1"),
                    metric: String::from(name),
                    value: GuestMeasurementValue::Unsigned(value),
                },
            )
        };
        let success = sample(0, 1, "traffic_success_packets", 7);
        let route = SchedulerEventLogEntry::guest_semantic_marker_observation(
            1,
            Icount { retired: 2 },
            node.clone(),
            String::from("network.failover.observed"),
            String::from("instance-1"),
            vec![
                GuestSemanticMarkerDetail {
                    key: String::from("path"),
                    value: GuestMeasurementValue::Enumerated(String::from("a-c-east")),
                },
                GuestSemanticMarkerDetail {
                    key: String::from("sequence"),
                    value: GuestMeasurementValue::Unsigned(42),
                },
            ],
        );
        let route_hash = route.content_hash().to_hex();
        let loss = sample(2, 3, "traffic_loss_packets", 2);

        let projected = project_attempt_effect_evidence(
            None,
            &[],
            String::from("event-id"),
            &[success, route, loss],
        );
        let value = serde_json::to_value(projected)?;

        assert_eq!(value["route_event_count"], 1);
        assert_eq!(value["route_events"][0]["entry"], route_hash);
        assert_eq!(value["route_events"][0]["event_sequence"], 1);
        assert_eq!(value["route_events"][0]["node"], "traffic-west");
        assert_eq!(value["route_events"][0]["path"], "a-c-east");
        assert_eq!(value["route_events"][0]["route_sequence"], 42);
        assert_eq!(value["metric_sample_count"], 2);
        assert_eq!(value["metric_samples"][0]["event_sequence"], 0);
        assert_eq!(
            value["metric_samples"][0]["name"],
            "traffic_success_packets"
        );
        assert_eq!(value["metric_samples"][0]["value_kind"], "u64");
        assert_eq!(value["metric_samples"][0]["value"], 7);
        assert_eq!(value["metric_samples"][1]["event_sequence"], 2);
        assert_eq!(value["metric_samples"][1]["name"], "traffic_loss_packets");
        assert_eq!(value["metric_samples"][1]["value"], 2);
        Ok(())
    }

    #[test]
    fn rejects_tampered_trace_bytes_before_typed_projection() {
        let bytes = b"canonical event log";
        let trace = ContentId::for_bytes(ObjectKind::Trace, 2, bytes);
        assert!(verify_complete_trace_content_id(trace, bytes).is_ok());

        let mut tampered = bytes.to_vec();
        tampered[0] ^= 1;
        assert!(verify_complete_trace_content_id(trace, &tampered).is_err());
    }

    #[test]
    fn caps_public_metric_samples_while_retaining_the_total_count()
    -> Result<(), std::num::TryFromIntError> {
        let events = (0..=MAX_PROJECTED_ITEMS)
            .map(|index| -> Result<_, std::num::TryFromIntError> {
                let sequence = u64::try_from(index)?;
                Ok(SchedulerEventLogEntry::guest_measurement_observation(
                    sequence,
                    Icount { retired: sequence },
                    NodeId {
                        name: String::from("traffic-west"),
                    },
                    GuestMeasurementEvent::Sample {
                        measurement: String::from("traffic-window"),
                        instance: String::from("instance-1"),
                        metric: String::from("traffic_success_packets"),
                        value: GuestMeasurementValue::Unsigned(sequence),
                    },
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let projected =
            project_attempt_effect_evidence(None, &[], String::from("event-id"), &events);

        assert_eq!(projected.metric_sample_count, MAX_PROJECTED_ITEMS + 1);
        assert_eq!(projected.metric_samples.len(), MAX_PROJECTED_ITEMS);
        assert!(projected.metric_samples_truncated);
        Ok(())
    }
}

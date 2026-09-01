//! Borrowed canonical wire views for allocation-free network-output encoding.

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

use super::*;

#[derive(Serialize)]
pub(super) struct BackendNetworkOutputEncodeWire<'a> {
    version: u16,
    source: &'a str,
    destination: &'a str,
    emit_icount: u64,
    sequence: u64,
    payload: &'a [u8],
    route: Option<BackendNetworkRouteEncodeWire<'a>>,
    fault: BackendNetworkFaultContinuationEncodeWire<'a>,
}

impl<'a> BackendNetworkOutputEncodeWire<'a> {
    pub(super) fn new(
        output: &'a BackendNetworkOutput,
    ) -> Result<Self, BackendNetworkOutputCodecError> {
        validate_network_checkpoint_name(&output.source.name, "source")?;
        validate_network_checkpoint_name(&output.destination.name, "destination")?;
        if output.payload.len() > HARD_BACKEND_NETWORK_CHECKPOINT_BYTES {
            return Err(backend_network_resource(
                "frame payload",
                0,
                output.payload.len(),
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            ));
        }
        validate_network_fault_continuation(&output.fault_continuation)?;
        let route = output
            .route
            .as_ref()
            .map(BackendNetworkRouteEncodeWire::new)
            .transpose()?;
        Ok(Self {
            version: BACKEND_NETWORK_OUTPUT_VERSION,
            source: &output.source.name,
            destination: &output.destination.name,
            emit_icount: output.emit_icount.retired,
            sequence: output.sequence,
            payload: &output.payload,
            route,
            fault: BackendNetworkFaultContinuationEncodeWire::new(&output.fault_continuation),
        })
    }
}

#[derive(Serialize)]
struct BackendNetworkRouteEncodeWire<'a> {
    link: &'a str,
    direction: u8,
    destination: &'a str,
}

impl<'a> BackendNetworkRouteEncodeWire<'a> {
    fn new(route: &'a BackendNetworkRoute) -> Result<Self, BackendNetworkOutputCodecError> {
        validate_network_checkpoint_name(&route.link.name, "route link")?;
        validate_network_checkpoint_name(&route.destination.name, "route destination")?;
        Ok(Self {
            link: &route.link.name,
            direction: match route.direction {
                crate::device::NetworkLinkDirection::EndpointAToEndpointB => 1,
                crate::device::NetworkLinkDirection::EndpointBToEndpointA => 2,
            },
            destination: &route.destination.name,
        })
    }
}

#[derive(Serialize)]
struct BackendNetworkFaultContinuationEncodeWire<'a> {
    preserved_availability: PreservedAvailabilitySequence<'a>,
    resolved_frame_effects: ResolvedNetworkFrameEffectsEncodeWire<'a>,
    protocol_expansion_path: &'a [u16],
    generated_response_depth: u8,
    generated_response_cause: Option<ContentHash>,
    forwarding_mutation_path: &'a [ContentHash],
    forced_route_destination: Option<&'a str>,
    cursor: BackendNetworkFaultCursorEncodeWire<'a>,
}

impl<'a> BackendNetworkFaultContinuationEncodeWire<'a> {
    fn new(value: &'a BackendNetworkFaultContinuation) -> Self {
        Self {
            preserved_availability: PreservedAvailabilitySequence(&value.preserved_availability),
            resolved_frame_effects: ResolvedNetworkFrameEffectsEncodeWire::new(
                &value.resolved_frame_effects,
            ),
            protocol_expansion_path: &value.protocol_expansion_path,
            generated_response_depth: value.generated_response_depth,
            generated_response_cause: value.generated_response_cause,
            forwarding_mutation_path: &value.forwarding_mutation_path,
            forced_route_destination: value
                .forced_route_destination
                .as_ref()
                .map(|node| node.name.as_str()),
            cursor: BackendNetworkFaultCursorEncodeWire::new(&value.cursor),
        }
    }
}

#[derive(Clone, Copy)]
struct PreservedAvailabilitySequence<'a>(&'a [BackendNetworkPreservedAvailability]);

impl Serialize for PreservedAvailabilitySequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            sequence.serialize_element(&BackendNetworkPreservedAvailabilityEncodeWire {
                binding: &entry.binding,
                target: &entry.target,
                phase: entry.phase,
                transition_sequence: entry.transition_sequence,
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct BackendNetworkPreservedAvailabilityEncodeWire<'a> {
    binding: &'a FaultObjectId,
    target: &'a ResolvedFaultTarget,
    phase: FaultPhase,
    transition_sequence: u64,
}

#[derive(Serialize)]
struct BackendNetworkFaultCursorEncodeWire<'a> {
    completed_phases: CompletedFaultPhaseSequence<'a>,
    not_before_nanos: u64,
    completed_release_nanos: u64,
    queue_opportunity: Option<ContentHash>,
    repeated_phase_effect: Option<EffectKind>,
    queue_priority: Option<u8>,
    route_path_version: Option<&'a FaultObjectId>,
}

impl<'a> BackendNetworkFaultCursorEncodeWire<'a> {
    fn new(value: &'a BackendNetworkFaultCursor) -> Self {
        Self {
            completed_phases: CompletedFaultPhaseSequence(&value.completed_phases),
            not_before_nanos: value.not_before_nanos,
            completed_release_nanos: value.completed_release_nanos,
            queue_opportunity: value.queue_opportunity,
            repeated_phase_effect: value.repeated_phase_effect,
            queue_priority: value.queue_priority,
            route_path_version: value.route_path_version.as_ref(),
        }
    }
}

#[derive(Clone, Copy)]
struct CompletedFaultPhaseSequence<'a>(&'a [BackendNetworkCompletedFaultPhase]);

impl Serialize for CompletedFaultPhaseSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            sequence.serialize_element(&BackendNetworkCompletedFaultPhaseEncodeWire {
                target: &entry.target,
                phase: entry.phase,
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct BackendNetworkCompletedFaultPhaseEncodeWire<'a> {
    target: &'a ResolvedFaultTarget,
    phase: FaultPhase,
}

#[derive(Serialize)]
struct ResolvedNetworkFrameEffectsEncodeWire<'a> {
    latency_delta_nanos: i64,
    additional_delay_nanos: u64,
    serialization_rate_cap_bps: Option<u64>,
    serialization_accounted: bool,
    contact_services_accounted: &'a [[u8; 32]],
    drop: bool,
    duplicate_gaps_nanos: &'a [u64],
}

impl<'a> ResolvedNetworkFrameEffectsEncodeWire<'a> {
    fn new(value: &'a crucible_device::ResolvedNetworkFrameEffects) -> Self {
        Self {
            latency_delta_nanos: value.latency_delta_nanos(),
            additional_delay_nanos: value.additional_delay_nanos(),
            serialization_rate_cap_bps: value.serialization_rate_cap_bps(),
            serialization_accounted: value.serialization_is_accounted(),
            contact_services_accounted: value.accounted_contact_services(),
            drop: value.is_dropped(),
            duplicate_gaps_nanos: value.duplicate_gaps_nanos(),
        }
    }
}

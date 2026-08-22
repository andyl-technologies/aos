//! Canonical pending backend-network output checkpoints.
//!
//! The format retains routed frame identity and every signal-fault
//! continuation needed to resume scheduler-owned delivery.

use super::*;

mod encode;
mod error;
mod writer;

pub use error::BackendNetworkOutputCodecError;

use encode::BackendNetworkOutputEncodeWire;
use error::backend_network_resource;

use writer::{BackendNetworkCheckpointCountingWriter, BackendNetworkCheckpointReservedWriter};

impl BackendNetworkOutput {
    /// Encodes a pending routed frame and its complete fault continuation.
    ///
    /// # Errors
    ///
    /// Returns [`BackendNetworkOutputCodecError`] when an identity or payload
    /// exceeds its hard bound, a continuation collection is not canonical, a
    /// target is invalid, or deterministic CBOR encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BackendNetworkOutputCodecError> {
        self.canonical_bytes_with_limit(
            u64::try_from(HARD_BACKEND_NETWORK_CHECKPOINT_BYTES).unwrap_or(u64::MAX),
        )
    }

    /// Encodes a pending routed frame under an authored aggregate byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BackendNetworkOutputCodecError`] under the same conditions as
    /// [`Self::canonical_bytes`], and when the representation exceeds `maximum`.
    pub fn canonical_bytes_with_limit(
        &self,
        maximum: u64,
    ) -> Result<Vec<u8>, BackendNetworkOutputCodecError> {
        let hard = u64::try_from(HARD_BACKEND_NETWORK_CHECKPOINT_BYTES).unwrap_or(u64::MAX);
        let configured = usize::try_from(maximum.min(hard)).unwrap_or(usize::MAX);
        let wire = BackendNetworkOutputEncodeWire::new(self)?;
        let mut counter = BackendNetworkCheckpointCountingWriter::new(configured);
        ciborium::ser::into_writer(&wire, &mut counter).map_err(|_| {
            counter
                .failure
                .unwrap_or(BackendNetworkOutputCodecError::Encoding)
        })?;
        let encoded_length = usize::try_from(counter.length).map_err(|_| {
            backend_network_resource(
                "encoded frame",
                0,
                usize::MAX,
                configured,
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            )
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(encoded_length).map_err(|_| {
            backend_network_resource(
                "encoded frame",
                0,
                encoded_length,
                configured,
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            )
        })?;
        let mut writer =
            BackendNetworkCheckpointReservedWriter::new(&mut bytes, encoded_length, configured);
        ciborium::ser::into_writer(&wire, &mut writer).map_err(|_| {
            writer
                .failure
                .unwrap_or(BackendNetworkOutputCodecError::Encoding)
        })?;
        if bytes.len() != encoded_length {
            return Err(BackendNetworkOutputCodecError::Encoding);
        }
        Ok(bytes)
    }

    /// Decodes and validates a pending routed frame and fault continuation.
    ///
    /// # Errors
    ///
    /// Returns [`BackendNetworkOutputCodecError`] for malformed, over-limit,
    /// noncanonical, semantically invalid, or trailing state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BackendNetworkOutputCodecError> {
        Self::from_canonical_bytes_with_limit(
            bytes,
            u64::try_from(HARD_BACKEND_NETWORK_CHECKPOINT_BYTES).unwrap_or(u64::MAX),
        )
    }

    /// Decodes a pending routed frame under an authored aggregate byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BackendNetworkOutputCodecError`] under the same conditions as
    /// [`Self::from_canonical_bytes`], and before decoding when `bytes` exceeds
    /// `maximum`.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum: u64,
    ) -> Result<Self, BackendNetworkOutputCodecError> {
        let hard = u64::try_from(HARD_BACKEND_NETWORK_CHECKPOINT_BYTES).unwrap_or(u64::MAX);
        let configured = usize::try_from(maximum.min(hard)).unwrap_or(usize::MAX);
        if bytes.len() > configured {
            return Err(backend_network_resource(
                "encoded frame",
                0,
                bytes.len(),
                configured,
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            ));
        }
        let wire: BackendNetworkOutputWire = ciborium::de::from_reader(bytes)
            .map_err(|_| BackendNetworkOutputCodecError::Encoding)?;
        let output = Self::try_from(wire)?;
        if output.canonical_bytes()?.as_slice() != bytes {
            return Err(BackendNetworkOutputCodecError::Noncanonical);
        }
        Ok(output)
    }
}

const BACKEND_NETWORK_OUTPUT_VERSION: u16 = 1;
const HARD_BACKEND_NETWORK_CHECKPOINT_BYTES: usize = 16_777_216;
const HARD_BACKEND_NETWORK_ID_BYTES: usize = 4_096;
const HARD_BACKEND_NETWORK_CURSOR_PHASES: usize = 65_536;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkOutputWire {
    version: u16,
    source: String,
    destination: String,
    emit_icount: u64,
    sequence: u64,
    payload: Vec<u8>,
    route: Option<BackendNetworkRouteWire>,
    fault: BackendNetworkFaultContinuationWire,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkRouteWire {
    link: String,
    direction: u8,
    destination: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkFaultContinuationWire {
    preserved_availability: Vec<BackendNetworkPreservedAvailabilityWire>,
    resolved_frame_effects: ResolvedNetworkFrameEffectsWire,
    protocol_expansion_path: Vec<u16>,
    generated_response_depth: u8,
    generated_response_cause: Option<ContentHash>,
    forwarding_mutation_path: Vec<ContentHash>,
    forced_route_destination: Option<String>,
    cursor: BackendNetworkFaultCursorWire,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkPreservedAvailabilityWire {
    binding: FaultObjectId,
    target: ResolvedFaultTarget,
    phase: FaultPhase,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkCompletedFaultPhaseWire {
    target: ResolvedFaultTarget,
    phase: FaultPhase,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkFaultCursorWire {
    completed_phases: Vec<BackendNetworkCompletedFaultPhaseWire>,
    not_before_nanos: u64,
    completed_release_nanos: u64,
    queue_opportunity: Option<ContentHash>,
    repeated_phase_effect: Option<EffectKind>,
    queue_priority: Option<u8>,
    route_path_version: Option<FaultObjectId>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedNetworkFrameEffectsWire {
    latency_delta_nanos: i64,
    additional_delay_nanos: u64,
    serialization_rate_cap_bps: Option<u64>,
    serialization_accounted: bool,
    contact_services_accounted: Vec<[u8; 32]>,
    drop: bool,
    duplicate_gaps_nanos: Vec<u64>,
}

impl TryFrom<BackendNetworkOutputWire> for BackendNetworkOutput {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(wire: BackendNetworkOutputWire) -> Result<Self, Self::Error> {
        if wire.version != BACKEND_NETWORK_OUTPUT_VERSION {
            return Err(BackendNetworkOutputCodecError::Version);
        }
        validate_network_checkpoint_name(&wire.source, "source")?;
        validate_network_checkpoint_name(&wire.destination, "destination")?;
        if wire.payload.len() > HARD_BACKEND_NETWORK_CHECKPOINT_BYTES {
            return Err(backend_network_resource(
                "frame payload",
                0,
                wire.payload.len(),
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            ));
        }
        let route = wire
            .route
            .map(|route| {
                validate_network_checkpoint_name(&route.link, "route link")?;
                validate_network_checkpoint_name(&route.destination, "route destination")?;
                let direction = match route.direction {
                    1 => crate::device::NetworkLinkDirection::EndpointAToEndpointB,
                    2 => crate::device::NetworkLinkDirection::EndpointBToEndpointA,
                    _ => return Err(BackendNetworkOutputCodecError::Invalid("route direction")),
                };
                Ok(BackendNetworkRoute {
                    link: LinkId::from_name(route.link),
                    direction,
                    destination: NodeId {
                        name: route.destination,
                    },
                })
            })
            .transpose()?;
        Ok(Self {
            source: NodeId { name: wire.source },
            destination: NodeId {
                name: wire.destination,
            },
            emit_icount: Icount {
                retired: wire.emit_icount,
            },
            sequence: wire.sequence,
            payload: wire.payload,
            route,
            fault_continuation: BackendNetworkFaultContinuation::try_from(wire.fault)?,
        })
    }
}

impl TryFrom<BackendNetworkFaultContinuationWire> for BackendNetworkFaultContinuation {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(wire: BackendNetworkFaultContinuationWire) -> Result<Self, Self::Error> {
        let preserved_availability = wire
            .preserved_availability
            .into_iter()
            .map(|entry| {
                entry
                    .target
                    .validate()
                    .map_err(|_| BackendNetworkOutputCodecError::Invalid("preserved target"))?;
                Ok(BackendNetworkPreservedAvailability {
                    binding: entry.binding,
                    target: entry.target,
                    phase: entry.phase,
                    transition_sequence: entry.transition_sequence,
                })
            })
            .collect::<Result<Vec<_>, BackendNetworkOutputCodecError>>()?;
        let forced_route_destination = wire
            .forced_route_destination
            .map(|name| {
                validate_network_checkpoint_name(&name, "forced route destination")?;
                Ok(NodeId { name })
            })
            .transpose()?;
        let value = Self {
            preserved_availability,
            resolved_frame_effects: crucible_device::ResolvedNetworkFrameEffects::try_from(
                wire.resolved_frame_effects,
            )?,
            protocol_expansion_path: wire.protocol_expansion_path,
            generated_response_depth: wire.generated_response_depth,
            generated_response_cause: wire.generated_response_cause,
            forwarding_mutation_path: wire.forwarding_mutation_path,
            forced_route_destination,
            cursor: BackendNetworkFaultCursor::try_from(wire.cursor)?,
        };
        validate_network_fault_continuation(&value)?;
        Ok(value)
    }
}

impl TryFrom<BackendNetworkFaultCursorWire> for BackendNetworkFaultCursor {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(wire: BackendNetworkFaultCursorWire) -> Result<Self, Self::Error> {
        if wire.completed_phases.len() > HARD_BACKEND_NETWORK_CURSOR_PHASES {
            return Err(backend_network_resource(
                "completed phases",
                0,
                wire.completed_phases.len(),
                HARD_BACKEND_NETWORK_CURSOR_PHASES,
                HARD_BACKEND_NETWORK_CURSOR_PHASES,
            ));
        }
        let completed_phases = wire
            .completed_phases
            .into_iter()
            .map(|entry| {
                entry
                    .target
                    .validate()
                    .map_err(|_| BackendNetworkOutputCodecError::Invalid("completed target"))?;
                Ok(BackendNetworkCompletedFaultPhase {
                    target: entry.target,
                    phase: entry.phase,
                })
            })
            .collect::<Result<Vec<_>, BackendNetworkOutputCodecError>>()?;
        if completed_phases.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(BackendNetworkOutputCodecError::Noncanonical);
        }
        let deferred = wire.queue_opportunity.is_some();
        if wire.repeated_phase_effect.is_some() && !deferred
            || wire.queue_priority.is_some() && wire.repeated_phase_effect.is_none()
        {
            return Err(BackendNetworkOutputCodecError::Invalid(
                "fault cursor deferral state",
            ));
        }
        Ok(Self {
            completed_phases,
            not_before_nanos: wire.not_before_nanos,
            completed_release_nanos: wire.completed_release_nanos,
            queue_opportunity: wire.queue_opportunity,
            repeated_phase_effect: wire.repeated_phase_effect,
            queue_priority: wire.queue_priority,
            route_path_version: wire.route_path_version,
        })
    }
}

impl TryFrom<ResolvedNetworkFrameEffectsWire> for crucible_device::ResolvedNetworkFrameEffects {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(wire: ResolvedNetworkFrameEffectsWire) -> Result<Self, Self::Error> {
        if wire.contact_services_accounted.len() > 256 || wire.duplicate_gaps_nanos.len() > 256 {
            return Err(backend_network_resource(
                "resolved frame effects",
                0,
                wire.contact_services_accounted
                    .len()
                    .max(wire.duplicate_gaps_nanos.len()),
                256,
                256,
            ));
        }
        if wire
            .contact_services_accounted
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || wire
                .duplicate_gaps_nanos
                .windows(2)
                .any(|pair| pair[0] > pair[1])
            || !wire.contact_services_accounted.is_empty() && !wire.serialization_accounted
        {
            return Err(BackendNetworkOutputCodecError::Noncanonical);
        }
        let mut effects = Self::default();
        effects
            .add_latency_delta(wire.latency_delta_nanos)
            .map_err(|_| BackendNetworkOutputCodecError::Invalid("latency delta"))?;
        effects
            .add_delay(wire.additional_delay_nanos)
            .map_err(|_| BackendNetworkOutputCodecError::Invalid("additional delay"))?;
        if let Some(rate) = wire.serialization_rate_cap_bps {
            effects
                .constrain_rate(rate)
                .map_err(|_| BackendNetworkOutputCodecError::Invalid("rate cap"))?;
        }
        for service in wire.contact_services_accounted {
            effects
                .mark_contact_service_accounted(service)
                .map_err(|_| BackendNetworkOutputCodecError::Invalid("contact service"))?;
        }
        if wire.serialization_accounted && effects.accounted_contact_services().is_empty() {
            effects.mark_serialization_accounted();
        }
        if wire.drop {
            effects.mark_drop();
        }
        for gap in wire.duplicate_gaps_nanos {
            effects
                .add_duplicate_gap(gap)
                .map_err(|_| BackendNetworkOutputCodecError::Invalid("duplicate gap"))?;
        }
        Ok(effects)
    }
}

fn validate_network_fault_continuation(
    value: &BackendNetworkFaultContinuation,
) -> Result<(), BackendNetworkOutputCodecError> {
    if value.preserved_availability.len() > HARD_BACKEND_NETWORK_CURSOR_PHASES {
        return Err(backend_network_resource(
            "preserved availability",
            0,
            value.preserved_availability.len(),
            HARD_BACKEND_NETWORK_CURSOR_PHASES,
            HARD_BACKEND_NETWORK_CURSOR_PHASES,
        ));
    }
    for entry in &value.preserved_availability {
        entry
            .target
            .validate()
            .map_err(|_| BackendNetworkOutputCodecError::Invalid("preserved target"))?;
    }
    if value
        .preserved_availability
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || value.protocol_expansion_path.len() > crate::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
        || value.generated_response_depth > crate::model::HARD_NETWORK_RESPONSE_DEPTH
        || value.forwarding_mutation_path.len()
            > usize::from(crate::model::HARD_NETWORK_FORWARDING_MUTATION_DEPTH)
        || (value.generated_response_depth == 0) != value.generated_response_cause.is_none()
        || value.forwarding_mutation_path.is_empty() != value.forced_route_destination.is_none()
    {
        return Err(BackendNetworkOutputCodecError::Noncanonical);
    }
    if let Some(node) = &value.forced_route_destination {
        validate_network_checkpoint_name(&node.name, "forced route destination")?;
    }
    if value.cursor.completed_phases.len() > HARD_BACKEND_NETWORK_CURSOR_PHASES {
        return Err(backend_network_resource(
            "completed phases",
            0,
            value.cursor.completed_phases.len(),
            HARD_BACKEND_NETWORK_CURSOR_PHASES,
            HARD_BACKEND_NETWORK_CURSOR_PHASES,
        ));
    }
    for completed in &value.cursor.completed_phases {
        completed
            .target
            .validate()
            .map_err(|_| BackendNetworkOutputCodecError::Invalid("completed target"))?;
    }
    if value
        .cursor
        .completed_phases
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || value.cursor.repeated_phase_effect.is_some() && value.cursor.queue_opportunity.is_none()
        || value.cursor.queue_priority.is_some() && value.cursor.repeated_phase_effect.is_none()
    {
        return Err(BackendNetworkOutputCodecError::Noncanonical);
    }
    let effects = &value.resolved_frame_effects;
    if effects.accounted_contact_services().len() > 256
        || effects.duplicate_gaps_nanos().len() > 256
    {
        return Err(backend_network_resource(
            "resolved frame effects",
            0,
            effects
                .accounted_contact_services()
                .len()
                .max(effects.duplicate_gaps_nanos().len()),
            256,
            256,
        ));
    }
    if effects
        .accounted_contact_services()
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || effects
            .duplicate_gaps_nanos()
            .windows(2)
            .any(|pair| pair[0] > pair[1])
        || !effects.accounted_contact_services().is_empty() && !effects.serialization_is_accounted()
    {
        return Err(BackendNetworkOutputCodecError::Noncanonical);
    }
    Ok(())
}

fn validate_network_checkpoint_name(
    value: &str,
    field: &'static str,
) -> Result<(), BackendNetworkOutputCodecError> {
    if value.is_empty() || value.len() > HARD_BACKEND_NETWORK_ID_BYTES {
        return Err(backend_network_resource(
            field,
            0,
            value.len(),
            HARD_BACKEND_NETWORK_ID_BYTES,
            HARD_BACKEND_NETWORK_ID_BYTES,
        ));
    }
    Ok(())
}

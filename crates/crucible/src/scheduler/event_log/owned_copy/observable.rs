//! Closed observable payload copies with exact field allocation admission.

use super::*;
use crate::model::MarkerId;
use crate::trigger::GuestMeasurementRational;

pub(crate) fn copy_observable(
    source: &ObservableEventPayload,
) -> Result<ObservableEventPayload, EngineError> {
    use ObservableEventPayload as P;
    Ok(match source {
        P::NetworkDelivered { link, payload } => P::NetworkDelivered {
            link: link
                .as_ref()
                .map(|link| {
                    Ok(LinkId {
                        name: copy_string(&link.name)?,
                    })
                })
                .transpose()?,
            payload: copy_vec(payload)?,
        },
        P::ConsoleOutput { node, bytes } => P::ConsoleOutput {
            node: copy_node(node)?,
            bytes: copy_vec(bytes)?,
        },
        P::CoverageBlock {
            execution_icount,
            node,
            guest_pc,
            block_len,
        } => P::CoverageBlock {
            execution_icount: *execution_icount,
            node: copy_node(node)?,
            guest_pc: *guest_pc,
            block_len: *block_len,
        },
        P::CoverageMarker {
            retired_icount,
            node,
            marker,
        } => P::CoverageMarker {
            retired_icount: *retired_icount,
            node: copy_node(node)?,
            marker: MarkerId {
                name: copy_string(&marker.name)?,
            },
        },
        P::AssertionProximity {
            assertion,
            quantifier,
            distance,
            node,
        } => P::AssertionProximity {
            assertion: copy_assertion(assertion)?,
            quantifier: *quantifier,
            distance: *distance,
            node: node.as_ref().map(copy_node).transpose()?,
        },
        P::MemorySample {
            sample_icount,
            node,
            place,
            value,
        } => P::MemorySample {
            sample_icount: *sample_icount,
            node: copy_node(node)?,
            place: copy_place(place)?,
            value: *value,
        },
        P::IoCompletion {
            node,
            kind,
            payload,
        } => P::IoCompletion {
            node: copy_node(node)?,
            kind: *kind,
            payload: copy_vec(payload)?,
        },
        P::NodeState { node, state } => P::NodeState {
            node: copy_node(node)?,
            state: *state,
        },
        P::AssertionStateChanged { name, state } => P::AssertionStateChanged {
            name: copy_assertion(name)?,
            state: *state,
        },
        P::AssertionEvaluated {
            name,
            flavor,
            condition,
            message,
            details,
        } => P::AssertionEvaluated {
            name: copy_assertion(name)?,
            flavor: *flavor,
            condition: *condition,
            message: copy_string(message)?,
            details: copy_details(details)?,
        },
        P::GuestMarker {
            retired_icount,
            node,
            marker,
        } => P::GuestMarker {
            retired_icount: *retired_icount,
            node: copy_node(node)?,
            marker: MarkerId {
                name: copy_string(&marker.name)?,
            },
        },
        P::GuestMeasurement {
            retired_icount,
            node,
            event,
        } => P::GuestMeasurement {
            retired_icount: *retired_icount,
            node: copy_node(node)?,
            event: copy_measurement(event)?,
        },
        P::GuestSemanticMarker {
            retired_icount,
            node,
            marker,
            instance,
            details,
        } => P::GuestSemanticMarker {
            retired_icount: *retired_icount,
            node: copy_node(node)?,
            marker: copy_string(marker)?,
            instance: copy_string(instance)?,
            details: copy_semantic_details(details)?,
        },
        P::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } => P::GuestAssertionMarker {
            retired_icount: *retired_icount,
            node: copy_node(node)?,
            marker: copy_marker(marker)?,
        },
    })
}

fn copy_place(source: &ResolvedMemPlace) -> Result<ResolvedMemPlace, EngineError> {
    Ok(match source {
        ResolvedMemPlace::PhysicalAddress { address, bytes } => ResolvedMemPlace::PhysicalAddress {
            address: *address,
            bytes: *bytes,
        },
        ResolvedMemPlace::VirtualAddress { address, bytes } => ResolvedMemPlace::VirtualAddress {
            address: *address,
            bytes: *bytes,
        },
        ResolvedMemPlace::Register { name, bytes } => ResolvedMemPlace::Register {
            name: copy_string(name)?,
            bytes: *bytes,
        },
    })
}

fn copy_details(source: &[GuestAssertionDetail]) -> Result<Vec<GuestAssertionDetail>, EngineError> {
    let mut result = reserve_array(source.len())?;
    for detail in source {
        result.push(GuestAssertionDetail {
            key: copy_string(&detail.key)?,
            value: copy_string(&detail.value)?,
        });
    }
    Ok(result)
}

fn copy_semantic_details(
    source: &[GuestSemanticMarkerDetail],
) -> Result<Vec<GuestSemanticMarkerDetail>, EngineError> {
    let mut result = reserve_array(source.len())?;
    for detail in source {
        result.push(GuestSemanticMarkerDetail {
            key: copy_string(&detail.key)?,
            value: copy_value(&detail.value)?,
        });
    }
    Ok(result)
}

fn copy_marker(source: &GuestAssertionMarker) -> Result<GuestAssertionMarker, EngineError> {
    Ok(GuestAssertionMarker {
        id: copy_assertion(&source.id)?,
        message: copy_string(&source.message)?,
        kind: source.kind,
        condition: source.condition,
        must_hit: source.must_hit,
        details: copy_details(&source.details)?,
        location: copy_string(&source.location)?,
    })
}

fn copy_value(source: &GuestMeasurementValue) -> Result<GuestMeasurementValue, EngineError> {
    use GuestMeasurementValue as V;
    Ok(match source {
        V::Signed(value) => V::Signed(*value),
        V::Unsigned(value) => V::Unsigned(*value),
        V::Rational(value) => V::Rational(GuestMeasurementRational {
            negative: value.negative,
            numerator: value.numerator,
            denominator: value.denominator,
        }),
        V::Boolean(value) => V::Boolean(*value),
        V::Enumerated(value) => V::Enumerated(copy_string(value)?),
        V::SignedVector(value) => V::SignedVector(copy_vec(value)?),
        V::UnsignedVector(value) => V::UnsignedVector(copy_vec(value)?),
    })
}

fn copy_measurement(source: &GuestMeasurementEvent) -> Result<GuestMeasurementEvent, EngineError> {
    use GuestMeasurementEvent as M;
    Ok(match source {
        M::Begin {
            measurement,
            instance,
        } => M::Begin {
            measurement: copy_string(measurement)?,
            instance: copy_string(instance)?,
        },
        M::End {
            measurement,
            instance,
        } => M::End {
            measurement: copy_string(measurement)?,
            instance: copy_string(instance)?,
        },
        M::Sample {
            measurement,
            instance,
            metric,
            value,
        } => M::Sample {
            measurement: copy_string(measurement)?,
            instance: copy_string(instance)?,
            metric: copy_string(metric)?,
            value: copy_value(value)?,
        },
    })
}

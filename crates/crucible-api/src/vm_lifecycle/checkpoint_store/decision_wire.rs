//! Allocation-bounded wire ownership for scheduler decisions in checkpoints.

use super::decode::FallibleString;
use crucible::{
    AppRandomDecision, ChoiceTag, Decision, DeliveryOrderDecision, EventKey, OverrideDecision,
    PreemptionDecision, PreemptionKind, RngDecision, RngStreamId, SchedulerNodeId,
    SchedulingNodeKind, SchedulingPoint,
};

/// Wire-compatible decision shape with fallible text and sequence ownership.
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) enum DecisionWire {
    /// A deterministic or recorded ordering of events at one virtual time.
    DeliveryOrder(DeliveryOrderDecisionWire),
    /// A raw draw from a named deterministic decision stream.
    RngDraw(RngDecisionWire),
    /// A search or fuzzing override at a scheduling point.
    Override(OverrideDecisionWire),
    /// A vCPU switch or interrupt-preemption decision.
    Preemption(PreemptionDecisionWire),
    /// A served application-requested random value.
    AppRandom(AppRandomDecisionWire),
}

#[derive(serde::Serialize, serde::Deserialize)]
/// Wire-owned delivery-order decision.
pub(super) struct DeliveryOrderDecisionWire {
    at: crucible::VirtualTime,
    #[serde(deserialize_with = "super::decode::deserialize_vec")]
    order: Vec<EventKeyWire>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EventKeyWire {
    virtual_time: crucible::VirtualTime,
    consumer: SchedulerNodeIdWire,
    producer: SchedulerNodeIdWire,
    sequence: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SchedulerNodeIdWire {
    node: NodeIdWire,
    kind: SchedulingNodeKind,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct NodeIdWire {
    name: FallibleString,
}

#[derive(serde::Serialize, serde::Deserialize)]
/// Wire-owned deterministic RNG decision.
pub(super) struct RngDecisionWire {
    stream: RngStreamIdWire,
    value: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RngStreamIdWire {
    domain: FallibleString,
    name: FallibleString,
}

#[derive(serde::Serialize, serde::Deserialize)]
/// Wire-owned search override decision.
pub(super) struct OverrideDecisionWire {
    point: SchedulingPointWire,
    choice: ChoiceTagWire,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SchedulingPointWire {
    key: FallibleString,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ChoiceTagWire {
    name: FallibleString,
}

#[derive(serde::Serialize, serde::Deserialize)]
/// Wire-owned vCPU preemption decision.
pub(super) struct PreemptionDecisionWire {
    node: NodeIdWire,
    at: crucible::Icount,
    kind: PreemptionKind,
}

#[derive(serde::Serialize, serde::Deserialize)]
/// Wire-owned application RNG decision.
pub(super) struct AppRandomDecisionWire {
    node: NodeIdWire,
    stream: RngStreamIdWire,
    request_id: u64,
    width: u8,
    value: u64,
}

impl From<&Decision> for DecisionWire {
    fn from(decision: &Decision) -> Self {
        match decision {
            Decision::DeliveryOrder(decision) => Self::DeliveryOrder(DeliveryOrderDecisionWire {
                at: decision.at,
                order: decision.order.iter().map(EventKeyWire::from).collect(),
            }),
            Decision::RngDraw(decision) => Self::RngDraw(RngDecisionWire {
                stream: RngStreamIdWire::from(&decision.stream),
                value: decision.value,
            }),
            Decision::Override(decision) => Self::Override(OverrideDecisionWire {
                point: SchedulingPointWire {
                    key: FallibleString::new(decision.point.key.clone()),
                },
                choice: ChoiceTagWire {
                    name: FallibleString::new(decision.choice.name.clone()),
                },
            }),
            Decision::Preemption(decision) => Self::Preemption(PreemptionDecisionWire {
                node: NodeIdWire::from(&decision.node),
                at: decision.at,
                kind: decision.kind.clone(),
            }),
            Decision::AppRandom(decision) => Self::AppRandom(AppRandomDecisionWire {
                node: NodeIdWire::from(&decision.node),
                stream: RngStreamIdWire::from(&decision.stream),
                request_id: decision.request_id,
                width: decision.width,
                value: decision.value,
            }),
        }
    }
}

impl DecisionWire {
    /// Transfers the decoded wire ownership into the scheduler model.
    pub(super) fn into_decision(self) -> Decision {
        match self {
            Self::DeliveryOrder(decision) => Decision::DeliveryOrder(DeliveryOrderDecision {
                at: decision.at,
                order: decision
                    .order
                    .into_iter()
                    .map(EventKeyWire::into_event_key)
                    .collect(),
            }),
            Self::RngDraw(decision) => Decision::RngDraw(RngDecision {
                stream: decision.stream.into_stream_id(),
                value: decision.value,
            }),
            Self::Override(decision) => Decision::Override(OverrideDecision {
                point: SchedulingPoint {
                    key: decision.point.key.into_string(),
                },
                choice: ChoiceTag {
                    name: decision.choice.name.into_string(),
                },
            }),
            Self::Preemption(decision) => Decision::Preemption(PreemptionDecision {
                node: decision.node.into_node_id(),
                at: decision.at,
                kind: decision.kind,
            }),
            Self::AppRandom(decision) => Decision::AppRandom(AppRandomDecision {
                node: decision.node.into_node_id(),
                stream: decision.stream.into_stream_id(),
                request_id: decision.request_id,
                width: decision.width,
                value: decision.value,
            }),
        }
    }
}

impl From<&EventKey> for EventKeyWire {
    fn from(event: &EventKey) -> Self {
        Self {
            virtual_time: event.virtual_time,
            consumer: SchedulerNodeIdWire::from(&event.consumer),
            producer: SchedulerNodeIdWire::from(&event.producer),
            sequence: event.sequence,
        }
    }
}

impl EventKeyWire {
    fn into_event_key(self) -> EventKey {
        EventKey {
            virtual_time: self.virtual_time,
            consumer: self.consumer.into_scheduler_node_id(),
            producer: self.producer.into_scheduler_node_id(),
            sequence: self.sequence,
        }
    }
}

impl From<&SchedulerNodeId> for SchedulerNodeIdWire {
    fn from(node: &SchedulerNodeId) -> Self {
        Self {
            node: NodeIdWire::from(&node.node),
            kind: node.kind,
        }
    }
}

impl SchedulerNodeIdWire {
    fn into_scheduler_node_id(self) -> SchedulerNodeId {
        SchedulerNodeId {
            node: self.node.into_node_id(),
            kind: self.kind,
        }
    }
}

impl From<&crucible::NodeId> for NodeIdWire {
    fn from(node: &crucible::NodeId) -> Self {
        Self {
            name: FallibleString::new(node.name.clone()),
        }
    }
}

impl NodeIdWire {
    fn into_node_id(self) -> crucible::NodeId {
        crucible::NodeId {
            name: self.name.into_string(),
        }
    }
}

impl From<&RngStreamId> for RngStreamIdWire {
    fn from(stream: &RngStreamId) -> Self {
        Self {
            domain: FallibleString::new(stream.domain.clone()),
            name: FallibleString::new(stream.name.clone()),
        }
    }
}

impl RngStreamIdWire {
    fn into_stream_id(self) -> RngStreamId {
        RngStreamId {
            domain: self.domain.into_string(),
            name: self.name.into_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::{Icount, IrqVector, VcpuId, VirtualTime};

    #[derive(serde::Serialize, serde::Deserialize)]
    struct DecisionVector(
        #[serde(deserialize_with = "super::super::decode::deserialize_vec")] Vec<DecisionWire>,
    );

    #[test]
    fn fallible_decision_wire_preserves_canonical_bytes_and_nested_text() {
        let node = crucible::NodeId {
            name: String::from("node-a"),
        };
        let scheduler_node = SchedulerNodeId {
            node: node.clone(),
            kind: SchedulingNodeKind::Vm,
        };
        let decisions = vec![
            Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: 3 },
                order: vec![EventKey::new(
                    VirtualTime { ticks: 3 },
                    scheduler_node.clone(),
                    scheduler_node,
                    5,
                )],
            }),
            Decision::RngDraw(RngDecision {
                stream: RngStreamId::new("domain", "x".repeat(5_000)),
                value: 7,
            }),
            Decision::Override(OverrideDecision {
                point: SchedulingPoint {
                    key: String::from("point"),
                },
                choice: ChoiceTag {
                    name: String::from("choice"),
                },
            }),
            Decision::Preemption(PreemptionDecision {
                node: node.clone(),
                at: Icount { retired: 11 },
                kind: PreemptionKind::InterruptAt {
                    target_vcpu: VcpuId { index: 1 },
                    irq: IrqVector { vector: 32 },
                },
            }),
            Decision::AppRandom(AppRandomDecision {
                node,
                stream: RngStreamId::new("app", "stream"),
                request_id: 13,
                width: 32,
                value: 17,
            }),
        ];
        let wire = DecisionVector(decisions.iter().map(DecisionWire::from).collect());
        let mut model_bytes = Vec::new();
        ciborium::ser::into_writer(&decisions, &mut model_bytes)
            .unwrap_or_else(|error| panic!("encode model decisions: {error}"));
        let mut wire_bytes = Vec::new();
        ciborium::ser::into_writer(&wire, &mut wire_bytes)
            .unwrap_or_else(|error| panic!("encode fallible decision wire: {error}"));
        assert_eq!(wire_bytes, model_bytes);

        let limits = crucible::model::FaultResourceLimits {
            fat_checkpoint_bytes: 65_536,
            ..crucible::model::FaultResourceLimits::default()
        };
        let decoded: DecisionVector = super::super::decode::decode_cbor_with_limits(
            &wire_bytes,
            limits,
            "decode decision wire",
        )
        .unwrap_or_else(|error| panic!("decode fallible decision wire: {error}"));
        let decoded = decoded
            .0
            .into_iter()
            .map(DecisionWire::into_decision)
            .collect::<Vec<_>>();
        assert_eq!(decoded, decisions);
    }
}

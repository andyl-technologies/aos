//! SPDX-License-Identifier: Apache-2.0
//! Executes engine test APIs using portable, bounded test-oracle projections.
//!
//! State belongs to one inherited socket connection. Requests carry parameters
//! rather than fixture identities; every result comes from the actual engine.

use std::error::Error;
use std::io;

use crucible_determinism::DecisionStream;
use crucible_engine::{
    AdvanceOutcome, EventLog, EventSource, ExecutionHorizon, Icount, MarkerId, NodeId,
    ObservableEvent, RngStreamId, SchedulerError, SchedulerEventLogClass, SchedulerEventLogEntry,
    SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer, Seed, SimDouble,
    SimDoubleConfig, SimDoubleHostScheduleEvent, SimInstructionScript, SimInstructionStep,
    SimOutboundFrame, event_log_causal_projection, observable_event_from_whitebox_marker_payload,
};
use crucible_qemu_protocol::{WhiteboxDoorbellFrame, decode_whitebox_marker_payload};
use serde_json::{Value, json};

use super::invalid;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Default)]
pub(super) struct EngineOracle {
    rng: Option<DecisionStream>,
    log: EventLog,
    entries: Vec<SchedulerEventLogEntry>,
    double: Option<SimDouble>,
}

impl EngineOracle {
    pub(super) fn dispatch(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let request: Value = serde_json::from_slice(bytes)?;
        let operation = string(&request, "operation")?;
        let response = match operation {
            "rng-init" => {
                fields(&request, &["operation", "seed", "stream"])?;
                let seed = Seed::from_u64(number(&request, "seed")?);
                let stream = RngStreamId::from_name(string(&request, "stream")?);
                self.rng = Some(
                    seed.decision_rng()
                        .fork_in_domain(&stream.domain, &stream.name),
                );
                json!({"root_seed": seed.decision_rng_root_seed()})
            }
            "rng-next" => {
                fields(&request, &["operation", "advance"])?;
                let advance = number(&request, "advance")?;
                if advance > 1_000_000 {
                    return Err(invalid("RNG advance exceeds the test-oracle work bound").into());
                }
                let rng = self
                    .rng
                    .as_mut()
                    .ok_or_else(|| invalid("RNG is not initialized"))?;
                rng.advance_by(advance);
                json!({"draw": rng.next_u64()})
            }
            "marker" | "diagnostic" => self.append_marker(&request, operation)?,
            "sim-create" => {
                fields(
                    &request,
                    &["operation", "slot", "nodes", "capacity", "steps"],
                )?;
                let steps = request["steps"]
                    .as_array()
                    .ok_or_else(|| invalid("steps must be an array"))?;
                let mut script = Vec::new();
                for step in steps {
                    fields(step, &["budget", "frames"])?;
                    let frames = step["frames"]
                        .as_array()
                        .ok_or_else(|| invalid("frames must be an array"))?;
                    let mut outbound_frames = Vec::new();
                    for frame in frames {
                        fields(frame, &["destination", "icount", "payload"])?;
                        outbound_frames.push(SimOutboundFrame {
                            dst_slot: number32(frame, "destination")?,
                            delivery_icount: number(frame, "icount")?,
                            payload: bytes_field(frame, "payload")?,
                        });
                    }
                    script.push(SimInstructionStep {
                        instruction_budget: number(step, "budget")?,
                        outbound_frames,
                    });
                }
                let config = SimDoubleConfig {
                    slot_index: number32(&request, "slot")?,
                    vm_node_count: number32(&request, "nodes")?,
                    queue_capacity: number32(&request, "capacity")?,
                    script: SimInstructionScript::new(script),
                };
                // Avoid unbounded allocations from a small configuration frame.
                if config.vm_node_count > 16 || config.queue_capacity > 4096 {
                    return Err(invalid("simulation geometry exceeds the test-oracle bound").into());
                }
                let double = SimDouble::new(config)?;
                let layout = double.shmem_layout();
                let response =
                    json!({"node_count": layout.node_count, "region_size": layout.region_size});
                self.double = Some(double);
                response
            }
            "sim-control" => {
                fields(&request, &["operation", "frame"])?;
                let frame = bytes_field(&request, "frame")?;
                json!({"reply": self.double()?.accept_host_control_frame(&frame)?})
            }
            "sim-inbound" => {
                fields(
                    &request,
                    &["operation", "source", "sequence", "icount", "payload"],
                )?;
                self.double()?.enqueue_inbound_frame_with_sequence(
                    number32(&request, "source")?,
                    number32(&request, "sequence")?,
                    number(&request, "icount")?,
                    &bytes_field(&request, "payload")?,
                )?;
                json!({})
            }
            "sim-advance" => {
                fields(
                    &request,
                    &["operation", "horizon", "authorization", "topology_epoch"],
                )?;
                if string(&request, "authorization")? != "allow-all" {
                    return Err(invalid("unknown simulation send-authorization policy").into());
                }
                let authorization = AllowSends {
                    topology_epoch: number(&request, "topology_epoch")?,
                };
                let horizon = ExecutionHorizon {
                    icount: Icount {
                        retired: number(&request, "horizon")?,
                    },
                };
                outcome(
                    self.double()?
                        .advance_scripted_quantum(horizon, &authorization)?,
                )
            }
            "sim-schedule" => {
                fields(&request, &["operation"])?;
                let schedule = self.double()?.host_observable_schedule();
                let events: Vec<Value> =
                    schedule.iter().map(schedule_event).collect::<Result<_>>()?;
                json!({"events": events})
            }
            _ => return Err(invalid("unknown engine test-oracle operation").into()),
        };
        Ok(serde_json::to_vec(&response)?)
    }

    fn double(&mut self) -> Result<&mut SimDouble> {
        self.double
            .as_mut()
            .ok_or_else(|| invalid("simulation is not initialized").into())
    }

    fn append_marker(&mut self, request: &Value, operation: &str) -> Result<Value> {
        let node = NodeId {
            name: string(request, "node")?.to_owned(),
        };
        let icount = Icount {
            retired: number(request, "icount")?,
        };
        let event = if operation == "marker" {
            fields(request, &["operation", "node", "icount", "frame"])?;
            let frame =
                WhiteboxDoorbellFrame::decode_bounded(&bytes_field(request, "frame")?, 65_536)?;
            let marker = decode_whitebox_marker_payload(&frame)?;
            observable_event_from_whitebox_marker_payload(icount, node, &marker)
                .ok_or_else(|| invalid("marker is not observational"))?
        } else {
            fields(request, &["operation", "node", "icount", "marker"])?;
            ObservableEvent::guest_marker(
                icount,
                node,
                MarkerId::from_name(string(request, "marker")?),
            )
        };
        let sequence = self.log.next_sequence(0).map_err(engine_error)?;
        let entry =
            crucible_engine::test_support::condition_observation_entry_for_test(sequence, &event);
        let appended = self.log.append_entries(vec![entry]).map_err(engine_error)?;
        let mut projections = Vec::new();
        for entry in &appended.entries {
            let stamp = &entry.time().stamp;
            let source = match entry.source() {
                EventSource::Guest { node } => json!({"kind": "guest", "node": node.name}),
                _ => return Err(invalid("marker append returned a non-guest source").into()),
            };
            projections.push(json!({
                "class": match entry.class() {
                    SchedulerEventLogClass::Causal => "causal",
                    SchedulerEventLogClass::Observational => "observational",
                },
                "stamp": {"node": stamp.node.as_ref().map(|node| &node.name),
                          "tick": stamp.tick.ticks, "retired": stamp.retired.map(|count| count.retired)},
                "source": source,
                "payload": {"kind": entry.event_payload().kind(),
                            "assertion": entry.event_payload().string("assertion")},
            }));
        }
        self.entries.extend(appended.entries);
        Ok(json!({"entries": projections,
                  "causal_projection_empty": event_log_causal_projection(&self.entries).is_empty()}))
    }
}

struct AllowSends {
    topology_epoch: u64,
}

impl SchedulerSendAuthorizer for AllowSends {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> std::result::Result<SchedulerSendAuthorization, SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: self.topology_epoch,
        })
    }
}

fn outcome(value: AdvanceOutcome) -> Value {
    match value {
        AdvanceOutcome::ReachedHorizon => json!({"kind": "reached-horizon"}),
        AdvanceOutcome::Paused { at } => json!({"kind": "paused", "at": at.retired}),
    }
}

fn schedule_event(event: &SimDoubleHostScheduleEvent) -> Result<Value> {
    Ok(match event {
        SimDoubleHostScheduleEvent::HorizonAdvance {
            from_icount,
            requested_icount,
            reached_icount,
            outcome: result,
        } => json!({"kind": "horizon", "from": from_icount, "requested": requested_icount,
                   "reached": reached_icount, "outcome": outcome(*result)}),
        SimDoubleHostScheduleEvent::FrameDelivery {
            src_slot,
            sequence,
            delivery_icount,
            payload,
        } => json!({"kind": "delivery", "source": src_slot, "sequence": sequence,
                   "icount": delivery_icount, "payload": payload}),
        SimDoubleHostScheduleEvent::FrameEmission {
            dst_slot,
            sequence,
            delivery_icount,
            payload,
        } => json!({"kind": "emission", "destination": dst_slot, "sequence": sequence,
                   "icount": delivery_icount, "payload": payload}),
        // The v2 projection registry deliberately admits these three variants.
        // A new engine variant must get an explicit portable protocol schema.
        _ => return Err(invalid("schedule event has no v2 test-oracle projection").into()),
    })
}

fn fields(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("expected a JSON object"))?;
    if object.len() != expected.len() || expected.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid("unknown or missing test-oracle fields").into());
    }
    Ok(())
}

fn number(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| invalid("expected an unsigned integer").into())
}

fn number32(value: &Value, field: &str) -> Result<u32> {
    Ok(u32::try_from(number(value, field)?)?)
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| invalid("expected a UTF-8 string").into())
}

fn bytes_field(value: &Value, field: &str) -> Result<Vec<u8>> {
    let values = value[field]
        .as_array()
        .ok_or_else(|| invalid("expected an array of bytes"))?;
    values
        .iter()
        .map(|value| {
            let number = value
                .as_u64()
                .ok_or_else(|| invalid("expected an unsigned byte"))?;
            Ok(u8::try_from(number)?)
        })
        .collect()
}

fn engine_error(error: impl std::fmt::Debug) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}"))
}

//! Checks `gate:layer1-injection` with a two-node injection double.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use crucible_shmem::{
    FrameDeliveryKey, FrameEntry, authorize_advance_ceiling, deliverable_frames_at,
    validate_frame_delivery_is_future,
};

const NODE_A: u32 = 10;
const NODE_B: u32 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostInterleaving {
    ProducerSkewed,
    ConsumerSkewed,
}

#[derive(Clone, Debug)]
struct ScheduledInput {
    receiver_node: u32,
    frame: FrameEntry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ObservedInjection {
    receiver_node: u32,
    observed_icount: u64,
    key: FrameDeliveryKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostStep {
    Enqueue {
        input_index: usize,
        producer_host_tick: u64,
    },
    Observe {
        node: u32,
        delivery_icount: u64,
    },
}

#[test]
fn gate_layer1_injection_run_twice_observed_vectors_match() {
    let producer_skewed = run_two_vm_injection(HostInterleaving::ProducerSkewed);
    let consumer_skewed = run_two_vm_injection(HostInterleaving::ConsumerSkewed);

    assert_eq!(producer_skewed, consumer_skewed);
    assert_eq!(producer_skewed, expected_observed_vector());
    assert_ne!(
        producer_host_timing_vector(HostInterleaving::ProducerSkewed),
        producer_host_timing_vector(HostInterleaving::ConsumerSkewed)
    );
}

#[test]
fn gate_layer1_injection_rejects_host_timing_negative_control() {
    let producer_skewed = host_timing_observed_vector(HostInterleaving::ProducerSkewed);
    let consumer_skewed = host_timing_observed_vector(HostInterleaving::ConsumerSkewed);

    assert_ne!(producer_skewed, consumer_skewed);
}

fn run_two_vm_injection(interleaving: HostInterleaving) -> Vec<ObservedInjection> {
    let inputs = scenario_inputs();
    let mut inbound = BTreeMap::<u32, Vec<FrameEntry>>::new();
    let mut current_icounts = BTreeMap::from([(NODE_A, 0_u64), (NODE_B, 0_u64)]);
    let mut delivered = BTreeSet::<(u32, FrameDeliveryKey)>::new();
    let mut observed = Vec::new();

    for step in host_script(interleaving) {
        match step {
            HostStep::Enqueue {
                input_index,
                producer_host_tick,
            } => {
                assert!(producer_host_tick > 0);
                let input = &inputs[input_index];
                let current_icount = current_icount(input.receiver_node, &current_icounts);
                validate_frame_delivery_is_future(&input.frame, current_icount).unwrap_or_else(
                    |error| panic!("scheduled input must be in the consumer future: {error}"),
                );
                inbound
                    .entry(input.receiver_node)
                    .or_default()
                    .push(input.frame.clone());
            }
            HostStep::Observe {
                node,
                delivery_icount,
            } => {
                let current_icount = current_icount(node, &current_icounts);
                authorize_advance_ceiling(current_icount, delivery_icount, None).unwrap_or_else(
                    |error| panic!("advance to an observed delivery must be authorized: {error}"),
                );
                current_icounts.insert(node, delivery_icount);

                let frames = match inbound.get(&node) {
                    Some(frames) => frames,
                    None => continue,
                };

                for frame in deliverable_frames_at(frames, delivery_icount) {
                    let key = frame.delivery_key();
                    if !delivered.insert((node, key)) {
                        continue;
                    }
                    assert_eq!(frame.delivery_icount, delivery_icount);
                    observed.push(ObservedInjection {
                        receiver_node: node,
                        observed_icount: delivery_icount,
                        key,
                    });
                }
            }
        }
    }

    observed
}

fn host_timing_observed_vector(interleaving: HostInterleaving) -> Vec<ObservedInjection> {
    let inputs = scenario_inputs();

    host_script(interleaving)
        .into_iter()
        .filter_map(|step| {
            let HostStep::Enqueue {
                input_index,
                producer_host_tick,
            } = step
            else {
                return None;
            };
            let input = &inputs[input_index];
            Some(ObservedInjection {
                receiver_node: input.receiver_node,
                observed_icount: producer_host_tick,
                key: input.frame.delivery_key(),
            })
        })
        .collect()
}

fn producer_host_timing_vector(interleaving: HostInterleaving) -> Vec<u64> {
    host_script(interleaving)
        .into_iter()
        .filter_map(|step| match step {
            HostStep::Enqueue {
                producer_host_tick, ..
            } => Some(producer_host_tick),
            HostStep::Observe { .. } => None,
        })
        .collect()
}

fn scenario_inputs() -> Vec<ScheduledInput> {
    vec![
        input(NODE_B, 10, NODE_A, 0, b"a-to-b-0"),
        input(NODE_A, 12, NODE_B, 0, b"b-to-a-0"),
        input(NODE_B, 14, NODE_A, 1, b"a-to-b-1"),
        input(NODE_B, 14, NODE_B, 1, b"b-loopback-1"),
        input(NODE_A, 18, NODE_B, 2, b"b-to-a-2"),
    ]
}

fn host_script(interleaving: HostInterleaving) -> Vec<HostStep> {
    match interleaving {
        HostInterleaving::ProducerSkewed => vec![
            HostStep::Enqueue {
                input_index: 3,
                producer_host_tick: 900,
            },
            HostStep::Enqueue {
                input_index: 1,
                producer_host_tick: 120,
            },
            HostStep::Enqueue {
                input_index: 4,
                producer_host_tick: 850,
            },
            HostStep::Enqueue {
                input_index: 0,
                producer_host_tick: 40,
            },
            HostStep::Enqueue {
                input_index: 2,
                producer_host_tick: 610,
            },
            HostStep::Observe {
                node: NODE_B,
                delivery_icount: 10,
            },
            HostStep::Observe {
                node: NODE_A,
                delivery_icount: 12,
            },
            HostStep::Observe {
                node: NODE_B,
                delivery_icount: 14,
            },
            HostStep::Observe {
                node: NODE_A,
                delivery_icount: 18,
            },
        ],
        HostInterleaving::ConsumerSkewed => vec![
            HostStep::Enqueue {
                input_index: 0,
                producer_host_tick: 700,
            },
            HostStep::Observe {
                node: NODE_B,
                delivery_icount: 10,
            },
            HostStep::Enqueue {
                input_index: 1,
                producer_host_tick: 930,
            },
            HostStep::Observe {
                node: NODE_A,
                delivery_icount: 12,
            },
            HostStep::Enqueue {
                input_index: 3,
                producer_host_tick: 300,
            },
            HostStep::Enqueue {
                input_index: 2,
                producer_host_tick: 990,
            },
            HostStep::Observe {
                node: NODE_B,
                delivery_icount: 14,
            },
            HostStep::Enqueue {
                input_index: 4,
                producer_host_tick: 420,
            },
            HostStep::Observe {
                node: NODE_A,
                delivery_icount: 18,
            },
        ],
    }
}

fn expected_observed_vector() -> Vec<ObservedInjection> {
    vec![
        observed(NODE_B, 10, NODE_A, 0),
        observed(NODE_A, 12, NODE_B, 0),
        observed(NODE_B, 14, NODE_A, 1),
        observed(NODE_B, 14, NODE_B, 1),
        observed(NODE_A, 18, NODE_B, 2),
    ]
}

fn input(
    receiver_node: u32,
    delivery_icount: u64,
    src_node: u32,
    seq: u32,
    payload: &[u8],
) -> ScheduledInput {
    let frame = FrameEntry::new(delivery_icount, src_node, seq, payload)
        .unwrap_or_else(|error| panic!("frame entry should be valid: {error}"));
    ScheduledInput {
        receiver_node,
        frame,
    }
}

fn observed(
    receiver_node: u32,
    observed_icount: u64,
    src_node: u32,
    seq: u32,
) -> ObservedInjection {
    ObservedInjection {
        receiver_node,
        observed_icount,
        key: FrameDeliveryKey {
            delivery_icount: observed_icount,
            src_node,
            seq,
        },
    }
}

fn current_icount(node: u32, current_icounts: &BTreeMap<u32, u64>) -> u64 {
    match current_icounts.get(&node) {
        Some(current_icount) => *current_icount,
        None => panic!("node {node} is not part of the two-node injection scenario"),
    }
}

//! Checks T-FAULT-16 in-process fault test-double coverage.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    BlockFault, CombinedFaults, Decision, DeviceDelivery, DeviceId, DeviceSchedulingSubNode, Fault,
    FaultBandwidthBitsPerSecond, FaultDecision, FaultDuration, FaultRateBasisPoints, IoFailureMode,
    NetworkCorruptionFault, NetworkFault, NetworkLinkDirection, NinePErrno, NinePFault, NodeId,
    PartitionDirection, SchedulerNodeId, SchedulingNodeKind, Seed,
    link_faults_from_combined_network,
};
use crucible_device::ninep::codec;
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, BlockResponse, BlockStatus, DeliveryLog,
    DeliveryRecord, DivergedField, Divergence, Frame, FrameDraws, FsTree, IoCore, IoFaults,
    LinkFaults, LinkRequest, NetLink, NetLinkHarness, NinepDevice, NinepLatency, Node,
    PastDeliveryPolicy, ResponseStatus, Script, localize_divergence, run_script, run_twice,
};

const LINK_A: &str = "link-a";
const LINK_B: &str = "link-b";
const LINK_SEED: u64 = 0x16;
const LINK_REORDER_REQUESTS: usize = 16;
const BLOCK_REORDER_REQUESTS: u32 = 16;
const NINEP_REORDER_REQUESTS: u16 = 16;

const NO_FAULT_FIRES: [ExpectedFaultDecision; 3] = [
    ExpectedFaultDecision {
        kind: "loss",
        fired: false,
    },
    ExpectedFaultDecision {
        kind: "duplicate",
        fired: false,
    },
    ExpectedFaultDecision {
        kind: "corrupt",
        fired: false,
    },
];
const LOSS_FIRES: [ExpectedFaultDecision; 3] = [
    ExpectedFaultDecision {
        kind: "loss",
        fired: true,
    },
    ExpectedFaultDecision {
        kind: "duplicate",
        fired: false,
    },
    ExpectedFaultDecision {
        kind: "corrupt",
        fired: false,
    },
];
const DUPLICATE_FIRES: [ExpectedFaultDecision; 3] = [
    ExpectedFaultDecision {
        kind: "loss",
        fired: false,
    },
    ExpectedFaultDecision {
        kind: "duplicate",
        fired: true,
    },
    ExpectedFaultDecision {
        kind: "corrupt",
        fired: false,
    },
];
const CORRUPT_FIRES: [ExpectedFaultDecision; 3] = [
    ExpectedFaultDecision {
        kind: "loss",
        fired: false,
    },
    ExpectedFaultDecision {
        kind: "duplicate",
        fired: false,
    },
    ExpectedFaultDecision {
        kind: "corrupt",
        fired: true,
    },
];

#[derive(Clone, Debug)]
struct LinkFaultCase {
    name: &'static str,
    taxonomy_key: &'static str,
    faults: LinkFaults,
    frames: Vec<LinkFrameSpec>,
    expected: ExpectedLog,
    expected_divergence: Option<ExpectedDivergence>,
    expected_decisions: &'static [ExpectedFaultDecision; 3],
}

#[derive(Clone, Debug)]
struct IoFaultCase {
    name: &'static str,
    taxonomy_key: &'static str,
    table: IoFaults,
    expected: ExpectedIoEffect,
    expected_divergence: Option<ExpectedDivergence>,
    expected_decisions: &'static [ExpectedFaultDecision; 3],
}

#[derive(Clone, Copy, Debug)]
struct ExpectedFaultDecision {
    kind: &'static str,
    fired: bool,
}

#[derive(Clone, Copy, Debug)]
struct LinkFrameSpec {
    emit_icount: u64,
    frame_id: u32,
}

#[derive(Clone, Debug)]
enum ExpectedLog {
    Empty,
    One {
        delivery_icount: u64,
        payload: Vec<u8>,
    },
    Corrupted {
        delivery_icount: u64,
        mode: ExpectedCorruption,
    },
    Duplicate {
        primary_icount: u64,
        duplicate_icount: u64,
        payload: Vec<u8>,
    },
    Reordered {
        expected_len: usize,
    },
}

#[derive(Clone, Debug)]
enum ExpectedCorruption {
    BitFlip,
    FieldMutation,
    Truncation { max_removed: usize },
}

#[derive(Clone, Debug)]
enum ExpectedIoEffect {
    DeliveryDelayed,
    ErrorStatus,
    Dropped,
    Reordered,
    Duplicated,
    Corrupted,
    BandwidthDelayed,
}

#[derive(Clone, Copy, Debug)]
struct ExpectedDivergence {
    record_index: usize,
    field: ExpectedDivergedField,
}

#[derive(Clone, Copy, Debug)]
enum ExpectedDivergedField {
    Missing { left_missing: bool },
    DeliveryIcount,
    CorrelationId,
    Status,
    PayloadLen,
    PayloadByte,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IoRun {
    log: DeliveryLog,
    decisions: Vec<Decision>,
    decision_batches: Vec<Vec<Decision>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinkRun {
    log: DeliveryLog,
    decisions: Vec<Decision>,
}

#[test]
fn fault_test_double_exercises_each_network_fault_kind() {
    for case in link_fault_cases() {
        let script = seeded_link_script(&case);
        let comparison =
            run_twice::<NetLinkHarness, _>(|| link_harness(case.faults.clone()), &script)
                .unwrap_or_else(|error| panic!("{} run-twice should not fail: {error}", case.name));
        assert!(
            comparison.is_identical(),
            "{} ({}) diverged on run-twice: {:?}",
            case.name,
            case.taxonomy_key,
            comparison.divergence()
        );

        let observed =
            run_script::<NetLinkHarness, _>(|| link_harness(case.faults.clone()), &script)
                .unwrap_or_else(|error| {
                    panic!("{} scripted run should not fail: {error}", case.name)
                });
        assert_expected_log(case.name, &observed, &case.expected);

        let recorded = recorded_link_run(&case);
        assert_eq!(
            observed, recorded.log,
            "{} recorded link path must match the same-seed harness path",
            case.name
        );

        let fault_free = run_script::<NetLinkHarness, _>(
            || link_harness(LinkFaults::none()),
            &fault_free_link_script(&case.frames),
        )
        .unwrap_or_else(|error| panic!("{} fault-free run should not fail: {error}", case.name));
        assert_localizes(case.name, &observed, &fault_free, case.expected_divergence);

        assert_rng_draw_sequence(
            case.name,
            &recorded.decisions,
            &device(case.name),
            Seed::from_u64(LINK_SEED),
        );
        assert_exact_fault_decisions(
            case.name,
            &recorded.decisions,
            &device(case.name),
            case.expected_decisions,
        );
    }
}

#[test]
fn fault_test_double_exercises_each_block_fault_kind() {
    for case in block_fault_cases() {
        let first = run_block_case(&case.table, &case.expected);
        let second = run_block_case(&case.table, &case.expected);
        assert_eq!(
            first, second,
            "{} ({}) must be run-twice deterministic",
            case.name, case.taxonomy_key
        );
        let fault_free = run_block_case(&IoFaults::none(), &case.expected);
        assert_block_effect(case.name, &first, &fault_free, &case.expected);

        assert_localizes(
            case.name,
            &first.log,
            &fault_free.log,
            case.expected_divergence,
        );
        assert_io_rng_draw_batches(
            case.name,
            &first.decision_batches,
            &block_device_id(),
            Seed::from_u64(0xb10c16),
            matches!(case.expected, ExpectedIoEffect::Reordered),
        );
        assert_exact_fault_decisions(
            case.name,
            &first.decisions,
            &block_device_id(),
            case.expected_decisions,
        );
    }
}

#[test]
fn fault_test_double_exercises_each_9p_fault_kind() {
    for case in ninep_fault_cases() {
        let first = run_ninep_case(&case.table, &case.expected);
        let second = run_ninep_case(&case.table, &case.expected);
        assert_eq!(
            first, second,
            "{} ({}) must be run-twice deterministic",
            case.name, case.taxonomy_key
        );
        let fault_free = run_ninep_case(&IoFaults::none(), &case.expected);
        assert_ninep_effect(case.name, &first, &fault_free, &case.expected);

        assert_localizes(
            case.name,
            &first.log,
            &fault_free.log,
            case.expected_divergence,
        );
        assert_io_rng_draw_batches(
            case.name,
            &first.decision_batches,
            &ninep_device_id(),
            Seed::from_u64(0x9f516),
            matches!(case.expected, ExpectedIoEffect::Reordered),
        );
        assert_exact_fault_decisions(
            case.name,
            &first.decisions,
            &ninep_device_id(),
            case.expected_decisions,
        );
    }
}

fn link_fault_cases() -> Vec<LinkFaultCase> {
    vec![
        LinkFaultCase {
            name: "network.partition.a-to-b",
            taxonomy_key: "network.partition",
            faults: link_fault_table(Fault::Network(NetworkFault::Partition {
                link: link_id(),
                direction: PartitionDirection::EndpointAToEndpointB,
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::Empty,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::Missing { left_missing: true },
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
        LinkFaultCase {
            name: "network.partition.b-to-a-unaffected",
            taxonomy_key: "network.partition",
            faults: link_fault_table(Fault::Network(NetworkFault::Partition {
                link: link_id(),
                direction: PartitionDirection::EndpointBToEndpointA,
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::One {
                delivery_icount: 10,
                payload: frame_payload(),
            },
            expected_divergence: None,
            expected_decisions: &NO_FAULT_FIRES,
        },
        LinkFaultCase {
            name: "network.partition.bidirectional",
            taxonomy_key: "network.partition",
            faults: link_fault_table(Fault::Network(NetworkFault::Partition {
                link: link_id(),
                direction: PartitionDirection::Bidirectional,
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::Empty,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::Missing { left_missing: true },
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
        LinkFaultCase {
            name: "network.loss",
            taxonomy_key: "network.loss",
            faults: link_fault_table(Fault::Network(NetworkFault::Loss {
                link: link_id(),
                rate: rate(10_000),
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::Empty,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::Missing { left_missing: true },
            }),
            expected_decisions: &LOSS_FIRES,
        },
        LinkFaultCase {
            name: "network.reorder",
            taxonomy_key: "network.reorder",
            faults: link_fault_table(Fault::Network(NetworkFault::Reorder {
                link: link_id(),
                window: FaultDuration::from_nanos(10_000),
            })),
            frames: reorder_link_frames(),
            expected: ExpectedLog::Reordered {
                expected_len: LINK_REORDER_REQUESTS,
            },
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::DeliveryIcount,
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
        LinkFaultCase {
            name: "network.duplicate",
            taxonomy_key: "network.duplicate",
            faults: link_fault_table(Fault::Network(NetworkFault::Duplicate {
                link: link_id(),
                rate: rate(10_000),
                gap: FaultDuration::from_nanos(2),
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::Duplicate {
                primary_icount: 10,
                duplicate_icount: 12,
                payload: frame_payload(),
            },
            expected_divergence: Some(ExpectedDivergence {
                record_index: 1,
                field: ExpectedDivergedField::Missing {
                    left_missing: false,
                },
            }),
            expected_decisions: &DUPLICATE_FIRES,
        },
        LinkFaultCase {
            name: "network.corruption.bit-flip",
            taxonomy_key: "network.corruption.bit-flip",
            faults: link_fault_table(Fault::Network(NetworkFault::Corruption {
                link: link_id(),
                kind: NetworkCorruptionFault::BitFlip {
                    rate: rate(10_000),
                    max_bits: 2,
                },
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::Corrupted {
                delivery_icount: 10,
                mode: ExpectedCorruption::BitFlip,
            },
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::PayloadByte,
            }),
            expected_decisions: &CORRUPT_FIRES,
        },
        LinkFaultCase {
            name: "network.corruption.field-mutation",
            taxonomy_key: "network.corruption.field-mutation",
            faults: link_fault_table(Fault::Network(NetworkFault::Corruption {
                link: link_id(),
                kind: NetworkCorruptionFault::FieldMutation { rate: rate(10_000) },
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::Corrupted {
                delivery_icount: 10,
                mode: ExpectedCorruption::FieldMutation,
            },
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::PayloadByte,
            }),
            expected_decisions: &CORRUPT_FIRES,
        },
        LinkFaultCase {
            name: "network.corruption.truncation",
            taxonomy_key: "network.corruption.truncation",
            faults: link_fault_table(Fault::Network(NetworkFault::Corruption {
                link: link_id(),
                kind: NetworkCorruptionFault::Truncation {
                    rate: rate(10_000),
                    max_bytes: 2,
                },
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::Corrupted {
                delivery_icount: 10,
                mode: ExpectedCorruption::Truncation { max_removed: 2 },
            },
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::PayloadLen,
            }),
            expected_decisions: &CORRUPT_FIRES,
        },
        LinkFaultCase {
            name: "network.bandwidth",
            taxonomy_key: "network.bandwidth",
            faults: link_fault_table(Fault::Network(NetworkFault::Bandwidth {
                link: link_id(),
                limit: bandwidth(1_000),
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::One {
                delivery_icount: 32_000_010,
                payload: frame_payload(),
            },
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::DeliveryIcount,
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
        LinkFaultCase {
            name: "network.latency-bump",
            taxonomy_key: "network.latency-bump",
            faults: link_fault_table(Fault::Network(NetworkFault::LatencyBump {
                link: link_id(),
                extra: FaultDuration::from_nanos(7),
            })),
            frames: single_link_frame(),
            expected: ExpectedLog::One {
                delivery_icount: 17,
                payload: frame_payload(),
            },
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::DeliveryIcount,
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
    ]
}

fn block_fault_cases() -> Vec<IoFaultCase> {
    vec![
        IoFaultCase {
            name: "block.latency",
            taxonomy_key: "block.latency",
            table: block_table(Fault::Block(BlockFault::Latency {
                device: block_device_id(),
                extra: FaultDuration::from_nanos(7),
                jitter: FaultDuration::ZERO,
            })),
            expected: ExpectedIoEffect::DeliveryDelayed,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::DeliveryIcount,
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
        IoFaultCase {
            name: "block.failure.error-status",
            taxonomy_key: "block.failure",
            table: block_table(Fault::Block(BlockFault::Failure {
                device: block_device_id(),
                rate: rate(10_000),
                mode: IoFailureMode::ErrorStatus,
            })),
            expected: ExpectedIoEffect::ErrorStatus,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::Status,
            }),
            expected_decisions: &LOSS_FIRES,
        },
        IoFaultCase {
            name: "block.failure.drop",
            taxonomy_key: "block.failure",
            table: block_table(Fault::Block(BlockFault::Failure {
                device: block_device_id(),
                rate: rate(10_000),
                mode: IoFailureMode::Drop,
            })),
            expected: ExpectedIoEffect::Dropped,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::Missing { left_missing: true },
            }),
            expected_decisions: &LOSS_FIRES,
        },
        IoFaultCase {
            name: "block.reorder",
            taxonomy_key: "block.reorder",
            table: block_table(Fault::Block(BlockFault::Reorder {
                device: block_device_id(),
                window: FaultDuration::from_nanos(10_000),
            })),
            expected: ExpectedIoEffect::Reordered,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::DeliveryIcount,
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
        IoFaultCase {
            name: "block.duplicate",
            taxonomy_key: "block.duplicate",
            table: block_table(Fault::Block(BlockFault::Duplicate {
                device: block_device_id(),
                rate: rate(10_000),
                gap: FaultDuration::from_nanos(11),
            })),
            expected: ExpectedIoEffect::Duplicated,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 1,
                field: ExpectedDivergedField::Missing {
                    left_missing: false,
                },
            }),
            expected_decisions: &DUPLICATE_FIRES,
        },
        IoFaultCase {
            name: "block.corruption.bit-flip",
            taxonomy_key: "block.corruption.bit-flip",
            table: block_table(Fault::Block(BlockFault::Corruption {
                device: block_device_id(),
                rate: rate(10_000),
                bit_flips: 1,
            })),
            expected: ExpectedIoEffect::Corrupted,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::CorrelationId,
            }),
            expected_decisions: &CORRUPT_FIRES,
        },
        IoFaultCase {
            name: "block.bandwidth",
            taxonomy_key: "block.bandwidth",
            table: block_table(Fault::Block(BlockFault::Bandwidth {
                device: block_device_id(),
                limit: bandwidth(1_000),
            })),
            expected: ExpectedIoEffect::BandwidthDelayed,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::DeliveryIcount,
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
    ]
}

fn ninep_fault_cases() -> Vec<IoFaultCase> {
    vec![
        IoFaultCase {
            name: "9p.latency",
            taxonomy_key: "9p.latency",
            table: ninep_table(Fault::NineP(NinePFault::Latency {
                device: ninep_device_id(),
                extra: FaultDuration::from_nanos(7),
                jitter: FaultDuration::ZERO,
            })),
            expected: ExpectedIoEffect::DeliveryDelayed,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::DeliveryIcount,
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
        IoFaultCase {
            name: "9p.failure",
            taxonomy_key: "9p.failure",
            table: ninep_table(Fault::NineP(NinePFault::Failure {
                device: ninep_device_id(),
                rate: rate(10_000),
                errno: errno(13),
            })),
            expected: ExpectedIoEffect::ErrorStatus,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::Status,
            }),
            expected_decisions: &LOSS_FIRES,
        },
        IoFaultCase {
            name: "9p.reorder",
            taxonomy_key: "9p.reorder",
            table: ninep_table(Fault::NineP(NinePFault::Reorder {
                device: ninep_device_id(),
                window: FaultDuration::from_nanos(10_000),
            })),
            expected: ExpectedIoEffect::Reordered,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::DeliveryIcount,
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
        IoFaultCase {
            name: "9p.duplicate",
            taxonomy_key: "9p.duplicate",
            table: ninep_table(Fault::NineP(NinePFault::Duplicate {
                device: ninep_device_id(),
                rate: rate(10_000),
                gap: FaultDuration::from_nanos(13),
            })),
            expected: ExpectedIoEffect::Duplicated,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 1,
                field: ExpectedDivergedField::Missing {
                    left_missing: false,
                },
            }),
            expected_decisions: &DUPLICATE_FIRES,
        },
        IoFaultCase {
            name: "9p.corruption.bit-flip",
            taxonomy_key: "9p.corruption.bit-flip",
            table: ninep_table(Fault::NineP(NinePFault::Corruption {
                device: ninep_device_id(),
                rate: rate(10_000),
                bit_flips: 1,
            })),
            expected: ExpectedIoEffect::Corrupted,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::PayloadByte,
            }),
            expected_decisions: &CORRUPT_FIRES,
        },
        IoFaultCase {
            name: "9p.bandwidth",
            taxonomy_key: "9p.bandwidth",
            table: ninep_table(Fault::NineP(NinePFault::Bandwidth {
                device: ninep_device_id(),
                limit: bandwidth(1_000),
            })),
            expected: ExpectedIoEffect::BandwidthDelayed,
            expected_divergence: Some(ExpectedDivergence {
                record_index: 0,
                field: ExpectedDivergedField::DeliveryIcount,
            }),
            expected_decisions: &NO_FAULT_FIRES,
        },
    ]
}

fn assert_expected_log(name: &str, log: &[DeliveryRecord], expected: &ExpectedLog) {
    match expected {
        ExpectedLog::Empty => {
            assert!(log.is_empty(), "{name} should suppress all deliveries");
        }
        ExpectedLog::One {
            delivery_icount,
            payload,
        } => {
            assert_eq!(log.len(), 1, "{name} should emit one delivery");
            assert_eq!(log[0].delivery_icount, *delivery_icount);
            assert_eq!(&log[0].payload, payload);
        }
        ExpectedLog::Corrupted {
            delivery_icount,
            mode,
        } => {
            assert_eq!(log.len(), 1, "{name} should emit one corrupted delivery");
            assert_eq!(log[0].delivery_icount, *delivery_icount);
            assert_link_corruption(name, &log[0].payload, mode);
        }
        ExpectedLog::Duplicate {
            primary_icount,
            duplicate_icount,
            payload,
        } => {
            assert_eq!(log.len(), 2, "{name} should emit duplicate deliveries");
            assert_eq!(log[0].delivery_icount, *primary_icount);
            assert_eq!(log[1].delivery_icount, *duplicate_icount);
            assert_eq!(&log[0].payload, payload);
            assert_eq!(&log[1].payload, payload);
        }
        ExpectedLog::Reordered { expected_len } => {
            assert_eq!(
                log.len(),
                *expected_len,
                "{name} should emit every reordered frame"
            );
            let ids = correlation_ids(log);
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, (1..=*expected_len as u32).collect::<Vec<_>>());
            assert_ne!(
                ids, sorted,
                "{name} should move at least one frame ahead of an earlier frame"
            );
        }
    }
}

fn assert_link_corruption(name: &str, payload: &[u8], mode: &ExpectedCorruption) {
    let original = frame_payload();
    match mode {
        ExpectedCorruption::BitFlip => {
            assert_eq!(
                payload.len(),
                original.len(),
                "{name} bit-flip corruption should preserve payload length"
            );
            assert_ne!(
                payload,
                original.as_slice(),
                "{name} should flip at least one bit"
            );
        }
        ExpectedCorruption::FieldMutation => {
            assert_eq!(
                payload.len(),
                original.len(),
                "{name} field mutation should preserve payload length"
            );
            let changed = payload
                .iter()
                .zip(original.iter())
                .filter(|(left, right)| **left != **right)
                .count();
            assert_eq!(changed, 1, "{name} should mutate exactly one field byte");
        }
        ExpectedCorruption::Truncation { max_removed } => {
            assert!(
                payload.len() < original.len(),
                "{name} should truncate the payload"
            );
            assert!(
                original.len() - payload.len() <= *max_removed,
                "{name} should respect the truncation bound"
            );
            assert_eq!(
                payload,
                &original[..payload.len()],
                "{name} should preserve the original prefix"
            );
        }
    }
}

fn assert_block_effect(name: &str, run: &IoRun, control: &IoRun, expected: &ExpectedIoEffect) {
    match expected {
        ExpectedIoEffect::DeliveryDelayed => {
            assert_eq!(run.log.len(), 1, "{name} should emit one block response");
            assert!(
                run.log[0].delivery_icount > control.log[0].delivery_icount,
                "{name} should delay the block response"
            );
        }
        ExpectedIoEffect::Reordered => {
            assert_reordered_ids(name, &run.log, &control.log);
        }
        ExpectedIoEffect::BandwidthDelayed => {
            assert_eq!(run.log.len(), 1, "{name} should emit one block response");
            assert!(
                run.log[0].delivery_icount >= control.log[0].delivery_icount + 128_000_000,
                "{name} should include exact bit-rate serialization delay"
            );
        }
        ExpectedIoEffect::ErrorStatus => {
            assert_eq!(run.log.len(), 1, "{name} should emit one block error");
            let response = decode_block_response(&run.log[0].payload);
            assert_eq!(response.status, BlockStatus::Error);
        }
        ExpectedIoEffect::Dropped => {
            assert!(run.log.is_empty(), "{name} should drop the block response");
            assert!(
                !run.decisions.is_empty(),
                "{name} should still record decisions"
            );
        }
        ExpectedIoEffect::Duplicated => {
            assert_eq!(
                run.log.len(),
                2,
                "{name} should emit a duplicate block response"
            );
            assert_eq!(run.log[0].payload, run.log[1].payload);
            assert!(run.log[1].delivery_icount > run.log[0].delivery_icount);
        }
        ExpectedIoEffect::Corrupted => {
            assert_eq!(
                run.log.len(),
                1,
                "{name} should emit one corrupted block response"
            );
            assert_ne!(
                run.log[0].payload, control.log[0].payload,
                "{name} should mutate block response bytes"
            );
        }
    }
}

fn assert_ninep_effect(name: &str, run: &IoRun, control: &IoRun, expected: &ExpectedIoEffect) {
    match expected {
        ExpectedIoEffect::DeliveryDelayed => {
            assert_eq!(run.log.len(), 1, "{name} should emit one 9p reply");
            assert!(
                run.log[0].delivery_icount > control.log[0].delivery_icount,
                "{name} should delay the 9p reply"
            );
        }
        ExpectedIoEffect::Reordered => {
            assert_reordered_ids(name, &run.log, &control.log);
        }
        ExpectedIoEffect::BandwidthDelayed => {
            assert_eq!(run.log.len(), 1, "{name} should emit one 9p reply");
            assert!(
                run.log[0].delivery_icount > control.log[0].delivery_icount,
                "{name} should include a serialization delay"
            );
        }
        ExpectedIoEffect::ErrorStatus => {
            assert_eq!(run.log.len(), 1, "{name} should emit one 9p error reply");
            assert_eq!(reply_type(&run.log[0].payload), codec::RLERROR);
            assert_eq!(rlerror_code(&run.log[0].payload), 13);
        }
        ExpectedIoEffect::Dropped => {
            panic!("9p has no drop-mode failure case");
        }
        ExpectedIoEffect::Duplicated => {
            assert_eq!(run.log.len(), 2, "{name} should emit a duplicate 9p reply");
            assert_eq!(run.log[0].payload, run.log[1].payload);
            assert!(run.log[1].delivery_icount > run.log[0].delivery_icount);
        }
        ExpectedIoEffect::Corrupted => {
            assert_eq!(
                run.log.len(),
                1,
                "{name} should emit one corrupted 9p reply"
            );
            assert_ne!(
                run.log[0].payload, control.log[0].payload,
                "{name} should mutate 9p reply bytes"
            );
        }
    }
}

fn assert_reordered_ids(name: &str, observed: &[DeliveryRecord], control: &[DeliveryRecord]) {
    assert_eq!(
        observed.len(),
        control.len(),
        "{name} should preserve the number of completions while reordering"
    );
    let observed_ids = correlation_ids(observed);
    let control_ids = correlation_ids(control);
    assert_ne!(
        observed_ids, control_ids,
        "{name} should change delivery order, not only delay completions"
    );
    let mut observed_sorted = observed_ids;
    observed_sorted.sort_unstable();
    let mut control_sorted = control_ids;
    control_sorted.sort_unstable();
    assert_eq!(
        observed_sorted, control_sorted,
        "{name} should deliver the same completions in a different order"
    );
}

fn correlation_ids(log: &[DeliveryRecord]) -> Vec<u32> {
    log.iter().map(|record| record.correlation_id).collect()
}

fn assert_localizes(
    name: &str,
    left: &[DeliveryRecord],
    right: &[DeliveryRecord],
    expected: Option<ExpectedDivergence>,
) {
    let divergence = localize_divergence(left, right);
    match expected {
        Some(expected) => {
            let divergence =
                divergence.unwrap_or_else(|| panic!("{name} should diverge at {expected:?}"));
            assert_divergence(name, &divergence, expected);
            assert_eq!(localize_divergence(left, right), Some(divergence));
        }
        None => {
            assert_eq!(
                divergence, None,
                "{name} should match the fault-free directed-link observation"
            );
        }
    }
}

fn assert_divergence(name: &str, actual: &Divergence, expected: ExpectedDivergence) {
    assert_eq!(
        actual.record_index, expected.record_index,
        "{name} localized to the wrong record"
    );
    match (expected.field, &actual.field) {
        (
            ExpectedDivergedField::Missing { left_missing },
            DivergedField::Missing {
                left_missing: actual,
            },
        ) => assert_eq!(
            *actual, left_missing,
            "{name} localized missing side incorrectly"
        ),
        (ExpectedDivergedField::DeliveryIcount, DivergedField::DeliveryIcount { .. })
        | (ExpectedDivergedField::CorrelationId, DivergedField::CorrelationId { .. })
        | (ExpectedDivergedField::Status, DivergedField::Status { .. })
        | (ExpectedDivergedField::PayloadLen, DivergedField::PayloadLen { .. })
        | (ExpectedDivergedField::PayloadByte, DivergedField::PayloadByte { .. }) => {}
        (expected, actual) => {
            panic!("{name} localized to {actual:?}, expected {expected:?}");
        }
    }
}

fn assert_rng_draw_sequence(
    case_name: &str,
    decisions: &[Decision],
    device: &DeviceId,
    seed: Seed,
) {
    let draws = decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::RngDraw(draw) => Some(draw),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!draws.is_empty(), "{case_name} must record RNG draws");

    let stream = crucible::device_stream_id(device);
    assert!(
        draws.iter().all(|draw| draw.stream == stream),
        "{case_name} must record draws on the device stream"
    );

    let mut replay = crucible::device_rng(seed, device, 0);
    for (index, draw) in draws.iter().enumerate() {
        assert_eq!(
            draw.value,
            replay.next_u64(),
            "{case_name} recorded RNG draw {index} out of sequence"
        );
    }
}

fn assert_io_rng_draw_batches(
    case_name: &str,
    batches: &[Vec<Decision>],
    device: &DeviceId,
    seed: Seed,
    allow_reordered_batches: bool,
) {
    let actual = batches
        .iter()
        .filter_map(|batch| {
            let draws = rng_draw_values(case_name, batch, device);
            (!draws.is_empty()).then_some(draws)
        })
        .collect::<Vec<_>>();
    assert!(!actual.is_empty(), "{case_name} must record RNG draws");

    let mut replay = crucible::device_rng(seed, device, 0);
    let mut expected = actual
        .iter()
        .map(|draws| {
            (0..draws.len())
                .map(|_| replay.next_u64())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    if allow_reordered_batches {
        for actual_batch in actual {
            let index = expected
                .iter()
                .position(|expected_batch| expected_batch == &actual_batch)
                .unwrap_or_else(|| {
                    panic!("{case_name} recorded an RNG draw batch outside the replay stream")
                });
            expected.remove(index);
        }
        assert!(
            expected.is_empty(),
            "{case_name} did not record every replayed RNG batch"
        );
    } else {
        assert_eq!(
            actual, expected,
            "{case_name} must record RNG draws in replay-stream order"
        );
    }
}

fn rng_draw_values(case_name: &str, decisions: &[Decision], device: &DeviceId) -> Vec<u64> {
    let stream = crucible::device_stream_id(device);
    decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::RngDraw(draw) => {
                assert_eq!(
                    draw.stream, stream,
                    "{case_name} must record draws on the device stream"
                );
                Some(draw.value)
            }
            _ => None,
        })
        .collect()
}

fn assert_exact_fault_decisions(
    case_name: &str,
    decisions: &[Decision],
    device: &DeviceId,
    expected: &[ExpectedFaultDecision; 3],
) {
    let actual = decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::FaultFires(FaultDecision { fault, fired, .. }) => {
                Some((fault.clone(), *fired))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let expected = expected
        .iter()
        .map(|decision| (crucible::io_fault_id(device, decision.kind), decision.fired))
        .collect::<Vec<_>>();
    assert_eq!(
        actual.len() % expected.len(),
        0,
        "{case_name} must record complete loss/duplicate/corrupt decision triples"
    );
    for chunk in actual.chunks(expected.len()) {
        assert_eq!(
            chunk,
            expected.as_slice(),
            "{case_name} must record exact fault decisions in loss/duplicate/corrupt order"
        );
    }
}

fn run_block_case(table: &IoFaults, expected: &ExpectedIoEffect) -> IoRun {
    let mut node = fresh_block_subnode();
    node.set_io_faults(table.clone());
    if matches!(expected, ExpectedIoEffect::Reordered) {
        for request_id in 1..=BLOCK_REORDER_REQUESTS {
            node.submit(0, &BlockRequest::read(request_id, 0, 4))
                .unwrap_or_else(|error| panic!("block reorder request should submit: {error}"));
        }
    } else {
        node.submit(0, &BlockRequest::read(42, 0, 4))
            .unwrap_or_else(|error| panic!("block request should submit: {error}"));
    }
    block_run_from_deliveries(node.deliver_due(u64::MAX))
}

fn run_ninep_case(table: &IoFaults, expected: &ExpectedIoEffect) -> IoRun {
    let mut node = fresh_ninep_subnode();
    node.set_io_faults(table.clone());
    if matches!(expected, ExpectedIoEffect::Reordered) {
        for tag in 1..=NINEP_REORDER_REQUESTS {
            node.submit_ninep_frame(0, &tversion(tag, 4096, codec::PROTOCOL_VERSION))
                .unwrap_or_else(|error| panic!("9p reorder request should submit: {error}"));
        }
    } else {
        node.submit_ninep_frame(0, &tversion(7, 4096, codec::PROTOCOL_VERSION))
            .unwrap_or_else(|error| panic!("9p request should submit: {error}"));
    }
    ninep_run_from_deliveries(node.deliver_due(u64::MAX))
}

fn block_run_from_deliveries(deliveries: Vec<DeviceDelivery>) -> IoRun {
    let mut log = DeliveryLog::new();
    let mut decisions = Vec::new();
    let mut decision_batches = Vec::new();
    for delivery in deliveries {
        decision_batches.push(delivery.decisions.clone());
        decisions.extend(delivery.decisions.clone());
        if let Some(completion) = &delivery.completion {
            let response = decode_block_response(&completion.payload);
            log.push(DeliveryRecord {
                delivery_icount: delivery.delivery_icount,
                src_node: delivery.source_node,
                seq: delivery.sequence,
                correlation_id: response.request_id,
                status: response_status_from_block(response.status),
                payload: completion.payload.clone(),
            });
        }
    }
    IoRun {
        log,
        decisions,
        decision_batches,
    }
}

fn ninep_run_from_deliveries(deliveries: Vec<DeviceDelivery>) -> IoRun {
    let mut log = DeliveryLog::new();
    let mut decisions = Vec::new();
    let mut decision_batches = Vec::new();
    for delivery in deliveries {
        decision_batches.push(delivery.decisions.clone());
        decisions.extend(delivery.decisions.clone());
        if let Some(completion) = &delivery.completion {
            log.push(DeliveryRecord {
                delivery_icount: delivery.delivery_icount,
                src_node: delivery.source_node,
                seq: delivery.sequence,
                correlation_id: reply_tag(&completion.payload) as u32,
                status: if reply_type(&completion.payload) == codec::RLERROR {
                    ResponseStatus::Error
                } else {
                    ResponseStatus::Ok
                },
                payload: completion.payload.clone(),
            });
        }
    }
    IoRun {
        log,
        decisions,
        decision_batches,
    }
}

fn recorded_link_run(case: &LinkFaultCase) -> LinkRun {
    let mut link = net_link(case.faults.clone());
    let mut decisions = Vec::new();
    for frame in &case.frames {
        let record = crucible::emit_link_frame_with_recorded_faults(
            Seed::from_u64(LINK_SEED),
            &device(case.name),
            &mut link,
            &link_frame(frame),
            PastDeliveryPolicy::FailLoud,
        )
        .unwrap_or_else(|error| panic!("{} recorded link emit should resolve: {error}", case.name));
        decisions.extend(record.decisions);
    }
    let deliveries = link
        .advance_to(100_000_000)
        .unwrap_or_else(|error| panic!("{} recorded link should advance: {error}", case.name));
    LinkRun {
        log: deliveries
            .into_iter()
            .map(|delivery| {
                DeliveryRecord::new(
                    delivery.key,
                    delivery.frame_id,
                    ResponseStatus::Ok,
                    delivery.payload,
                )
            })
            .collect(),
        decisions,
    }
}

fn seeded_link_script(case: &LinkFaultCase) -> Script<LinkRequest> {
    let mut rng = crucible::device_rng(Seed::from_u64(LINK_SEED), &device(case.name), 0);
    let mut script = Script::new();
    for frame in &case.frames {
        let draws = FrameDraws::from_rng_for_faults(&mut rng, &case.faults);
        script = script.request(
            frame.emit_icount,
            LinkRequest::new(link_frame(frame), draws),
        );
    }
    script.advance_to(100_000_000)
}

fn fault_free_link_script(frames: &[LinkFrameSpec]) -> Script<LinkRequest> {
    let mut script = Script::new();
    for frame in frames {
        script = script.request(
            frame.emit_icount,
            LinkRequest::new(link_frame(frame), FrameDraws::default()),
        );
    }
    script.advance_to(100_000_000)
}

fn single_link_frame() -> Vec<LinkFrameSpec> {
    vec![LinkFrameSpec {
        emit_icount: 0,
        frame_id: 1,
    }]
}

fn reorder_link_frames() -> Vec<LinkFrameSpec> {
    (1..=LINK_REORDER_REQUESTS as u32)
        .map(|frame_id| LinkFrameSpec {
            emit_icount: 0,
            frame_id,
        })
        .collect()
}

fn link_frame(spec: &LinkFrameSpec) -> Frame {
    Frame::new(spec.emit_icount, spec.frame_id, frame_payload())
}

fn link_harness(faults: LinkFaults) -> NetLinkHarness {
    NetLinkHarness::new(net_link(faults), PastDeliveryPolicy::FailLoud)
}

fn net_link(faults: LinkFaults) -> NetLink {
    NetLink::new(0, 7, 10, 1, faults).expect("test net link should build")
}

fn fresh_block_subnode() -> DeviceSchedulingSubNode {
    DeviceSchedulingSubNode::new(
        sub_node("disk-sub", SchedulingNodeKind::Disk),
        node("vm-a"),
        block_device_id(),
        block_device(),
        Seed::from_u64(0xb10c16),
    )
}

fn fresh_ninep_subnode() -> DeviceSchedulingSubNode {
    DeviceSchedulingSubNode::new_ninep(
        sub_node("ninep-sub", SchedulingNodeKind::NineP),
        node("vm-a"),
        ninep_device_id(),
        ninep_device(),
        Seed::from_u64(0x9f516),
    )
}

fn block_device() -> BlockDevice {
    let core = IoCore::new(0, 11, 64, 64).expect("block io core should build");
    BlockDevice::new(
        core,
        BaseImage::new(vec![0xab; 4096]),
        BlockLatency::default(),
    )
}

fn ninep_device() -> NinepDevice {
    let core = IoCore::new(0, 13, 64, 64).expect("9p io core should build");
    let mut root = BTreeMap::new();
    root.insert(
        "alpha".to_owned(),
        Node::File {
            content: b"alpha".to_vec(),
        },
    );
    NinepDevice::new(
        core,
        FsTree::new(Node::Directory { children: root }),
        NinepLatency::default(),
    )
}

fn link_fault_table(fault: Fault) -> LinkFaults {
    let combined = CombinedFaults::from_faults(&[fault]);
    let faults = combined
        .network
        .get(&link_id())
        .unwrap_or_else(|| panic!("combined network faults should include test link"));
    link_faults_from_combined_network(faults, NetworkLinkDirection::EndpointAToEndpointB)
}

fn block_table(fault: Fault) -> IoFaults {
    let combined = CombinedFaults::from_faults(&[fault]);
    let faults = combined
        .block
        .get(&block_device_id())
        .unwrap_or_else(|| panic!("combined block faults should include test disk"));
    crucible::block_faults_from_combined_block(faults)
}

fn ninep_table(fault: Fault) -> IoFaults {
    let combined = CombinedFaults::from_faults(&[fault]);
    let faults = combined
        .ninep
        .get(&ninep_device_id())
        .unwrap_or_else(|| panic!("combined 9p faults should include test fs"));
    crucible::ninep_faults_from_combined_ninep(faults)
}

fn decode_block_response(payload: &[u8]) -> BlockResponse {
    BlockResponse::decode(payload)
        .unwrap_or_else(|error| panic!("block response should decode: {error}"))
}

fn response_status_from_block(status: BlockStatus) -> ResponseStatus {
    match status {
        BlockStatus::Ok => ResponseStatus::Ok,
        BlockStatus::Error => ResponseStatus::Error,
    }
}

fn tversion(tag: u16, msize: u32, version: &str) -> Vec<u8> {
    let mut body = msize.to_le_bytes().to_vec();
    body.extend_from_slice(&string_bytes(version));
    frame(codec::TVERSION, tag, &body)
}

fn frame(msg_type: u8, tag: u16, body: &[u8]) -> Vec<u8> {
    let size = (codec::HEADER_LEN + body.len()) as u32;
    let mut frame = Vec::new();
    frame.extend_from_slice(&size.to_le_bytes());
    frame.push(msg_type);
    frame.extend_from_slice(&tag.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

fn string_bytes(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

fn reply_type(frame: &[u8]) -> u8 {
    frame[4]
}

fn reply_tag(frame: &[u8]) -> u16 {
    u16::from_le_bytes([frame[5], frame[6]])
}

fn rlerror_code(frame: &[u8]) -> u32 {
    u32::from_le_bytes([frame[7], frame[8], frame[9], frame[10]])
}

fn link_id() -> crucible::LinkId {
    crucible::LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        LINK_A.len(),
        LINK_A,
        LINK_B.len(),
        LINK_B
    ))
}

fn frame_payload() -> Vec<u8> {
    vec![1, 2, 3, 4]
}

fn rate(basis_points: u32) -> FaultRateBasisPoints {
    FaultRateBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("test rate should be valid: {error}"))
}

fn bandwidth(bits_per_second: u64) -> FaultBandwidthBitsPerSecond {
    FaultBandwidthBitsPerSecond::new(bits_per_second)
        .unwrap_or_else(|error| panic!("test bandwidth should be valid: {error}"))
}

fn errno(code: i32) -> NinePErrno {
    NinePErrno::from_code(code)
        .unwrap_or_else(|error| panic!("test errno should be valid: {error}"))
}

fn block_device_id() -> DeviceId {
    device("disk0")
}

fn ninep_device_id() -> DeviceId {
    device("fs0")
}

fn device(name: &str) -> DeviceId {
    DeviceId {
        name: name.to_owned(),
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn sub_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind,
    }
}

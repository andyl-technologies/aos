//! CLI unit tests grouped by user-facing workflow.

use super::*;

use std::error::Error;

use crucible_harness::reproduction::{ReproductionArtifact, mock_e2e_reproduction_artifact};
use tempfile::TempDir;

#[path = "tests/actual_failure.rs"]
mod actual_failure;
#[path = "tests/graph_support.rs"]
mod graph_support;
#[path = "tests/replay_artifact.rs"]
mod replay_artifact;
#[path = "tests/state_workflows.rs"]
mod state_workflows;
#[path = "tests/surface.rs"]
mod surface;
#[path = "tests/verify_dispatch.rs"]
mod verify_dispatch;

use graph_support::*;
use surface::*;

fn coverage_event_frame(
    sequence: u64,
    kind: &str,
    attributes: impl IntoIterator<Item = (&'static str, crucible_api::OpenSetAttributeValue)>,
) -> crucible_api::StreamingEventFrame {
    use std::collections::BTreeMap;

    crucible_api::StreamingEventFrame {
        generation: 0,
        cursor: crucible_api::EventLogCursor::new(sequence),
        next_cursor: crucible_api::EventLogCursor::new(sequence + 1),
        event: crucible_api::OpenSetEventEnvelope {
            sequence,
            at: crucible_api::OpenSetEventTime {
                virtual_time_ticks: sequence,
                icount_retired: sequence,
                icount_node: Some(String::from("vm-0")),
            },
            source: crucible_api::OpenSetEventSource::Node {
                node: String::from("vm-0"),
            },
            level: crucible::EventLevel::Trace,
            observational: true,
            payload: crucible_api::OpenSetPayload::new(
                kind,
                attributes
                    .into_iter()
                    .map(|(name, value)| (String::from(name), value))
                    .collect::<BTreeMap<_, _>>(),
            ),
        },
    }
}

#[test]
fn streamed_basic_block_coverage_rebuilds_canonical_feedback() {
    use crucible_api::OpenSetAttributeValue::{String as Text, Uint};

    let frame = coverage_event_frame(
        7,
        "crucible.event.coverage",
        [
            ("kind", Text(String::from("basic_block"))),
            ("node", Text(String::from("vm-0"))),
            ("execution_icount", Uint(41)),
            ("guest_pc", Uint(0x401000)),
            ("block_len", Uint(32)),
        ],
    );
    let event = coverage_event_from_streaming_frame(&frame)
        .expect("valid coverage frame must parse")
        .expect("coverage frame must produce an observation");
    let feedback = coverage_feedback_from_streamed_events(vec![event])
        .expect("valid observation must rebuild feedback");

    assert_eq!(feedback.projection().len(), 1);
    assert_eq!(
        feedback.projection().entries()[0].observation,
        crucible::EventLogCoverageObservation::BasicBlock {
            node: crucible::NodeId {
                name: String::from("vm-0"),
            },
            guest_pc: 0x401000,
            block_len: 32,
        }
    );
}

#[test]
fn malformed_streamed_coverage_fails_loudly() {
    use crucible_api::OpenSetAttributeValue::{String as Text, Uint};

    let frame = coverage_event_frame(
        9,
        "crucible.event.coverage",
        [
            ("kind", Text(String::from("basic_block"))),
            ("node", Text(String::from("vm-0"))),
            ("execution_icount", Uint(52)),
            ("guest_pc", Uint(0x402000)),
        ],
    );
    let error = coverage_event_from_streaming_frame(&frame)
        .expect_err("missing block_len must reject the coverage frame");

    assert!(error.to_string().contains("block_len"));
}

//! Fixed canonical bytes, nested ordering and original allocation refusal.

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};

fn id(text: &str) -> SignalId {
    SignalId::parse(text).unwrap_or_else(|error| panic!("canonical fixture identifier: {error}"))
}

fn ratio(numerator: i64, denominator: u64) -> ExactRatio {
    ExactRatio::new(numerator, denominator)
        .unwrap_or_else(|error| panic!("canonical fixture ratio: {error}"))
}

fn limits() -> SignalResourceLimits {
    SignalResourceLimits {
        nodes: 8,
        edges: 16,
        inputs_per_node: 4,
        graph_depth: 8,
        state_bytes: 128,
        authored_payload_bytes: 1024,
        states_per_node: 4,
        transitions_per_node: 8,
        lookup_points_per_node: 16,
    }
}

fn constant() -> SignalNode {
    SignalNode {
        id: id("enabled"),
        domain: SignalDomain::VirtualTime,
        output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("canonical fixture shape: {error}")),
        inputs: Vec::new(),
        kind: SignalNodeKind::Constant {
            value: SignalValue::Bool(true),
        },
    }
}

const CONSTANT_MATERIAL: &str = "evaluator_version=2\nlimit.signal_nodes=8\nlimit.signal_edges=16\nlimit.signal_inputs_per_node=4\nlimit.signal_graph_depth=8\nlimit.signal_state_bytes=128\nlimit.state_machine_states_per_node=4\nlimit.state_machine_transitions_per_node=8\nlimit.lookup_points_per_node=16\nexport=enabled\nnode=enabled\ndomain=virtual_time\noutput=bool|dimensionless|0\nkind=constant\nvalue=bool:true";

#[test]
fn retained_program_preserves_fixed_material_and_identity() {
    let program = SignalProgram::new(vec![constant()], vec![id("enabled")], limits())
        .unwrap_or_else(|error| panic!("canonical fixture program: {error}"));

    assert_eq!(program.canonical_material(), CONSTANT_MATERIAL);
    assert_eq!(
        program.id(),
        ContentHash::from_canonical_material("crucible.signal-program.v2", CONSTANT_MATERIAL)
    );
    assert!(!program.canonical_material().ends_with('\n'));
}

#[test]
fn literal_and_shape_streams_match_the_independent_literal_representation() {
    let values = [
        SignalValue::Bool(false),
        SignalValue::I64(i64::MIN),
        SignalValue::U64(u64::MAX),
        SignalValue::Ratio(ratio(-2, 3)),
        SignalValue::DurationNanos(17),
        SignalValue::RatePerSecond(18),
        SignalValue::ProbabilityMillionths(999_999),
        SignalValue::Enum {
            schema: id("mode"),
            variant: id("ready"),
        },
        SignalValue::Event {
            schema: id("event"),
            payload: vec![0, 15, 255],
        },
        SignalValue::Vector2(vec![SignalValue::I64(-3), SignalValue::I64(5)]),
        SignalValue::Vector3(vec![
            SignalValue::U64(7),
            SignalValue::U64(0),
            SignalValue::U64(9),
        ]),
        SignalValue::Bytes(vec![0, 127, 128, 255]),
    ];

    for value in &values {
        assert_eq!(format!("{}", value_material(value)), value.material());
        if let Some(value_type) = value.value_type() {
            assert_eq!(
                format!("{}", type_material(&value_type)),
                value_type.material()
            );
        }
    }
    assert_eq!(format!("{}", hex_material(&[])), "");
    assert_eq!(format!("{}", hex_material(&[0, 15, 255])), "000fff");
}

#[test]
fn source_stream_preserves_nested_points_trace_mapping_and_grid_vectors() {
    let coordinate = SignalCoordinate::Event {
        parent: Box::new(SignalCoordinate::Operation {
            adapter: id("block"),
            target: id("disk"),
            operation: id("read"),
            producer_sequence: 11,
            suboperation: 3,
        }),
        sequence: 9,
    };
    let source = SignalSourceSpecification::Step {
        points: vec![SignalPoint {
            coordinate,
            sequence: 2,
            value: SignalValue::I64(-7),
        }],
        before: SignalBoundaryBehavior::Constant(SignalValue::I64(1)),
    };
    assert_eq!(
        format!("{}", source_material(&source)),
        "points=event:operation:block:disk:read:11:3:9#2=>i64:-7;before=constant:i64:1"
    );

    let trace = SignalSourceSpecification::Trace {
        artifact: ContentHash { bytes: [0x12; 32] },
        raw_provenance: ContentHash { bytes: [0xab; 32] },
        channel: id("values"),
        quality_channel: Some(id("quality")),
        quality_accept: Some(-1),
        interpolation: SignalInterpolation::Linear {
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Saturate,
        },
        before: SignalBoundaryBehavior::Hold,
        after: SignalBoundaryBehavior::Inactive,
        missing: MissingSampleBehavior::Interpolate,
        time_mapping: Some(TraceTimeMapping {
            source_epoch: -2,
            virtual_epoch_ticks: 3,
            scale: ratio(5, 7),
            rounding: SignalRounding::Floor,
        }),
    };
    assert_eq!(
        format!("{}", source_material(&trace)),
        concat!(
            "artifact=1212121212121212121212121212121212121212121212121212121212121212;",
            "raw_provenance=abababababababababababababababababababababababababababababababab;",
            "channel=values;quality_channel=some:quality;quality_accept=some:-1;",
            "interpolation=linear(rounding=nearest_ties_to_even,overflow=saturate);before=hold;after=inactive;missing=interpolate;time_mapping=some:-2:3:5/7:floor"
        )
    );

    let grid = SignalSourceSpecification::RegularGrid {
        artifact: ContentHash { bytes: [0; 32] },
        coordinate_frame: id("map"),
        origin_mm: [-1, 0, 2],
        cell_size_mm: [3, 4, 5],
        dimensions: [6, 7, 8],
        interpolation: SignalInterpolation::Nearest,
        outside: SignalBoundaryBehavior::Error,
    };
    assert_eq!(
        format!("{}", source_material(&grid)),
        "artifact=0000000000000000000000000000000000000000000000000000000000000000;coordinate_frame=map;origin_mm=-1,0,2;cell_size_mm=3,4,5;dimensions=6,7,8;interpolation=nearest;outside=error"
    );
}

#[test]
fn pure_and_stateful_streams_preserve_order_and_empty_fragments() {
    let mapping = PureSignalSpecification::EnumMap {
        entries: vec![
            (id("second"), SignalValue::I64(2)),
            (id("first"), SignalValue::I64(1)),
        ],
    };
    assert_eq!(
        format!("{}", pure_material(&mapping)),
        "entries=second=>i64:2,first=>i64:1"
    );
    let lookup = PureSignalSpecification::LookupStep {
        points: vec![
            (SignalValue::I64(-1), SignalValue::I64(4)),
            (SignalValue::I64(3), SignalValue::I64(9)),
        ],
        before: SignalBoundaryBehavior::Error,
        after: SignalBoundaryBehavior::Constant(SignalValue::I64(8)),
    };
    assert_eq!(
        format!("{}", pure_material(&lookup)),
        "points=i64:-1=>i64:4,i64:3=>i64:9;before=error;after=constant:i64:8"
    );
    assert_eq!(
        format!("{}", pure_material(&PureSignalSpecification::FieldSample)),
        ""
    );
    assert_eq!(
        format!("{}", pure_material(&PureSignalSpecification::GateEvents)),
        ""
    );

    let machine = StatefulSignalSpecification::FiniteStateMachine {
        states: vec![id("off"), id("on")],
        initial: id("off"),
        unmatched_event: id("ignore"),
        transitions: vec![StateMachineTransition {
            from: id("off"),
            event: id("go"),
            guard: Some(id("allowed")),
            to: id("on"),
            emit: None,
            timer_operations: vec![
                StateMachineTimerOperation::Start {
                    timer: id("timer"),
                    duration_nanos: 23,
                },
                StateMachineTimerOperation::Cancel { timer: id("old") },
            ],
        }],
    };
    assert_eq!(
        format!("{}", stateful_material(&machine)),
        "states=off,on;initial=off;transitions=off:go:some:allowed=>on:none:start:timer:23/cancel:old;unmatched_event=ignore"
    );
    let markov = StatefulSignalSpecification::MarkovChain {
        states: vec![id("good"), id("bad")],
        initial: id("good"),
        opportunity: id("tick"),
        probability_rows: vec![vec![900_000, 100_000], vec![400_000, 600_000]],
    };
    assert_eq!(
        format!("{}", stateful_material(&markov)),
        "states=good,bad;initial=good;opportunity=tick;probability_rows=900000/100000,400000/600000"
    );
}

struct Authority {
    rejected_bytes: u64,
    rejected: AtomicU64,
    used: Arc<AtomicU64>,
}

struct Credit {
    bytes: u64,
    used: Arc<AtomicU64>,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        // Rejected allocation sizes model capacity refusal, not revocation.
        // This retained atomic fixture authority has no mutable closed state.
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        if bytes == self.rejected_bytes {
            self.rejected.fetch_add(1, Ordering::SeqCst);
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "fixture canonical allocation refused",
            )));
        }
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= 1_048_576)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other(
                    "fixture finite allowance exhausted",
                ))
            })?;
        Ok(Arc::new(Credit {
            bytes,
            used: self.used.clone(),
        }))
    }
}

#[test]
fn original_material_refusal_prevents_program_publication() -> Result<(), Box<dyn Error>> {
    let nodes = vec![constant()];
    let exports = vec![id("enabled")];
    // The shared account also reserves its documented receipt-vector overlap.
    let canonical_reservation =
        CONSTANT_MATERIAL.len() as u64 + (4 * std::mem::size_of::<Arc<dyn Send + Sync>>()) as u64;
    let authority = Arc::new(Authority {
        rejected_bytes: canonical_reservation,
        rejected: AtomicU64::new(0),
        used: Arc::new(AtomicU64::new(0)),
    });
    let budget = DecodeBudget::new(authority.clone(), 1_048_576)?;
    let scope = budget.enter();

    let error = SignalProgram::new(nodes, exports, limits())
        .err()
        .ok_or_else(|| {
            std::io::Error::other("program was published without canonical allocation credit")
        })?;
    assert!(matches!(&error, SignalProgramError::OriginalAdmission(_)));
    assert_eq!(authority.rejected.load(Ordering::SeqCst), 1);
    assert!(error.source().and_then(Error::source).is_some());

    drop(scope);
    drop(budget);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

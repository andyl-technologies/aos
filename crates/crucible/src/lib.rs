//! `crucible` owns the pure engine type spine.
//!
//! Spec index: RFC-0010 files 05, 06, 07, 08, 17, 18, 19.
//!
//! This L3 crate defines the RFC-0010 execution-model vocabulary shared by the
//! scheduler, temporal graph, checkpoint cache, fault engine, assertions, event
//! log, and VM backend adapters. The crate remains a safe reduction island: it
//! declares the backend trait and core model signatures, while concrete VM
//! drivers and driver-specific details live outside the engine crate.
//!
//! Module map: [`model`] owns the content-addressed execution vocabulary,
//! [`decision`] owns seeded decision recording, [`backend`] owns the VM backend
//! boundary, [`scheduler`] owns the quantum-loop boundary, and `sim_backend`
//! provides the gated in-process test double.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod backend;
pub mod decision;
pub mod model;
pub mod scheduler;
#[cfg(feature = "test-double")]
mod sim_backend;

pub use backend::{
    AdvanceOutcome, Backend, BackendError, BackendInput, ExecutionFingerprint, ExecutionHorizon,
};
pub use decision::{DecisionRecordError, DecisionRecorder};
pub use model::{
    AppRandomDecision, Checkpoint, CheckpointKind, ChoiceTag, Configuration, ContentHash, Decision,
    DeliveryOrderDecision, EngineError, EventKey, FaultDecision, FaultId, GenesisCheckpoint,
    Icount, IrqVector, NodeId, OverrideDecision, PreemptionDecision, PreemptionKind, RngDecision,
    RngStreamId, RuntimeState, ScenarioDef, Schedule, ScheduleError, SchedulingPoint, State,
    TemporalGraph, VcpuId, VirtualTime, World, bake, instantiate, reduce, step,
};
pub use scheduler::{
    ControlOperation, ControlOperationKind, IoCompletion, QuantumLoop, QuantumOutcome,
    QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload, SchedulerError,
    SchedulerNodeId, SchedulingNodeKind, ordered_scheduled_events,
};
#[cfg(feature = "test-double")]
pub use sim_backend::{SimBackend, SimBackendState};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_appends_decision_without_mutating_parent() {
        let config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
        let decision = Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: String::from("root"),
            },
            value: 42,
        });

        let child = step(&config, decision.clone());

        assert!(config.schedule.is_empty());
        assert_eq!(child.schedule.decisions(), &[decision]);
    }

    #[test]
    fn schedule_prefix_bounds_are_checked() {
        let schedule = Schedule::empty().appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: String::from("root"),
            },
            value: 1,
        }));

        let prefix = schedule.prefix(1);
        assert!(prefix.is_ok());
        assert_eq!(prefix.as_ref().map(Schedule::len), Ok(1));
        let error = match schedule.prefix(2) {
            Ok(_) => panic!("prefix beyond schedule length should fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ScheduleError::PrefixTooLong {
                requested: 2,
                available: 1,
            }
        ));
        assert_eq!(
            error.to_string(),
            "schedule prefix length 2 exceeds available length 1"
        );
    }

    #[test]
    fn canonical_material_builds_stable_scenario_identity() {
        let first =
            ScenarioDef::from_canonical_material("crucible.test.scenario", "field=a\nvalue=1");
        let second =
            ScenarioDef::from_canonical_material("crucible.test.scenario", "field=a\nvalue=1");
        let changed_material =
            ScenarioDef::from_canonical_material("crucible.test.scenario", "field=a\nvalue=2");
        let changed_domain =
            ScenarioDef::from_canonical_material("crucible.test.other", "field=a\nvalue=1");

        assert_eq!(first, second);
        assert_ne!(first.id, changed_material.id);
        assert_ne!(first.id, changed_domain.id);
    }

    #[test]
    fn reduce_is_pure_over_scenario_and_schedule() {
        let scenario =
            ScenarioDef::from_canonical_material("crucible.test.reduce", "node=a\nseed=1");
        let other_scenario =
            ScenarioDef::from_canonical_material("crucible.test.reduce", "node=a\nseed=2");
        let first_decision = Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: String::from("node-a/faults"),
            },
            value: 7,
        });
        let second_decision = Decision::FaultFires(FaultDecision {
            at: VirtualTime { ticks: 10 },
            fault: FaultId {
                name: String::from("link-drop"),
            },
            fired: true,
        });
        let schedule = Schedule::empty()
            .appended(first_decision.clone())
            .appended(second_decision.clone());
        let reordered = Schedule::empty()
            .appended(second_decision)
            .appended(first_decision);

        let first = reduce(&scenario, &schedule);
        let second = reduce(&scenario, &schedule);
        let changed_scenario = reduce(&other_scenario, &schedule);
        let changed_order = reduce(&scenario, &reordered);

        assert_eq!(first, second);
        assert_ne!(first, changed_scenario);
        assert_ne!(first, changed_order);
    }

    #[test]
    fn reduce_is_prefix_closed_by_schedule_hash() {
        let scenario =
            ScenarioDef::from_canonical_material("crucible.test.reduce", "node=a\nseed=prefix");
        let root = Configuration::genesis(scenario.clone());
        let child = step(
            &root,
            Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: 4 },
                order: vec![EventKey { sequence: 1 }, EventKey { sequence: 2 }],
            }),
        );
        let grandchild = step(
            &child,
            Decision::AppRandom(AppRandomDecision {
                node: NodeId {
                    name: String::from("node-a"),
                },
                stream: RngStreamId {
                    name: String::from("app/request"),
                },
                request_id: 3,
                width: 16,
                value: 0xace,
            }),
        );
        let child_prefix = match grandchild.schedule.prefix(1) {
            Ok(prefix) => prefix,
            Err(error) => panic!("valid prefix should not fail: {error}"),
        };
        let root_reduced = reduce(&scenario, &root.schedule);
        let child_reduced = reduce(&scenario, &child.schedule);
        let child_prefix_reduced = reduce(&scenario, &child_prefix);
        let grandchild_reduced = reduce(&scenario, &grandchild.schedule);

        assert_eq!(child.schedule, child_prefix);
        assert_eq!(child_reduced, child_prefix_reduced);
        assert_ne!(root_reduced, child_reduced);
        assert_ne!(child_reduced, grandchild_reduced);
        assert_ne!(root.content_hash(), child.content_hash());
        assert_ne!(child.content_hash(), grandchild.content_hash());
        assert_ne!(
            child.schedule.content_hash(),
            grandchild.schedule.content_hash()
        );
    }

    #[test]
    fn backend_trait_is_object_safe() {
        struct StubBackend;

        impl Backend for StubBackend {
            fn advance_to_horizon(
                &mut self,
                _horizon: ExecutionHorizon,
            ) -> Result<AdvanceOutcome, BackendError> {
                Ok(AdvanceOutcome::ReachedHorizon)
            }

            fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
                Ok(ExecutionFingerprint {
                    hash: ContentHash::default(),
                })
            }

            fn deliver_input(&mut self, _input: BackendInput) -> Result<(), BackendError> {
                Ok(())
            }

            fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
                Ok(Checkpoint {
                    id: ContentHash::default(),
                    configuration: ContentHash::default(),
                    kind: CheckpointKind::Fat,
                })
            }

            fn restore(&mut self, _checkpoint: &Checkpoint) -> Result<(), BackendError> {
                Ok(())
            }

            fn shutdown(&mut self) -> Result<(), BackendError> {
                Ok(())
            }
        }

        let mut backend = StubBackend;
        let object: &mut dyn Backend = &mut backend;
        let advanced = object.advance_to_horizon(ExecutionHorizon {
            icount: Icount { retired: 10 },
        });

        assert_eq!(advanced, Ok(AdvanceOutcome::ReachedHorizon));
    }

    #[test]
    fn engine_and_backend_errors_render_all_variants_deterministically() {
        let engine = EngineError::NotImplemented {
            operation: "instantiate",
        };
        let backend_not_implemented = BackendError::NotImplemented {
            operation: "snapshot",
        };
        let backend_rejected = BackendError::Rejected {
            message: String::from("stable rejection"),
        };

        assert_eq!(engine.to_string(), "instantiate is not implemented yet");
        assert_eq!(
            backend_not_implemented.to_string(),
            "backend operation snapshot is not implemented yet"
        );
        assert_eq!(backend_rejected.to_string(), "stable rejection");
    }
}

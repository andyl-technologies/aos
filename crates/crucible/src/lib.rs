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
//! [`backend`] owns the VM backend boundary, [`scheduler`] owns the
//! quantum-loop boundary, and `sim_backend` provides the gated in-process test
//! double.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod backend;
pub mod model;
pub mod scheduler;
#[cfg(feature = "test-double")]
mod sim_backend;

pub use backend::{
    AdvanceOutcome, Backend, BackendError, BackendInput, ExecutionFingerprint, ExecutionHorizon,
};
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
    SchedulerNodeId, SchedulingNodeKind,
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
            operation: "reduce",
        };
        let backend_not_implemented = BackendError::NotImplemented {
            operation: "snapshot",
        };
        let backend_rejected = BackendError::Rejected {
            message: String::from("stable rejection"),
        };

        assert_eq!(engine.to_string(), "reduce is not implemented yet");
        assert_eq!(
            backend_not_implemented.to_string(),
            "backend operation snapshot is not implemented yet"
        );
        assert_eq!(backend_rejected.to_string(), "stable rejection");
    }
}

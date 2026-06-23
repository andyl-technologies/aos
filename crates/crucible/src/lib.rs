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
    Icount, IrqVector, NodeCounter, NodeId, OverrideDecision, PreemptionDecision, PreemptionKind,
    RngDecision, RngStreamId, RuntimeState, ScenarioDef, Schedule, ScheduleError, SchedulingPoint,
    Shift, SimDuration, SimInstant, SimOffset, State, TemporalGraph, TimeConversionError, VcpuId,
    VirtualInstant, VirtualTime, World, bake, instantiate, reduce, step,
};
pub use scheduler::{
    ControlOperation, ControlOperationKind, IoCompletion, NodeTimelineProjection, QuantumLoop,
    QuantumOutcome, QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerError, SchedulerNodeId, SchedulingNodeKind, SharedTimeline, SharedTimelineKey,
    ordered_scheduled_events, ordered_timeline_keys,
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
    fn step_is_pure_temporal_graph_edge_constructor() {
        for seed in 0..64 {
            let parent = Configuration {
                def: generated_scenario(seed),
                schedule: generated_schedule(seed, 4),
            };
            let original_parent = parent.clone();
            let decision = generated_decision(seed, 64);

            let child = step(&parent, decision.clone());

            assert_eq!(parent, original_parent);
            assert_eq!(child.def, parent.def);
            assert_ne!(child, parent);
            assert_eq!(child.schedule.len(), parent.schedule.len() + 1);
            assert_eq!(
                child.schedule.prefix(parent.schedule.len()),
                Ok(parent.schedule.clone())
            );
            assert_eq!(child.schedule.decisions().last(), Some(&decision));
            assert_eq!(child.id(), child.content_hash());
        }
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
    fn time_vocabulary_converts_icount_and_virtual_instants_exactly() {
        let shift = match Shift::new(4) {
            Ok(shift) => shift,
            Err(error) => panic!("valid shift should construct: {error}"),
        };
        let icount = Icount { retired: 17 };
        let instant = match icount.to_virtual(shift) {
            Ok(instant) => instant,
            Err(error) => panic!("valid icount conversion should succeed: {error}"),
        };
        let unaligned = VirtualInstant { nanos: 275 };

        assert_eq!(instant, VirtualInstant { nanos: 272 });
        assert_eq!(instant.to_icount_floor(shift), Ok(icount));
        assert_eq!(instant.to_icount_ceil(shift), Ok(icount));
        assert_eq!(unaligned.to_icount_floor(shift), Ok(Icount { retired: 17 }));
        assert_eq!(unaligned.to_icount_ceil(shift), Ok(Icount { retired: 18 }));
        let alias: SimInstant = instant;
        assert_eq!(alias, instant);
    }

    #[test]
    fn time_vocabulary_keeps_duration_and_offset_distinct() {
        let earlier = VirtualInstant { nanos: 40 };
        let later = VirtualInstant { nanos: 100 };
        let duration = SimDuration { nanos: 25 };

        assert_eq!(later.duration_since(earlier), SimDuration { nanos: 60 });
        assert_eq!(earlier.duration_since(later), SimDuration { nanos: 0 });
        assert_eq!(earlier + duration, VirtualInstant { nanos: 65 });
        assert_eq!(
            duration + SimDuration { nanos: 5 },
            SimDuration { nanos: 30 }
        );
        assert_eq!(duration * 3, SimDuration { nanos: 75 });
        assert_eq!(
            VirtualInstant { nanos: 10 }.with_skew(SimOffset { nanos: -15 }),
            VirtualInstant::EPOCH
        );
        assert_eq!(
            VirtualInstant { nanos: 10 }.with_skew(SimOffset { nanos: 15 }),
            VirtualInstant { nanos: 25 }
        );
    }

    #[test]
    fn time_vocabulary_rejects_invalid_shift_and_virtual_time_overflow() {
        let invalid = Shift { bits: 64 };
        let valid = Shift { bits: 63 };

        assert_eq!(
            Shift::new(64),
            Err(TimeConversionError::InvalidShift { shift: invalid })
        );
        assert_eq!(
            Icount { retired: 1 }.to_virtual(invalid),
            Err(TimeConversionError::InvalidShift { shift: invalid })
        );
        assert_eq!(
            Icount { retired: 2 }.to_virtual(valid),
            Err(TimeConversionError::VirtualTimeOverflow {
                icount: Icount { retired: 2 },
                shift: valid,
            })
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
    fn configuration_id_is_content_addressed_by_def_and_schedule() {
        let scenario =
            ScenarioDef::from_canonical_material("crucible.test.configuration", "node=a\nseed=1");
        let same_scenario =
            ScenarioDef::from_canonical_material("crucible.test.configuration", "node=a\nseed=1");
        let base_schedule = Schedule::empty().appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId {
                name: String::from("node-a/faults"),
            },
            value: 7,
        }));
        let same = Configuration {
            def: same_scenario,
            schedule: base_schedule.clone(),
        };
        let changed_schedule = Configuration {
            def: scenario.clone(),
            schedule: base_schedule.appended(Decision::FaultFires(FaultDecision {
                at: VirtualTime { ticks: 1 },
                fault: FaultId {
                    name: String::from("link-drop"),
                },
                fired: true,
            })),
        };
        let base = Configuration {
            def: scenario,
            schedule: same.schedule.clone(),
        };

        assert_eq!(base, same);
        assert_eq!(base.id(), same.id());
        assert_eq!(base.id(), base.content_hash());
        assert_ne!(base.schedule, changed_schedule.schedule);
        assert_ne!(base.id(), changed_schedule.id());
    }

    #[test]
    fn configuration_id_property_covers_generated_def_schedule_pairs() {
        let mut checked_cases = 0;

        for seed in 0..64 {
            let def = generated_scenario(seed);
            let schedule = generated_schedule(seed, 6);
            let base = Configuration {
                def: def.clone(),
                schedule: schedule.clone(),
            };
            let same = Configuration {
                def: generated_scenario(seed),
                schedule: schedule.clone(),
            };
            let changed_schedule = Configuration {
                def: def.clone(),
                schedule: schedule.appended(generated_decision(seed, 99)),
            };
            let same_length_changed_schedule = Configuration {
                def: def.clone(),
                schedule: generated_schedule(seed + 10_000, 6),
            };
            let reordered_schedule = Configuration {
                def: def.clone(),
                schedule: swap_first_two_decisions(&base.schedule),
            };
            let changed_def = Configuration {
                def: generated_scenario(seed + 1_000),
                schedule: base.schedule.clone(),
            };

            assert_eq!(base, same);
            assert_eq!(base.id(), same.id());
            assert_eq!(base.id(), base.content_hash());
            assert_ne!(base.schedule, changed_schedule.schedule);
            assert_ne!(base.id(), changed_schedule.id());
            assert_eq!(
                base.schedule.len(),
                same_length_changed_schedule.schedule.len()
            );
            assert_ne!(base.schedule, same_length_changed_schedule.schedule);
            assert_ne!(base.id(), same_length_changed_schedule.id());
            assert_eq!(base.schedule.len(), reordered_schedule.schedule.len());
            assert_ne!(base.schedule, reordered_schedule.schedule);
            assert_ne!(base.id(), reordered_schedule.id());
            assert_ne!(base.def, changed_def.def);
            assert_ne!(base.id(), changed_def.id());

            checked_cases += 1;
        }

        assert_eq!(checked_cases, 64);
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
    fn resume_continue_matches_uninterrupted_run_by_fingerprint() {
        let scenario = generated_scenario(0x500);
        let seed = 0x0010_5005;
        let mut uninterrupted =
            DecisionRecorder::new(Configuration::genesis(scenario.clone()), seed);
        for index in 0..8 {
            record_representative_decision(&mut uninterrupted, index);
        }
        let uninterrupted = uninterrupted.into_configuration();

        let mut prefix = DecisionRecorder::new(Configuration::genesis(scenario), seed);
        for index in 0..4 {
            record_representative_decision(&mut prefix, index);
        }
        let prefix = prefix.into_configuration();
        let prefix_len = prefix.schedule.len();
        let mut resumed = DecisionRecorder::new(prefix.clone(), seed);
        for index in 4..8 {
            record_representative_decision(&mut resumed, index);
        }
        let resumed = resumed.into_configuration();

        assert_eq!(
            uninterrupted.schedule.prefix(prefix_len),
            Ok(prefix.schedule.clone())
        );
        assert_ne!(
            configuration_execution_fingerprint(&prefix),
            configuration_execution_fingerprint(&uninterrupted)
        );
        assert_eq!(uninterrupted, resumed);
        assert_eq!(
            configuration_execution_fingerprint(&uninterrupted),
            configuration_execution_fingerprint(&resumed)
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

    fn generated_scenario(seed: u64) -> ScenarioDef {
        ScenarioDef::from_canonical_material(
            "crucible.test.configuration.generated",
            &format!("node=a\nseed={seed}\nimage=generated-{seed:04}"),
        )
    }

    fn generated_schedule(seed: u64, len: u64) -> Schedule {
        let mut schedule = Schedule::empty();
        for index in 0..len {
            schedule = schedule.appended(generated_decision(seed, index));
        }
        schedule
    }

    fn swap_first_two_decisions(schedule: &Schedule) -> Schedule {
        let decisions = schedule.decisions();
        let mut swapped = Schedule::empty();

        if decisions.len() < 2 {
            return schedule.clone();
        }

        swapped = swapped.appended(decisions[1].clone());
        swapped = swapped.appended(decisions[0].clone());
        for decision in &decisions[2..] {
            swapped = swapped.appended(decision.clone());
        }

        swapped
    }

    fn record_representative_decision(recorder: &mut DecisionRecorder, index: u64) {
        match index % 3 {
            0 => {
                let _ = recorder.draw_u64(RngStreamId {
                    name: format!("node-a/faults/{index}"),
                });
            }
            1 => {
                let _ = recorder.decide_fault(
                    VirtualTime { ticks: index + 1 },
                    FaultId {
                        name: format!("link-a-b/drop-{index}"),
                    },
                    RngStreamId {
                        name: String::from("node-b/faults"),
                    },
                    u64::MAX / 2,
                );
            }
            _ => {
                let served = recorder.serve_app_random(
                    NodeId {
                        name: String::from("node-a"),
                    },
                    RngStreamId {
                        name: String::from("node-a/app-random"),
                    },
                    16,
                );
                assert!(served.is_ok());
            }
        }
    }

    fn configuration_execution_fingerprint(configuration: &Configuration) -> ExecutionFingerprint {
        let state = match reduce(&configuration.def, &configuration.schedule) {
            Ok(state) => state,
            Err(error) => panic!("pure configuration fingerprint should reduce: {error}"),
        };
        ExecutionFingerprint { hash: state.id }
    }

    fn generated_decision(seed: u64, index: u64) -> Decision {
        match (seed + index) % 6 {
            0 => Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime {
                    ticks: seed + index,
                },
                order: vec![
                    EventKey { sequence: index },
                    EventKey {
                        sequence: index + 1,
                    },
                ],
            }),
            1 => Decision::FaultFires(FaultDecision {
                at: VirtualTime {
                    ticks: seed.saturating_mul(2) + index,
                },
                fault: FaultId {
                    name: format!("fault-{seed}-{index}"),
                },
                fired: index.is_multiple_of(2),
            }),
            2 => Decision::RngDraw(RngDecision {
                stream: RngStreamId {
                    name: format!("node-{seed}/stream-{index}"),
                },
                value: seed.rotate_left((index % 31) as u32) ^ index,
            }),
            3 => Decision::Override(OverrideDecision {
                point: SchedulingPoint {
                    key: format!("point-{seed}-{index}"),
                },
                choice: ChoiceTag {
                    name: format!("choice-{index}"),
                },
            }),
            4 => Decision::Preemption(PreemptionDecision {
                node: NodeId {
                    name: format!("node-{seed}"),
                },
                at: Icount {
                    retired: seed + index + 1,
                },
                kind: PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: 0 },
                    to_vcpu: VcpuId { index: 1 },
                },
            }),
            _ => Decision::AppRandom(AppRandomDecision {
                node: NodeId {
                    name: format!("node-{seed}"),
                },
                stream: RngStreamId {
                    name: format!("app-random-{index}"),
                },
                request_id: index,
                width: 32,
                value: seed.wrapping_mul(0x9e37_79b9) ^ index,
            }),
        }
    }
}

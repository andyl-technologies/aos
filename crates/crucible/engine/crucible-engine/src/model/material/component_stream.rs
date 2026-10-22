//! Borrowed plan, property, and scenario identity material.
//!
//! Renderers visit validated canonical collections without cloning them or
//! constructing per-element strings. Component constructors may hash the
//! stream or reserve one exact lexical buffer before rendering it.

use super::predicate_stream::{Name, PredicateMaterial};
use super::world_stream::Hex;
use super::*;
use std::fmt::{self, Display};

pub(in crate::model) struct PlanMaterial<'a> {
    pub(in crate::model) graph: &'a EventGraph,
    pub(in crate::model) faults: &'a FaultSignalPlan,
}

impl Display for PlanMaterial<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "plan=event-graph\nevents={}",
            self.graph.events().len()
        )?;
        for event in self.graph.events() {
            write!(
                output,
                "\n{}\npolicy={}\n",
                Name("event_id", &event.id.name),
                fire_policy_label(event.policy)
            )?;
            match &event.trigger {
                Some(trigger) => write!(output, "trigger=some\n{}", PredicateMaterial(trigger))?,
                None => output.write_str("trigger=entrypoint")?,
            }
            write!(output, "\naction:\n{}", ActionMaterial(&event.action))?;
        }
        write!(
            output,
            "\nfault-signal-plan={}",
            Hex(&self.faults.id().bytes)
        )
    }
}

struct ActionMaterial<'a>(&'a Action);

impl Display for ActionMaterial<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Action::ArmTimer { name, after } => write!(
                output,
                "action=arm-timer\n{}\nafter_ticks={}",
                Name("timer_id", &name.name),
                after.ticks
            ),
            Action::CancelTimer { name } => write!(
                output,
                "action=cancel-timer\n{}",
                Name("timer_id", &name.name)
            ),
            Action::StartNode { node } => {
                write!(output, "action=start-node\n{}", Name("node", &node.name))
            }
            Action::StopNode { node } => {
                write!(output, "action=stop-node\n{}", Name("node", &node.name))
            }
            Action::CreateSavepoint { label } | Action::Fork { label } => {
                let kind = if matches!(self.0, Action::Fork { .. }) {
                    "fork"
                } else {
                    "create-savepoint"
                };
                writeln!(output, "action={kind}")?;
                match label {
                    Some(label) => write!(output, "label=some\n{}", Name("label", label)),
                    None => output.write_str("label=none"),
                }
            }
            Action::Pass => output.write_str("action=pass"),
            Action::Fail { reason } => write!(output, "action=fail\n{}", Name("reason", reason)),
            Action::Log { level, message } => write!(
                output,
                "action=log\nlevel={}\n{}",
                log_level_label(*level),
                Name("message", message)
            ),
            Action::Group(actions) => {
                write!(output, "action=group\nactions={}", actions.len())?;
                for action in actions {
                    write!(output, "\n{}", ActionMaterial(action))?;
                }
                Ok(())
            }
        }
    }
}

pub(in crate::model) struct PropertiesMaterial<'a>(pub(in crate::model) &'a [AssertionDef]);

impl Display for PropertiesMaterial<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "assertions={}", self.0.len())?;
        for assertion in self.0 {
            write!(
                output,
                "\n{}\n{}\n{}",
                Name("assertion_id", &assertion.id.name),
                Name("message", &assertion.message),
                PropertyMaterial(&assertion.property)
            )?;
        }
        Ok(())
    }
}

struct PropertyMaterial<'a>(&'a Property);

impl Display for PropertyMaterial<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(output, "property={}", self.0.kind().canonical_label())?;
        match self.0 {
            Property::Always { predicate }
            | Property::Sometimes { predicate }
            | Property::AfterQuiescence { predicate } => {
                write!(output, "{}", PredicateMaterial(predicate))
            }
            Property::Eventually {
                trigger,
                property,
                deadline,
            } => write!(
                output,
                "deadline_ticks={}\ntrigger:\n{}\nproperty_predicate:\n{}",
                deadline.ticks,
                PredicateMaterial(trigger),
                PredicateMaterial(property)
            ),
            Property::Reachable {
                predicate,
                expectation,
            } => {
                match expectation {
                    ReachabilityExpectation::Reachable { on_unreached } => write!(
                        output,
                        "expectation=reachable\non_unreached={}\n",
                        reachable_disposition_label(*on_unreached)
                    )?,
                    ReachabilityExpectation::Unreachable => {
                        output.write_str("expectation=unreachable\n")?
                    }
                }
                write!(output, "{}", PredicateMaterial(predicate))
            }
        }
    }
}

pub(in crate::model) struct ScenarioMaterial<'a> {
    pub(in crate::model) world: ContentHash,
    pub(in crate::model) plan: ContentHash,
    pub(in crate::model) properties: ContentHash,
    pub(in crate::model) measurements: &'a MeasurementDefinitions,
    pub(in crate::model) selectables: &'a ScenarioSelectables,
    pub(in crate::model) seed: Seed,
    pub(in crate::model) cap: u64,
}

impl Display for ScenarioMaterial<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "world_ref={}\nplan_ref={}\nproperties_ref={}",
            Hex(&self.world.bytes),
            Hex(&self.plan.bytes),
            Hex(&self.properties.bytes)
        )?;
        if !self.measurements.is_empty() {
            write!(
                output,
                "\nmeasurements_ref={}",
                Hex(&self.measurements.content_hash().bytes)
            )?;
        }
        if !self.selectables.is_default_catalog() {
            write!(
                output,
                "\nselectables_ref={}",
                Hex(&self.selectables.content_hash().bytes)
            )?;
        }
        write!(
            output,
            "\nseed_bytes={}\napp_random_draw_cap={}",
            Hex(&self.seed.bytes()),
            self.cap
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_component_streams_preserve_existing_schema_hashes() -> Result<(), EngineError> {
        let faults = FaultSignalPlan::empty();
        let graph = EventGraph::from_unchecked_events_for_model(Vec::new());
        let plan = PlanMaterial {
            graph: &graph,
            faults: &faults,
        };
        assert_eq!(format!("{plan}"), plan_parts_material(&graph, &faults));
        assert_eq!(
            canonical_plan_hash(&graph, &faults)?,
            empty_plan_hash(&faults)
        );
        assert_eq!(canonical_properties_hash(&[])?, empty_properties_hash());
        Ok(())
    }

    #[test]
    fn predicate_stream_preserves_recursive_text_and_binary_patterns() -> Result<(), EngineError> {
        let predicates = [
            Predicate::At {
                at: VirtualTime { ticks: 7 },
            },
            Predicate::ConsoleMatch {
                node: NodeId { name: "é".into() },
                regex: RegexProgram::from_pattern("水.*"),
            },
            Predicate::NetworkMatch {
                link: Some(LinkId {
                    name: "wire".into(),
                }),
                predicate: FramePredicate::Prefix(vec![0, 0x7f, 0xff]),
            },
            Predicate::MemoryPredicate {
                node: NodeId {
                    name: "memory".into(),
                },
                place: MemPlace::Register {
                    name: "rip".into(),
                    width: MemoryWidth::U64,
                },
                cmp: MemoryCmp::Ne,
                value: 42,
            },
            Predicate::AllOf {
                predicates: vec![
                    Predicate::Quiescent,
                    Predicate::Not {
                        predicate: Box::new(Predicate::Once {
                            predicate: Box::new(Predicate::GuestMarker {
                                marker: MarkerId {
                                    name: "ready".into(),
                                },
                            }),
                        }),
                    },
                ],
            },
        ];
        for predicate in predicates {
            assert_eq!(
                canonical_predicate_material(&predicate)?,
                predicate_material(&predicate)
            );
        }
        Ok(())
    }
}

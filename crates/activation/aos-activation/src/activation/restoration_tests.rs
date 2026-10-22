//! Crash recovery of completed resource prerequisites and suspended repairs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};
use aos_core::Sha256Digest;
use aos_module_format::graph::{CheckedModuleGraph, Effect, identity_key};
use serde_json::{Value, json};

use super::journal::{Event, State};
use super::{
    Action, Activation, ActivationAdapter, Boundary, BoundaryEvent, CancellationToken, Invocation,
    Observation, inspect,
};
use crate::journal::{FileJournal, JournalLimits};

fn fixture() -> (CheckedModuleGraph, Vec<String>) {
    let template = super::tests::graph(Some("template"), "instance");
    let template = serde_json::to_value(template.graph().nodes.values().next().unwrap()).unwrap();
    let identities: Vec<_> = ["one-shot", "mapper", "format", "durable-file", "consumer"]
        .iter()
        .map(|name| vec!["test".to_owned(), "echo".to_owned(), (*name).to_owned()])
        .collect();
    let keys: Vec<_> = identities
        .iter()
        .map(|name| identity_key(name).unwrap())
        .collect();
    let mut nodes = serde_json::Map::new();
    for (index, identity) in identities.iter().enumerate() {
        let mut node = template.clone();
        node["identity"] = json!(identity);
        node["lifetime"] = json!(match index {
            0 => "transaction",
            3 => "persistent",
            _ => "instance",
        });
        node["input"] = match index {
            2 | 4 => {
                let producer = if index == 2 { 1 } else { 2 };
                node["dependencies"] = json!([keys[producer]]);
                json!({"value": {
                    "_type":"aos-effect-output", "identity":identities[producer],
                    "output":"value", "schema":{"kind":"string"}
                }})
            }
            _ => json!({"value":identity.last().unwrap()}),
        };
        let mut semantic = node.as_object().unwrap().clone();
        for field in ["revision", "dependencies", "inputs"] {
            semantic.remove(field);
        }
        node["revision"] =
            json!(Sha256Digest::of_bytes(serde_json::to_vec(&semantic).unwrap()).hex());
        nodes.insert(keys[index].clone(), node);
    }
    let graph = CheckedModuleGraph::decode(
        &serde_json::to_vec(&json!({
            "schema":"aos.activation.graph", "nodes":nodes, "order":keys
        }))
        .unwrap(),
    )
    .unwrap();
    (graph, keys)
}

#[derive(Default)]
struct Machine {
    resources: BTreeMap<String, Value>,
    calls: BTreeMap<String, usize>,
    boundaries: Vec<BoundaryEvent>,
    cut: Option<(String, Boundary)>,
    indeterminate: Option<String>,
    conflicting: Option<String>,
    mapper: String,
    format: String,
}

impl ActivationAdapter for Machine {
    fn retain(&mut self, _: &Effect) -> Result<()> {
        Ok(())
    }

    fn boundary(&mut self, event: &BoundaryEvent, _: &CancellationToken) -> Result<()> {
        self.boundaries.push(event.clone());
        if self
            .cut
            .as_ref()
            .is_some_and(|(id, boundary)| id == &event.effect && boundary == &event.boundary)
        {
            self.cut = None;
            bail!("physical-cut fixture boundary");
        }
        Ok(())
    }

    fn observe(&mut self, invocation: &Invocation, _: &CancellationToken) -> Result<Observation> {
        if invocation.id == self.format {
            ensure!(
                self.resources.contains_key(&self.mapper),
                "format prerequisite is absent"
            );
        }
        if self.indeterminate.as_ref() == Some(&invocation.id) {
            return Ok(Observation::Indeterminate);
        }
        Ok(self
            .resources
            .get(&invocation.id)
            .cloned()
            .map(Observation::Current)
            .unwrap_or(Observation::RetrySafe))
    }

    fn invoke(&mut self, invocation: &Invocation, _: &CancellationToken) -> Result<Value> {
        if invocation.action == Action::Remove {
            self.resources.remove(&invocation.id);
            return Ok(json!({}));
        }
        if invocation.id == self.format {
            ensure!(
                self.resources.contains_key(&self.mapper),
                "format prerequisite is absent"
            );
        }
        *self.calls.entry(invocation.id.clone()).or_default() += 1;
        let output = if self.conflicting.as_ref() == Some(&invocation.id) {
            json!({"value":"conflicting-but-well-typed"})
        } else {
            invocation.input.clone()
        };
        self.resources.insert(invocation.id.clone(), output.clone());
        Ok(output)
    }

    fn release(&mut self, _: &Effect) -> Result<()> {
        Ok(())
    }
}

fn interrupted(path: &std::path::Path) -> (CheckedModuleGraph, Vec<String>, Machine) {
    let (graph, ids) = fixture();
    let mut machine = Machine {
        mapper: ids[1].clone(),
        format: ids[2].clone(),
        cut: Some((ids[4].clone(), Boundary::DispatchReturned)),
        ..Default::default()
    };
    let mut activation = Activation::open(path, JournalLimits::default()).unwrap();
    assert!(
        activation
            .activate_once(
                "original",
                &graph,
                &BTreeSet::new(),
                &mut machine,
                &CancellationToken::default()
            )
            .is_err()
    );
    (graph, ids, machine)
}

#[test]
fn lost_prerequisites_are_restored_without_repeating_the_primary_or_one_shots() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("effects.journal");
    let (graph, ids, mut machine) = interrupted(&path);
    let primary =
        serde_json::to_value(inspect(&path, JournalLimits::default()).unwrap().pending).unwrap();
    machine.resources.remove(&ids[1]);
    machine.resources.remove(&ids[2]);
    machine.boundaries.clear();

    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    assert_eq!(activation.completed_transaction(), None);
    activation
        .activate_once(
            "original",
            &graph,
            &BTreeSet::new(),
            &mut machine,
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(activation.completed_transaction(), Some("original"));
    drop(activation);

    assert_eq!(machine.calls[&ids[0]], 1);
    assert_eq!(machine.calls[&ids[1]], 2);
    assert_eq!(machine.calls[&ids[2]], 2);
    assert_eq!(machine.calls[&ids[3]], 1);
    assert_eq!(machine.calls[&ids[4]], 1);
    let recovered = machine
        .boundaries
        .iter()
        .find(|event| event.effect == ids[4])
        .unwrap();
    assert_eq!(
        json!(recovered.journal_sequence),
        primary["journalSequence"]
    );
    let inspection = inspect(&path, JournalLimits::default()).unwrap();
    assert!(inspection.pending.is_none() && inspection.restoration.is_none());
    assert_eq!(inspection.completed.unwrap().transaction, "original");
}

#[test]
fn a_second_cut_restores_lost_mapper_before_resuming_the_original_format_repair() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("effects.journal");
    let (graph, ids, mut machine) = interrupted(&path);
    let primary =
        serde_json::to_value(inspect(&path, JournalLimits::default()).unwrap().pending).unwrap();
    machine.resources.remove(&ids[1]);
    machine.resources.remove(&ids[2]);
    machine.cut = Some((ids[2].clone(), Boundary::DispatchReturned));
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    assert!(
        activation
            .activate_once(
                "original",
                &graph,
                &BTreeSet::new(),
                &mut machine,
                &CancellationToken::default()
            )
            .is_err()
    );
    drop(activation);
    let cut = inspect(&path, JournalLimits::default()).unwrap();
    let repair = cut.restoration.unwrap();
    assert_eq!(repair.effect, ids[2]);
    assert_eq!(serde_json::to_value(cut.pending).unwrap(), primary);

    machine.resources.remove(&ids[1]);
    machine.resources.remove(&ids[2]);
    machine.cut = Some((ids[1].clone(), Boundary::DispatchReturned));
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    assert!(
        activation
            .activate_once(
                "original",
                &graph,
                &BTreeSet::new(),
                &mut machine,
                &CancellationToken::default()
            )
            .is_err()
    );
    drop(activation);
    let nested = inspect(&path, JournalLimits::default()).unwrap();
    let mapper_repair = nested.restoration.unwrap();
    assert_eq!(mapper_repair.effect, ids[1]);
    assert_eq!(serde_json::to_value(nested.pending).unwrap(), primary);

    machine.resources.remove(&ids[1]);
    machine.resources.remove(&ids[2]);
    machine.boundaries.clear();
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    activation
        .activate_once(
            "original",
            &graph,
            &BTreeSet::new(),
            &mut machine,
            &CancellationToken::default(),
        )
        .unwrap();
    drop(activation);

    let resumed = machine
        .boundaries
        .iter()
        .find(|event| event.effect == ids[2])
        .unwrap();
    assert_eq!(resumed.journal_sequence, repair.journal_sequence);
    let resumed_mapper = machine
        .boundaries
        .iter()
        .find(|event| event.effect == ids[1])
        .unwrap();
    assert_eq!(
        resumed_mapper.journal_sequence,
        mapper_repair.journal_sequence
    );
    assert_eq!(machine.calls[&ids[0]], 1);
    assert_eq!(machine.calls[&ids[1]], 4);
    assert_eq!(machine.calls[&ids[2]], 3);
    assert_eq!(machine.calls[&ids[3]], 1);
    assert_eq!(machine.calls[&ids[4]], 1);
    assert!(
        inspect(&path, JournalLimits::default())
            .unwrap()
            .restoration
            .is_none()
    );
}

#[test]
fn disappeared_persistent_prefix_resources_are_also_restored() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("effects.journal");
    let (graph, ids, mut machine) = interrupted(&path);
    machine.resources.remove(&ids[3]);
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    activation
        .activate_once(
            "original",
            &graph,
            &BTreeSet::new(),
            &mut machine,
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(machine.calls[&ids[3]], 2);
    assert_eq!(machine.calls[&ids[0]], 1);
    assert_eq!(machine.calls[&ids[4]], 1);
}

#[test]
fn resumed_restoration_reserves_outcomes_before_any_live_observation_or_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("effects.journal");
    let (graph, ids, mut machine) = interrupted(&path);
    machine.cut = Some((ids[1].clone(), Boundary::IntentDurable));
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    assert!(
        activation
            .activate_once(
                "original",
                &graph,
                &BTreeSet::new(),
                &mut machine,
                &CancellationToken::default()
            )
            .is_err()
    );
    drop(activation);
    let snapshot = inspect(&path, JournalLimits::default()).unwrap();
    assert!(snapshot.restoration.is_some());
    let limits = JournalLimits {
        max_records: snapshot.records.len() + 1,
        ..JournalLimits::default()
    };
    let bytes = std::fs::read(&path).unwrap();
    let calls = machine.calls.clone();
    machine.boundaries.clear();
    let mut activation = Activation::open(&path, limits).unwrap();
    assert!(
        activation
            .activate_once(
                "original",
                &graph,
                &BTreeSet::new(),
                &mut machine,
                &CancellationToken::default()
            )
            .is_err()
    );
    drop(activation);
    assert!(machine.boundaries.is_empty());
    assert_eq!(machine.calls, calls);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn uncertain_or_conflicting_repairs_leave_original_outputs_and_pending_identity_intact() {
    for conflict in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("effects.journal");
        let (graph, ids, mut machine) = interrupted(&path);
        let before = inspect(&path, JournalLimits::default()).unwrap();
        machine.resources.remove(&ids[1]);
        if conflict {
            machine.conflicting = Some(ids[1].clone());
        } else {
            machine.indeterminate = Some(ids[1].clone());
        }
        let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
        let error = activation
            .activate_once(
                "original",
                &graph,
                &BTreeSet::new(),
                &mut machine,
                &CancellationToken::default(),
            )
            .unwrap_err();
        assert!(error.to_string().contains(if conflict {
            "consumed outputs"
        } else {
            "safely"
        }));
        drop(activation);
        let after = inspect(&path, JournalLimits::default()).unwrap();
        assert_eq!(
            serde_json::to_value(after.pending).unwrap(),
            serde_json::to_value(before.pending).unwrap()
        );
        assert_eq!(after.retained_outputs, before.retained_outputs);
        assert_eq!(after.restoration.unwrap().effect, ids[1]);
        assert_eq!(machine.calls[&ids[4]], 1);
    }
}

#[test]
fn replay_rejects_unfinished_unknown_and_out_of_order_restoration_records() {
    let (graph, ids) = fixture();
    let mut state = State::default();
    state
        .apply(&Event::Begin {
            transaction: "original".into(),
            document: serde_json::from_slice(&graph.canonical_bytes().unwrap()).unwrap(),
            retire: vec![],
        })
        .unwrap();
    let unfinished = state.application(&ids[0]).unwrap();
    assert!(
        state
            .check(&Event::RestorationStarted {
                invocation: Box::new(unfinished.clone())
            })
            .is_err()
    );
    for id in &ids[..4] {
        let invocation = state.application(id).unwrap();
        let outputs = invocation.input.clone();
        state
            .apply(&Event::Started {
                invocation: Box::new(invocation),
            })
            .unwrap();
        state.apply(&Event::Finished { outputs }).unwrap();
    }
    let mapper = state.retained[&ids[1]].invocation.clone();
    state
        .apply(&Event::RestorationStarted {
            invocation: Box::new(mapper.clone()),
        })
        .unwrap();
    let format = state.retained[&ids[2]].invocation.clone();
    assert!(
        state
            .check(&Event::RestorationStarted {
                invocation: Box::new(format)
            })
            .is_err()
    );
    assert!(
        state
            .check(&Event::Started {
                invocation: Box::new(state.application(&ids[4]).unwrap())
            })
            .is_err()
    );
    assert!(state.check(&Event::Commit).is_err());
    assert!(
        state
            .check(&Event::RestorationFinished {
                outputs: json!({"value":"different"})
            })
            .is_err()
    );

    // Well-formed checksummed records cannot nest a later effect under an
    // earlier repair, even when both original outcomes are complete.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("effects.journal");
    let (_, actual_ids, _) = interrupted(&path);
    let inspection = inspect(&path, JournalLimits::default()).unwrap();
    let originals: Vec<_> = [1, 2]
        .into_iter()
        .map(|index| {
            inspection
                .retained_effects()
                .iter()
                .find(|effect| effect.invocation.id == actual_ids[index])
                .unwrap()
                .invocation
                .clone()
        })
        .collect();
    let mut journal = FileJournal::<Event>::open(&path, JournalLimits::default())
        .unwrap()
        .journal;
    journal
        .append(&Event::RestorationStarted {
            invocation: Box::new(originals[0].clone()),
        })
        .unwrap();
    journal
        .append(&Event::RestorationStarted {
            invocation: Box::new(originals[1].clone()),
        })
        .unwrap();
    drop(journal);
    let bytes = std::fs::read(&path).unwrap();
    assert!(Activation::open(&path, JournalLimits::default()).is_err());
    assert!(inspect(&path, JournalLimits::default()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

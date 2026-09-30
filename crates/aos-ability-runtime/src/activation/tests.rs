//! Lifecycle and recovery tests for the module activation boundary.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use aos_ability_plan::module_graph::{CheckedModuleGraph, Effect, identity_key};
use aos_contract::Sha256Digest;
use serde_json::{Value, json};

use super::*;
use crate::journal::JournalLimits;

fn graph(value: Option<&str>, lifetime: &str) -> CheckedModuleGraph {
    let mut nodes = serde_json::Map::new();
    let mut order = Vec::new();
    if let Some(value) = value {
        let identity = vec!["test".to_owned(), "echo".to_owned(), "main".to_owned()];
        let id = identity_key(&identity).unwrap();
        let mut node = json!({
            "identity": identity,
            "input": {"value": value},
            "inputs": {},
            "input_type": {"kind": "submodule", "open": false, "fields": {"value": {"kind": "string"}}},
            "after": [],
            "results": {"value": {"kind": "string"}},
            "handler": {
                "kind": "process",
                "artifact": "/nix/store/00000000000000000000000000000000-handler",
                "executable": "/nix/store/00000000000000000000000000000000-handler/bin/handler"
            },
            "lifetime": lifetime,
            "timeout_ms": 1000
        });
        let mut semantic = node.clone();
        semantic.as_object_mut().unwrap().remove("inputs");
        let revision = Sha256Digest::of_bytes(serde_json::to_vec(&semantic).unwrap()).hex();
        node["revision"] = revision.into();
        node["dependencies"] = json!([]);
        nodes.insert(id.clone(), node);
        order.push(id);
    }
    CheckedModuleGraph::decode(
        &serde_json::to_vec(&json!({
            "schema": "aos.activation.graph", "nodes": nodes, "order": order
        }))
        .unwrap(),
    )
    .unwrap()
}

#[derive(Default)]
struct Host {
    resources: BTreeMap<String, Value>,
    mutations: Vec<Action>,
    previous: Vec<Option<PreviousState>>,
    interrupt: bool,
    uncertain: bool,
    invalid_output: bool,
}

impl ActivationAdapter for Host {
    fn retain(&mut self, _: &Effect) -> Result<()> {
        Ok(())
    }

    fn observe(&mut self, invocation: &Invocation, _: &CancellationToken) -> Result<Observation> {
        if self.uncertain {
            return Ok(Observation::Indeterminate);
        }
        Ok(match self.resources.get(&invocation.id) {
            Some(value) => Observation::Current(value.clone()),
            None => Observation::Absent,
        })
    }

    fn invoke(&mut self, invocation: &Invocation, _: &CancellationToken) -> Result<Value> {
        self.mutations.push(invocation.action);
        self.previous.push(invocation.previous.clone());
        let output = match invocation.action {
            Action::Apply => {
                let output = if self.invalid_output {
                    json!({"value": 42})
                } else {
                    invocation.input.clone()
                };
                self.resources.insert(invocation.id.clone(), output.clone());
                output
            }
            Action::Remove => {
                self.resources.remove(&invocation.id);
                json!({})
            }
        };
        if std::mem::take(&mut self.interrupt) {
            bail!("simulated loss of handler completion");
        }
        Ok(output)
    }

    fn release(&mut self, _: &Effect) -> Result<()> {
        Ok(())
    }
}

#[test]
fn converges_observes_and_updates_without_tearing_down_state() {
    let directory = tempfile::tempdir().unwrap();
    let mut activation =
        Activation::open(directory.path().join("journal"), JournalLimits::default()).unwrap();
    let mut host = Host::default();
    let cancellation = CancellationToken::default();
    let initial = graph(Some("first"), "instance");

    activation
        .activate(&initial, &BTreeSet::new(), &mut host, &cancellation)
        .unwrap();
    activation
        .activate(&initial, &BTreeSet::new(), &mut host, &cancellation)
        .unwrap();
    activation
        .activate(
            &graph(Some("second"), "instance"),
            &BTreeSet::new(),
            &mut host,
            &cancellation,
        )
        .unwrap();

    assert_eq!(host.mutations, [Action::Apply, Action::Apply]);
    assert_eq!(
        host.previous[1].as_ref().unwrap().outputs,
        json!({"value": "first"})
    );
    assert_eq!(
        activation.retained().values().next().unwrap(),
        &json!({"value": "second"})
    );
}

#[test]
fn observes_interrupted_mutation_after_reopening_without_repeating_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let desired = graph(Some("first"), "instance");
    let mut host = Host {
        interrupt: true,
        ..Host::default()
    };
    let cancellation = CancellationToken::default();
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    assert!(
        activation
            .activate(&desired, &BTreeSet::new(), &mut host, &cancellation)
            .is_err()
    );
    drop(activation);

    let mut recovered = Activation::open(&path, JournalLimits::default()).unwrap();
    recovered
        .activate(&desired, &BTreeSet::new(), &mut host, &cancellation)
        .unwrap();

    assert_eq!(host.mutations, [Action::Apply]);
    assert_eq!(recovered.retained(), host.resources);
}

#[test]
fn uncertain_recovery_and_invalid_results_never_commit() {
    for invalid_output in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
        let desired = graph(Some("first"), "instance");
        let cancellation = CancellationToken::default();
        let mut host = Host {
            interrupt: !invalid_output,
            invalid_output,
            uncertain: true,
            ..Host::default()
        };

        assert!(
            activation
                .activate(&desired, &BTreeSet::new(), &mut host, &cancellation)
                .is_err()
        );
        drop(activation);
        let mut recovered = Activation::open(&path, JournalLimits::default()).unwrap();
        assert!(
            recovered
                .activate(&desired, &BTreeSet::new(), &mut host, &cancellation)
                .is_err()
        );

        assert!(recovered.retained().is_empty());
        assert_eq!(host.mutations, [Action::Apply]);
    }
}

#[test]
fn lifetimes_control_teardown_and_persistent_retirement() {
    for lifetime in ["transaction", "instance", "persistent"] {
        let directory = tempfile::tempdir().unwrap();
        let mut activation =
            Activation::open(directory.path().join("journal"), JournalLimits::default()).unwrap();
        let desired = graph(Some("first"), lifetime);
        let mut host = Host::default();
        let cancellation = CancellationToken::default();
        activation
            .activate(&desired, &BTreeSet::new(), &mut host, &cancellation)
            .unwrap();
        assert_eq!(activation.retained().is_empty(), lifetime == "transaction");

        let empty = graph(None, lifetime);
        activation
            .activate(&empty, &BTreeSet::new(), &mut host, &cancellation)
            .unwrap();
        assert_eq!(activation.retained().is_empty(), lifetime != "persistent");
        if lifetime == "persistent" {
            let retire = desired.graph().nodes.keys().cloned().collect();
            activation
                .activate(&empty, &retire, &mut host, &cancellation)
                .unwrap();
        }

        assert!(activation.retained().is_empty());
        assert!(host.resources.is_empty());
        assert_eq!(host.mutations, [Action::Apply, Action::Remove]);
    }
}

#[test]
fn transaction_recovery_does_not_repeat_completed_work() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let desired = graph(Some("first"), "transaction");
    let mut host = Host {
        interrupt: true,
        ..Host::default()
    };
    let cancellation = CancellationToken::default();
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    assert!(
        activation
            .activate(&desired, &BTreeSet::new(), &mut host, &cancellation)
            .is_err()
    );
    drop(activation);

    let mut recovered = Activation::open(&path, JournalLimits::default()).unwrap();
    let results = recovered
        .activate(&desired, &BTreeSet::new(), &mut host, &cancellation)
        .unwrap();

    assert_eq!(host.mutations, [Action::Apply, Action::Remove]);
    assert_eq!(results.values().next().unwrap(), &json!({"value": "first"}));
    assert!(recovered.retained().is_empty());
}

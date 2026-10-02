//! Lifecycle and recovery tests for the module activation boundary.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use aos_ability_plan::module_graph::{CheckedModuleGraph, Effect, identity_key};
use aos_contract::Sha256Digest;
use serde_json::{Value, json};

use super::*;
use crate::journal::JournalLimits;

pub(super) fn graph(value: Option<&str>, lifetime: &str) -> CheckedModuleGraph {
    let mut nodes = serde_json::Map::new();
    let mut order = Vec::new();
    if let Some(value) = value {
        let identity = vec!["test".to_owned(), "echo".to_owned(), "main".to_owned()];
        let id = identity_key(&identity).unwrap();
        let mut node = json!({
            "identity": identity,
            "owner": "@environment",
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
pub(super) struct Host {
    resources: BTreeMap<String, Value>,
    mutations: Vec<Action>,
    previous: Vec<Option<PreviousState>>,
    interrupt: bool,
    uncertain: bool,
    invalid_output: bool,
    interrupt_release: bool,
    releases: usize,
    boundaries: Vec<BoundaryEvent>,
    pub(super) halt_boundary: Option<Boundary>,
}

impl ActivationAdapter for Host {
    fn boundary(&mut self, event: &BoundaryEvent, _: &CancellationToken) -> Result<()> {
        self.boundaries.push(event.clone());
        if self.halt_boundary == Some(event.boundary) {
            bail!("observer requested interruption");
        }
        Ok(())
    }

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
        self.releases += 1;
        if std::mem::take(&mut self.interrupt_release) {
            bail!("simulated artifact cleanup failure");
        }
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

#[test]
fn artifact_cleanup_is_retried_after_durable_teardown() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    let mut host = Host::default();
    let cancellation = CancellationToken::default();
    activation
        .activate(
            &graph(Some("first"), "instance"),
            &BTreeSet::new(),
            &mut host,
            &cancellation,
        )
        .unwrap();

    host.interrupt_release = true;
    let empty = graph(None, "instance");
    assert!(
        activation
            .activate(&empty, &BTreeSet::new(), &mut host, &cancellation)
            .is_err()
    );
    assert!(host.resources.is_empty());
    drop(activation);

    let mut recovered = Activation::open(&path, JournalLimits::default()).unwrap();
    recovered
        .activate(&empty, &BTreeSet::new(), &mut host, &cancellation)
        .unwrap();

    assert_eq!(host.releases, 2);
    assert_eq!(host.mutations, [Action::Apply, Action::Remove]);
    assert!(recovered.retained().is_empty());
}

#[test]
fn documentation_changes_preserve_the_effect_revision() {
    let initial = graph(Some("first"), "instance");
    let id = initial.graph().order[0].clone();
    let mut document: Value = serde_json::from_slice(&initial.canonical_bytes().unwrap()).unwrap();
    document["nodes"][&id]["inputs"] = json!({
        "value": {"description": "An improved description.", "type": {"kind": "string"}}
    });
    let revised = CheckedModuleGraph::decode(&serde_json::to_vec(&document).unwrap()).unwrap();

    assert_eq!(
        initial.graph().nodes[&id].revision,
        revised.graph().nodes[&id].revision
    );
    assert_ne!(
        initial.canonical_bytes().unwrap(),
        revised.canonical_bytes().unwrap()
    );
}

#[test]
fn graph_boundary_rejects_inconsistent_content_and_execution_order() {
    let initial = graph(Some("first"), "instance");
    let id = initial.graph().order[0].clone();
    let original: Value = serde_json::from_slice(&initial.canonical_bytes().unwrap()).unwrap();

    let mut changed_content = original.clone();
    changed_content["nodes"][&id]["input"]["value"] = json!("tampered");
    assert!(CheckedModuleGraph::decode(&serde_json::to_vec(&changed_content).unwrap()).is_err());

    let mut omitted_node = original.clone();
    omitted_node["order"] = json!([]);
    assert!(CheckedModuleGraph::decode(&serde_json::to_vec(&omitted_node).unwrap()).is_err());

    let mut duplicate_node = original;
    duplicate_node["order"] = json!([id, id]);
    assert!(CheckedModuleGraph::decode(&serde_json::to_vec(&duplicate_node).unwrap()).is_err());
}

#[test]
fn caller_transaction_receipt_survives_generation_commit_interruption() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let desired = graph(Some("once"), "transaction");
    let cancellation = CancellationToken::default();
    let mut host = Host::default();
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    let first = activation
        .activate_once(
            "generation-1",
            &desired,
            &BTreeSet::new(),
            &mut host,
            &cancellation,
        )
        .unwrap();
    drop(activation);

    let mut recovered = Activation::open(&path, JournalLimits::default()).unwrap();
    let repeated = recovered
        .activate_once(
            "generation-1",
            &desired,
            &BTreeSet::new(),
            &mut host,
            &cancellation,
        )
        .unwrap();
    assert_eq!(first, repeated);
    assert_eq!(host.mutations, [Action::Apply, Action::Remove]);

    recovered
        .activate_once(
            "generation-2",
            &desired,
            &BTreeSet::new(),
            &mut host,
            &cancellation,
        )
        .unwrap();
    assert_eq!(
        host.mutations,
        [Action::Apply, Action::Remove, Action::Apply, Action::Remove]
    );
}

#[test]
fn observer_interruption_after_dispatch_recovers_the_same_durable_intent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("activation.journal");
    let desired = graph(Some("value"), "instance");
    let mut host = Host {
        halt_boundary: Some(Boundary::DispatchReturned),
        ..Host::default()
    };
    let cancellation = CancellationToken::default();
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();

    assert!(
        activation
            .activate_once(
                "generation-1",
                &desired,
                &BTreeSet::new(),
                &mut host,
                &cancellation
            )
            .is_err()
    );
    assert_eq!(host.mutations.len(), 1);
    let intent = host.boundaries[0].journal_sequence;
    drop(activation);

    host.halt_boundary = None;
    let mut recovered = Activation::open(&path, JournalLimits::default()).unwrap();
    recovered
        .activate_once(
            "generation-1",
            &desired,
            &BTreeSet::new(),
            &mut host,
            &cancellation,
        )
        .unwrap();

    assert_eq!(host.mutations.len(), 1);
    assert!(
        host.boundaries
            .iter()
            .any(|event| event.boundary == Boundary::ObservationStarted)
    );
    assert!(
        host.boundaries
            .iter()
            .all(|event| event.journal_sequence == intent)
    );
    assert_eq!(
        host.boundaries.last().unwrap().boundary,
        Boundary::OutcomeDurable
    );
    let wire = serde_json::to_value(host.boundaries.last().unwrap()).unwrap();
    assert!(wire.get("input").is_none());
    assert!(wire.get("outputs").is_none());
}

#[test]
fn observer_failure_after_durable_outcome_does_not_repeat_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("activation.journal");
    let desired = graph(Some("value"), "instance");
    let cancellation = CancellationToken::default();
    let mut host = Host {
        halt_boundary: Some(Boundary::OutcomeDurable),
        ..Host::default()
    };
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();

    assert!(
        activation
            .activate_once(
                "generation-1",
                &desired,
                &BTreeSet::new(),
                &mut host,
                &cancellation
            )
            .is_err()
    );
    drop(activation);
    host.halt_boundary = None;
    let mut recovered = Activation::open(&path, JournalLimits::default()).unwrap();
    recovered
        .activate_once(
            "generation-1",
            &desired,
            &BTreeSet::new(),
            &mut host,
            &cancellation,
        )
        .unwrap();
    assert_eq!(host.mutations.len(), 1);
}

#[test]
fn dispatch_attempt_boundary_precedes_handler_and_survives_failure() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("activation.journal");
    let desired = graph(Some("value"), "instance");
    let cancellation = CancellationToken::default();
    let mut host = Host {
        halt_boundary: Some(Boundary::DispatchStarted),
        ..Host::default()
    };
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    assert!(
        activation
            .activate_once(
                "first",
                &desired,
                &BTreeSet::new(),
                &mut host,
                &cancellation
            )
            .is_err()
    );
    assert!(host.mutations.is_empty());
    let intent = host.boundaries.last().unwrap().journal_sequence;
    assert_eq!(
        host.boundaries.last().unwrap().boundary,
        Boundary::DispatchStarted
    );
    drop(activation);

    host.halt_boundary = None;
    let mut recovered = Activation::open(&path, JournalLimits::default()).unwrap();
    assert!(
        recovered
            .activate_once(
                "first",
                &desired,
                &BTreeSet::new(),
                &mut host,
                &cancellation
            )
            .is_err()
    );
    assert!(host.mutations.is_empty());
    assert!(
        host.boundaries
            .iter()
            .all(|event| event.journal_sequence == intent)
    );

    // A failed handler call still emits its attempt boundary, without a return.
    let mut failed = Host {
        interrupt: true,
        ..Host::default()
    };
    let mut fresh = Activation::open(
        directory.path().join("failed.journal"),
        JournalLimits::default(),
    )
    .unwrap();
    assert!(
        fresh
            .activate_once(
                "second",
                &desired,
                &BTreeSet::new(),
                &mut failed,
                &cancellation
            )
            .is_err()
    );
    assert_eq!(failed.mutations.len(), 1);
    assert_eq!(
        failed
            .boundaries
            .iter()
            .filter(|event| event.boundary == Boundary::DispatchStarted)
            .count(),
        1
    );
    assert!(
        !failed
            .boundaries
            .iter()
            .any(|event| event.boundary == Boundary::DispatchReturned)
    );
}

#[test]
fn declarative_retirement_is_repeatable_but_unknown_identities_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let cancellation = CancellationToken::default();
    let desired = graph(Some("value"), "persistent");
    let absent = graph(None, "persistent");
    let retire: BTreeSet<_> = desired.graph().nodes.keys().cloned().collect();
    let mut host = Host::default();
    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    activation
        .activate(&desired, &BTreeSet::new(), &mut host, &cancellation)
        .unwrap();
    activation
        .activate(&absent, &retire, &mut host, &cancellation)
        .unwrap();
    drop(activation);

    let mut activation = Activation::open(&path, JournalLimits::default()).unwrap();
    activation
        .activate(&absent, &retire, &mut host, &cancellation)
        .unwrap();
    assert_eq!(activation.retired(), &retire);
    assert_eq!(host.mutations, [Action::Apply, Action::Remove]);
    assert!(
        activation
            .activate(
                &absent,
                &BTreeSet::from(["unknown".into()]),
                &mut host,
                &cancellation
            )
            .is_err()
    );

    activation
        .activate(&desired, &BTreeSet::new(), &mut host, &cancellation)
        .unwrap();
    assert!(activation.retired().is_empty());
    assert!(
        activation
            .activate(&desired, &retire, &mut host, &cancellation)
            .is_err()
    );
}

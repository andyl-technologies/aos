//! Native controller checks shared by the candidate's qualification helpers.
//!
//! These checks exercise framework ordering with an explicit in-memory adapter.
//! They do not claim that any package handler or live domain resource was
//! verified. Domain qualification retains independent production flight oracles.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_plan::module_graph::{CheckedModuleGraph, Effect, identity_key};
use aos_ability_runtime::activation::{
    Activation, ActivationAdapter, Boundary, BoundaryEvent, Invocation, Observation, inspect,
};
use aos_ability_runtime::adapter::CancellationToken;
use aos_ability_runtime::journal::JournalLimits;
use aos_contract::{Sha256Digest, canonical};
use serde_json::{Value, json};

/// Selects the native framework invariants tested by a qualification helper.
pub(super) enum AuditKind {
    /// Checks preflight rejection, cancellation, and invalid outcomes.
    Admission,
    /// Checks exact-intent recovery and read-only durable inspection.
    Recovery,
}

/// Executes native framework checks and writes their actual durable observations.
///
/// # Errors
/// Returns an error for invalid arguments, an existing state directory, failed
/// invariants, invalid native graphs, or journal and output I/O errors.
pub(super) fn run(kind: AuditKind) -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [output_flag, output, state_flag, state] = arguments.as_slice() else {
        bail!("expected --output OUTPUT --state-directory PRIVATE_DIRECTORY");
    };
    ensure!(
        output_flag == "--output" && state_flag == "--state-directory",
        "unexpected native audit arguments"
    );
    let root = PathBuf::from(state);
    ensure!(
        !root.exists(),
        "native audit state directory already exists"
    );
    fs::create_dir_all(&root).context("creating native audit state directory")?;
    let desired = graph()?;
    let checks = match kind {
        AuditKind::Admission => admission_checks(&root, &desired)?,
        AuditKind::Recovery => recovery_checks(&root, &desired)?,
    };
    let bytes = canonical::to_vec(&json!({
        "schema": "aos.qualification.native-runtime-audit",
        "framework": "activation",
        "liveStateVerified": false,
        "graph": desired.graph(),
        "checks": checks,
    }))?;
    fs::write(output, bytes).context("writing native framework audit")
}

fn graph() -> Result<CheckedModuleGraph> {
    let identity = vec![
        "nativeAudit".to_owned(),
        "echo".to_owned(),
        "example".to_owned(),
    ];
    let id = identity_key(&identity)?;
    let mut node = json!({
        "identity": identity,
        "owner": "@environment",
        "input": {"value": "native-framework-fixture"},
        "inputs": {},
        "input_type": {"kind":"submodule","open":false,"fields":{"value":{"kind":"string"}}},
        "after": [],
        "results": {"value":{"kind":"string"}},
        "handler": {"kind":"process","artifact":"/nix/store/00000000000000000000000000000000-native-audit","executable":"/nix/store/00000000000000000000000000000000-native-audit/bin/echo"},
        "lifetime":"instance",
        "timeout_ms":1000,
    });
    let mut semantic = node.clone();
    semantic
        .as_object_mut()
        .context("native audit graph node must be an object")?
        .remove("inputs");
    node["revision"] = Sha256Digest::of_bytes(&canonical::to_vec(&semantic)?)
        .hex()
        .into();
    node["dependencies"] = json!([]);
    CheckedModuleGraph::decode(&canonical::to_vec(
        &json!({"schema":"aos.activation.graph","nodes":{id.clone():node},"order":[id]}),
    )?)
}

#[derive(Default)]
struct FrameworkAdapter {
    resources: BTreeMap<String, Value>,
    mutations: usize,
    observations: usize,
    reject_retention: bool,
    invalid_output: bool,
    indeterminate: bool,
    halt: Option<Boundary>,
    boundaries: Vec<BoundaryEvent>,
}

impl ActivationAdapter for FrameworkAdapter {
    fn boundary(&mut self, event: &BoundaryEvent, _: &CancellationToken) -> Result<()> {
        self.boundaries.push(event.clone());
        if self.halt == Some(event.boundary) {
            bail!("native audit interruption");
        }
        Ok(())
    }

    fn retain(&mut self, _: &Effect) -> Result<()> {
        ensure!(
            !self.reject_retention,
            "native audit rejected artifact admission"
        );
        Ok(())
    }

    fn observe(&mut self, invocation: &Invocation, _: &CancellationToken) -> Result<Observation> {
        self.observations += 1;
        if self.indeterminate {
            return Ok(Observation::Indeterminate);
        }
        Ok(self
            .resources
            .get(&invocation.id)
            .map_or(Observation::Absent, |value| {
                Observation::Current(value.clone())
            }))
    }

    fn invoke(&mut self, invocation: &Invocation, _: &CancellationToken) -> Result<Value> {
        self.mutations += 1;
        let value = if self.invalid_output {
            json!({"value":17})
        } else {
            invocation.input.clone()
        };
        self.resources.insert(invocation.id.clone(), value.clone());
        Ok(value)
    }

    fn release(&mut self, _: &aos_ability_plan::module_graph::Effect) -> Result<()> {
        Ok(())
    }
}

fn admission_checks(root: &Path, desired: &CheckedModuleGraph) -> Result<Value> {
    let cancellation = CancellationToken::default();
    let mut adapter = FrameworkAdapter {
        reject_retention: true,
        ..Default::default()
    };
    let retention = root.join("retention.journal");
    let mut activation = Activation::open(&retention, JournalLimits::default())?;
    ensure!(
        activation
            .activate_once(
                "retention",
                desired,
                &BTreeSet::new(),
                &mut adapter,
                &cancellation
            )
            .is_err(),
        "retention rejection did not stop activation"
    );
    drop(activation);
    let rejected = inspect(&retention, JournalLimits::default())?;
    ensure!(
        adapter.mutations == 0 && rejected.records.is_empty(),
        "rejected artifact produced a durable dispatch"
    );

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut adapter = FrameworkAdapter::default();
    let path = root.join("cancelled.journal");
    let mut activation = Activation::open(&path, JournalLimits::default())?;
    ensure!(
        activation
            .activate_once(
                "cancelled",
                desired,
                &BTreeSet::new(),
                &mut adapter,
                &cancelled
            )
            .is_err(),
        "cancelled activation succeeded"
    );
    ensure!(
        adapter.mutations == 0,
        "cancelled activation dispatched a handler"
    );
    drop(activation);

    let mut adapter = FrameworkAdapter {
        invalid_output: true,
        ..Default::default()
    };
    let path = root.join("invalid-output.journal");
    let mut activation = Activation::open(&path, JournalLimits::default())?;
    ensure!(
        activation
            .activate_once(
                "invalid-output",
                desired,
                &BTreeSet::new(),
                &mut adapter,
                &cancellation
            )
            .is_err(),
        "invalid operation output was committed"
    );
    drop(activation);
    let invalid = inspect(&path, JournalLimits::default())?;
    ensure!(
        invalid.pending.is_some() && invalid.completed.is_none(),
        "invalid output became a checked durable outcome"
    );
    Ok(
        json!({"retentionBeforeIntent":rejected,"cancelledBeforeDispatch":inspect(root.join("cancelled.journal"),JournalLimits::default())?,"invalidOutcomeRemainsPending":invalid}),
    )
}

fn recovery_checks(root: &Path, desired: &CheckedModuleGraph) -> Result<Value> {
    let cancellation = CancellationToken::default();
    let path = root.join("recovery.journal");
    let mut adapter = FrameworkAdapter {
        halt: Some(Boundary::DispatchReturned),
        ..Default::default()
    };
    let mut activation = Activation::open(&path, JournalLimits::default())?;
    ensure!(
        activation
            .activate_once(
                "recovery",
                desired,
                &BTreeSet::new(),
                &mut adapter,
                &cancellation
            )
            .is_err(),
        "interruption did not stop activation"
    );
    drop(activation);
    let bytes = fs::read(&path)?;
    let pending = inspect(&path, JournalLimits::default())?;
    ensure!(
        pending.pending.is_some() && fs::read(&path)? == bytes,
        "inspection changed interrupted native journal"
    );

    adapter.halt = None;
    adapter.indeterminate = true;
    let mut activation = Activation::open(&path, JournalLimits::default())?;
    ensure!(
        activation
            .activate_once(
                "recovery",
                desired,
                &BTreeSet::new(),
                &mut adapter,
                &cancellation
            )
            .is_err(),
        "indeterminate observation permitted replay"
    );
    ensure!(
        adapter.mutations == 1,
        "indeterminate recovery mutated the resource"
    );
    drop(activation);
    let indeterminate = inspect(&path, JournalLimits::default())?;
    ensure!(
        indeterminate.pending.as_ref().map(|item| (
            &item.effect,
            &item.revision,
            item.journal_sequence
        )) == pending.pending.as_ref().map(|item| (
            &item.effect,
            &item.revision,
            item.journal_sequence
        )),
        "uncertain recovery changed its retained intent"
    );

    adapter.indeterminate = false;
    let mut activation = Activation::open(&path, JournalLimits::default())?;
    activation.activate_once(
        "recovery",
        desired,
        &BTreeSet::new(),
        &mut adapter,
        &cancellation,
    )?;
    drop(activation);
    let completed = inspect(&path, JournalLimits::default())?;
    ensure!(
        adapter.mutations == 1
            && adapter.observations >= 2
            && completed.pending.is_none()
            && completed.completed.is_some(),
        "recovery repeated or failed to commit the existing resource"
    );
    Ok(
        json!({"pendingExactIntent":pending,"uncertainObservationDoesNotReplay":indeterminate,"recoveredCurrentOutcome":completed,"boundaries":adapter.boundaries,"handlerMutationCount":adapter.mutations}),
    )
}

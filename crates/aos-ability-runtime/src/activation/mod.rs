//! Durable activation of bound graphs emitted by native Nix modules.
//!
//! The controller reuses the shared checksummed journal. Handler programs remain
//! behind an adapter that authenticates and retains artifacts before execution.
//! Interrupted mutations are observed before they can be retried. Configuration
//! removal retires instance state in reverse dependency order; persistent state
//! requires an explicit retirement decision.

mod controller;
mod inspection;
mod journal;
mod observer;
#[cfg(target_os = "linux")]
mod socket_observer;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod restoration_tests;

use std::collections::{BTreeMap, BTreeSet};

use crate::adapter::CancellationToken;
use anyhow::Result;
use aos_ability_plan::module_graph::Effect;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use controller::Activation;
pub use inspection::{
    ActivationInspection, ActivationObservation, CompletedTransaction, DispatchIdentity,
    InspectionRecord, RetainedEffect, inspect, observe,
};
pub use observer::{Boundary, BoundaryEvent, BoundaryObserver};
#[cfg(target_os = "linux")]
pub use socket_observer::SocketBoundaryObserver;

/// Selects the mutation performed by a terminal handler.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Establishes or updates the exact requested state.
    Apply,
    /// Releases the exact state previously established by this operation.
    Remove,
}

/// Carries the exact, retained context for a handler invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    /// Identifies the logical effect independently of its current revision.
    pub id: String,
    /// Contains the selected implementation and operation contract.
    pub effect: Effect,
    /// Contains fully materialized arguments; no deferred references remain.
    pub input: Value,
    /// Identifies the operation and its resolved inputs for replay and reuse.
    pub revision: String,
    /// Distinguishes convergence from teardown.
    pub action: Action,
    /// Supplies retained state to an updating handler without deleting it first.
    pub previous: Option<PreviousState>,
}

/// Supplies bounded migration context when input or handler content changes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousState {
    /// Retains the prior implementation and its typed contract.
    pub effect: Effect,
    /// Contains the previous concrete arguments.
    pub input: Value,
    /// Contains the previous checked results.
    pub outputs: Value,
    /// Identifies the previously established semantic state.
    pub revision: String,
}

/// Reports what an implementation can establish about a retained invocation.
#[derive(Clone, Debug)]
pub enum Observation {
    /// The requested state exists, with these checked results.
    Current(Value),
    /// Teardown has completed and the resource no longer exists.
    Absent,
    /// The handler establishes that replaying the exact invocation is safe.
    RetrySafe,
    /// Available evidence cannot establish a safe continuation.
    Indeterminate,
}

/// Implements admitted, bounded operations against the actual host.
///
/// Implementations authenticate the selected artifact and retain its closure
/// until release. Calls must honor `effect.timeout_ms`; errors after dispatch
/// leave an indeterminate mutation that must be observed on the next attempt.
pub trait ActivationAdapter {
    /// Acknowledges optional instrumentation at an execution boundary.
    ///
    /// # Errors
    /// Returns an error to stop execution while preserving the journal state.
    fn boundary(
        &mut self,
        _event: &BoundaryEvent,
        _cancellation: &CancellationToken,
    ) -> Result<()> {
        Ok(())
    }

    /// Authenticates and retains an exact handler artifact before any mutation.
    ///
    /// # Errors
    /// Returns an error if the artifact is unauthorized, unavailable, or cannot
    /// be retained for recovery.
    fn retain(&mut self, effect: &Effect) -> Result<()>;

    /// Authenticates and retains a complete preflight inventory.
    ///
    /// Implementations may share artifact authentication within this call, but
    /// must retain each effect independently. This does not authorize a later
    /// dispatch without its own live artifact check.
    ///
    /// # Errors
    /// Returns an error when any handler cannot be authenticated or retained.
    fn retain_batch(&mut self, effects: &[&Effect]) -> Result<()> {
        for effect in effects {
            self.retain(effect)?;
        }
        Ok(())
    }

    /// Observes the exact invocation without blindly repeating its mutation.
    ///
    /// # Errors
    /// Returns an error if observation fails or its deadline expires.
    fn observe(
        &mut self,
        invocation: &Invocation,
        cancellation: &CancellationToken,
    ) -> Result<Observation>;

    /// Executes one admitted invocation and returns its named results.
    ///
    /// # Errors
    /// Returns an error for handler failure, timeout, or indeterminate completion.
    fn invoke(
        &mut self,
        invocation: &Invocation,
        cancellation: &CancellationToken,
    ) -> Result<Value>;

    /// Idempotently releases recovery retention after durable teardown or replacement.
    ///
    /// # Errors
    /// Returns an error if the retained artifact cannot be released.
    fn release(&mut self, effect: &Effect) -> Result<()>;
}

/// Returns the typed results produced by a complete activation transaction.
pub type ActivationResults = BTreeMap<String, Value>;

/// Limits execution to the environment currently available to the caller.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionPolicy {
    /// Executes every configured operation and authorized teardown.
    #[default]
    Complete,
    /// Establishes installation resources while retaining pending startup work.
    Installation,
}

/// Reports actual operation results separately from unexecuted desired work.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationOutcome {
    /// Contains only schema-checked outcomes from completed operations.
    pub outputs: ActivationResults,
    /// Names configured operations delayed until startup, including consumers.
    pub deferred: BTreeSet<String>,
}

impl ExecutionPolicy {
    /// Computes the receipt identity for a checked graph, retirement, and policy.
    ///
    /// # Errors
    /// Returns an error if canonical graph or receipt encoding fails.
    pub fn content_identity(
        self,
        graph: &aos_ability_plan::module_graph::CheckedModuleGraph,
        retire: &BTreeSet<String>,
    ) -> Result<String> {
        let retirement: Vec<_> = retire.iter().cloned().collect();
        journal::policy_fingerprint(graph, &retirement, self)
    }

    /// Computes the checked dependency closure awaiting startup under this policy.
    #[must_use]
    pub fn deferred_effects(
        self,
        graph: &aos_ability_plan::module_graph::CheckedModuleGraph,
    ) -> BTreeSet<String> {
        let mut deferred = BTreeSet::new();
        if self == Self::Installation {
            for id in &graph.graph().order {
                let effect = &graph.graph().nodes[id];
                if effect.phase == aos_ability_plan::module_graph::ExecutionPhase::Startup
                    || effect
                        .dependencies
                        .iter()
                        .any(|dependency| deferred.contains(dependency))
                {
                    deferred.insert(id.clone());
                }
            }
        }
        deferred
    }
}

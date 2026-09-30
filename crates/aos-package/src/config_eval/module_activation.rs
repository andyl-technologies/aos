//! Derivation-backed handler transport for module activation graphs.
//!
//! A handler receives `apply`, `remove`, or `observe` as its sole argument and
//! one serialized invocation on standard input. Mutation responses contain the
//! named output object. Observation responses use this tagged format:
//!
//! ```json
//! {"status":"current","outputs":{"value":"observed value"}}
//! ```
//!
//! Other observation statuses are `absent`, `retry-safe`, and `indeterminate`.
//! Artifact admission and durable store retention belong to the host's package
//! store; subprocess limits and cancellation reuse the native handler transport.

use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use aos_ability_plan::module_graph::{Effect, Handler};
use aos_ability_runtime::activation::{Action, ActivationAdapter, Invocation, Observation};
use aos_ability_runtime::adapter::{CancellationToken, RuntimeControl};
use aos_contract::limits::{BoundedWriter, JsonLimits};
use serde::Deserialize;
use serde_json::Value;

use super::handler_process::run_bounded;

const MESSAGE_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 256 * 1024,
    max_depth: 64,
    max_items: 65_536,
    max_string_bytes: 128 * 1024,
};

/// Admits and durably retains handler outputs in the host's package store.
///
/// Retention must be idempotent and survive process restart. Implementations
/// verify the selected artifact against authenticated deployment inputs before
/// retaining its closure, including any prior implementation needed for updates.
pub trait HandlerArtifacts {
    /// Authenticates a bound handler and retains its recovery closure.
    ///
    /// # Errors
    /// Returns an error for unauthorized or unavailable artifacts or failed roots.
    fn retain(&mut self, effect: &Effect) -> Result<()>;

    /// Releases a handler's recovery root after durable teardown.
    ///
    /// # Errors
    /// Returns an error if the package store cannot release the root.
    fn release(&mut self, effect: &Effect) -> Result<()>;
}

/// Executes admitted module handlers with bounded pipes and process lifetimes.
pub struct ProcessAdapter<A> {
    artifacts: A,
}

impl<A: HandlerArtifacts> ProcessAdapter<A> {
    /// Constructs a transport backed by the host's artifact admission policy.
    pub const fn new(artifacts: A) -> Self {
        Self { artifacts }
    }

    fn exchange(
        &mut self,
        invocation: &Invocation,
        operation: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>> {
        let Handler::Process { executable, .. } = &invocation.effect.handler else {
            bail!("composed effects do not have a process transport");
        };
        // Recheck admission at dispatch as well as at transaction preflight.
        self.artifacts.retain(&invocation.effect)?;
        let mut input = BoundedWriter::new(MESSAGE_LIMITS.max_bytes as u64, "handler invocation");
        serde_json::to_writer(&mut input, invocation)?;
        let input = serde_json::to_vec(invocation)?;
        let mut command = Command::new(executable);
        command.arg(operation);
        let budget = InvocationBudget {
            cancellation,
            timeout_ms: invocation.effect.timeout_ms,
        };
        let output = run_bounded(
            &mut command,
            Some(&input),
            MESSAGE_LIMITS.max_bytes,
            &budget,
            &[],
        )
        .context("module handler transport failed")?;
        ensure!(
            output.status.success(),
            "module handler exited with {}",
            output.status
        );
        Ok(output.stdout)
    }
}

impl<A: HandlerArtifacts> ActivationAdapter for ProcessAdapter<A> {
    fn retain(&mut self, effect: &Effect) -> Result<()> {
        if matches!(effect.handler, Handler::Process { .. }) {
            self.artifacts.retain(effect)?;
        }
        Ok(())
    }

    fn observe(
        &mut self,
        invocation: &Invocation,
        cancellation: &CancellationToken,
    ) -> Result<Observation> {
        let bytes = self.exchange(invocation, "observe", cancellation)?;
        let response: Observed = MESSAGE_LIMITS.decode(&bytes, "handler observation")?;
        Ok(match response {
            Observed::Current { outputs } => {
                invocation.effect.check_results(&outputs)?;
                Observation::Current(outputs)
            }
            Observed::Absent => Observation::Absent,
            Observed::RetrySafe => Observation::RetrySafe,
            Observed::Indeterminate => Observation::Indeterminate,
        })
    }

    fn invoke(
        &mut self,
        invocation: &Invocation,
        cancellation: &CancellationToken,
    ) -> Result<Value> {
        let operation = match invocation.action {
            Action::Apply => "apply",
            Action::Remove => "remove",
        };
        let bytes = self.exchange(invocation, operation, cancellation)?;
        MESSAGE_LIMITS
            .decode(&bytes, "handler results")
            .map_err(Into::into)
    }

    fn release(&mut self, effect: &Effect) -> Result<()> {
        if matches!(effect.handler, Handler::Process { .. }) {
            self.artifacts.release(effect)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum Observed {
    Current { outputs: Value },
    Absent,
    RetrySafe,
    Indeterminate,
}

struct InvocationBudget<'a> {
    cancellation: &'a CancellationToken,
    timeout_ms: u64,
}

impl RuntimeControl for InvocationBudget<'_> {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn elapsed_millis(&self) -> u64 {
        0
    }

    fn attempt_remaining_millis(&self) -> u64 {
        self.timeout_ms
    }

    fn recovery_remaining_millis(&self) -> u64 {
        self.timeout_ms
    }
}

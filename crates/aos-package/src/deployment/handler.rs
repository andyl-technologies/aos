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

use anyhow::{Context, Result, bail};
use aos_ability_plan::module_graph::{Effect, Handler};
use aos_ability_runtime::activation::{
    Action, ActivationAdapter, BoundaryEvent, BoundaryObserver, Invocation, Observation,
};
use aos_ability_runtime::adapter::{CancellationToken, RuntimeControl};
use aos_contract::limits::{BoundedWriter, JsonLimits};
use serde::Deserialize;
use serde_json::Value;

use super::process::{ProcessOutput, run_bounded};

const MESSAGE_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 256 * 1024,
    max_depth: 64,
    max_items: 65_536,
    max_string_bytes: 128 * 1024,
};

/// Preserves a bounded diagnostic without exposing the typed result stream.
fn check_handler_status(output: &ProcessOutput) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }

    const DIAGNOSTIC_BYTES: usize = 4096;
    let stderr =
        String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(DIAGNOSTIC_BYTES)]);
    let suffix = if output.stderr.len() > DIAGNOSTIC_BYTES {
        "\n[stderr truncated]"
    } else {
        ""
    };
    bail!(
        "module handler exited with {}: {}{suffix}",
        output.status,
        stderr.trim_end()
    )
}

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

    /// Idempotently releases a handler root after durable teardown or replacement.
    ///
    /// # Errors
    /// Returns an error if the package store cannot release the root.
    fn release(&mut self, effect: &Effect) -> Result<()>;
}

/// Executes admitted module handlers with bounded pipes and process lifetimes.
pub struct ProcessAdapter<A> {
    artifacts: A,
    observer: Option<Box<dyn BoundaryObserver>>,
}

impl<A: HandlerArtifacts> ProcessAdapter<A> {
    /// Constructs a transport backed by the host's artifact admission policy.
    pub const fn new(artifacts: A) -> Self {
        Self {
            artifacts,
            observer: None,
        }
    }

    /// Installs or removes an explicitly selected execution observer.
    ///
    /// The caller authenticates any endpoint configuration before installation.
    /// Observer errors stop execution with the durable intent available for recovery.
    pub fn set_observer(&mut self, observer: Option<Box<dyn BoundaryObserver>>) {
        self.observer = observer;
    }

    /// Borrows the owning package store for generation retention.
    pub fn artifacts_mut(&mut self) -> &mut A {
        &mut self.artifacts
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
        let handler_context = || {
            format!(
                "{operation} handler {executable} for effect {:?}",
                invocation.effect.identity
            )
        };
        let output = run_bounded(
            &mut command,
            Some(&input),
            MESSAGE_LIMITS.max_bytes,
            &budget,
            &[],
        )
        .with_context(&handler_context)?;
        check_handler_status(&output).with_context(handler_context)?;
        Ok(output.stdout)
    }
}

impl<A: HandlerArtifacts> ActivationAdapter for ProcessAdapter<A> {
    fn boundary(&mut self, event: &BoundaryEvent, cancellation: &CancellationToken) -> Result<()> {
        if let Some(observer) = &mut self.observer {
            observer.boundary(event, cancellation)?;
        }
        Ok(())
    }

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

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::ExitStatus;

    use super::*;

    #[test]
    fn failed_handler_reports_stderr_without_its_typed_results() {
        let output = ProcessOutput {
            status: ExitStatus::from_raw(7 << 8),
            stdout: b"private-result-value".to_vec(),
            stderr: b"required device is absent\n".to_vec(),
        };

        let message = check_handler_status(&output).unwrap_err().to_string();

        assert!(message.contains("exit status: 7"));
        assert!(message.contains("required device is absent"));
        assert!(!message.contains("private-result-value"));
    }

    #[test]
    fn failed_handler_diagnostics_are_bounded_and_accept_non_utf8() {
        let mut stderr = vec![0xff; 4096];
        stderr.extend_from_slice(b"unretained-diagnostic-tail");
        let mut output = ProcessOutput {
            status: ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr,
        };

        let message = check_handler_status(&output).unwrap_err().to_string();

        assert!(message.contains("[stderr truncated]"));
        assert!(!message.contains("unretained-diagnostic-tail"));
        assert!(message.len() < 4096 * 3 + 128);

        output.status = ExitStatus::from_raw(0);
        assert!(check_handler_status(&output).is_ok());
    }
}

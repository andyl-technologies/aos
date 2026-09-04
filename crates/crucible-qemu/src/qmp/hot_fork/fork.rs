//! Exact retained-template fork request and parent-process result.

use serde_json::Value;
use thiserror::Error;

use super::{
    QmpHotForkChildConsoleState, QmpHotForkChildProcessContractState, QmpHotForkChildQmpState,
    QmpHotForkTemplateOutcome, QmpHotForkTemplateState,
};
use crate::qmp::{QmpCommandKind, QmpError};

/// QMP command that forks one exact retained template.
pub const QMP_HOT_FORK_COMMAND: &str = "crucible-hot-fork";
/// Version of the exact retained-template fork result.
pub const QMP_HOT_FORK_SCHEMA_VERSION: u32 = 2;

/// Failure to derive a fork request from one exact prepared template basis.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum QmpHotForkRequestError {
    /// The template report does not attest one retained prepared transaction.
    #[error("hot-fork template is not prepared")]
    TemplateNotPrepared,
    /// The private child-QMP report does not belong to the prepared template.
    #[error("hot-fork child QMP state does not match the prepared template")]
    ChildQmpBasisMismatch,
    /// The private child-console report does not belong to the template.
    #[error("hot-fork child console state does not match the prepared template")]
    ChildConsoleBasisMismatch,
    /// The process contract is absent, consumed, or belongs to another template.
    #[error("hot-fork child process contract does not match the prepared template")]
    ChildProcessContractBasisMismatch,
}

/// Exact generation preconditions consumed by one retained-template fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkRequest {
    template_generation: u64,
    private_ring_generation: u64,
    diagnostic_generation: u64,
    qmp_generation: u64,
    console_generation: u64,
    monitor_generation: u64,
    plugin_endpoint_generation: u64,
    plugin_barrier_generation: u64,
    rcu_barrier_generation: u64,
    bh_timer_barrier_generation: u64,
    block_barrier_generation: u64,
    parent_process_generation: u64,
    child_process_generation: u64,
    child_process_contract_generation: u64,
}

impl QmpHotForkRequest {
    /// Derives one request from matching prepared-template and child-QMP reports.
    ///
    /// The constructor binds the monitor generation, which is owned by the
    /// private-QMP report, to every generation retained in the prepared
    /// template. No generation can be supplied independently by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`QmpHotForkRequestError`] unless both reports describe the
    /// same complete, still-retained preparation transaction.
    pub fn from_prepared_template(
        template: &QmpHotForkTemplateState,
        child_qmp: &QmpHotForkChildQmpState,
        child_console: &QmpHotForkChildConsoleState,
        child_process_contract: &QmpHotForkChildProcessContractState,
    ) -> Result<Self, QmpHotForkRequestError> {
        let stage = template.resource_stage();
        let prepared = template.outcome() == QmpHotForkTemplateOutcome::Prepared
            && template.ready()
            && template.transaction_active()
            && stage.transaction_bound()
            && stage.plugin_child_plan_bound()
            && stage.plugin_child_resource_plan_bound()
            && stage.readiness_proof_acknowledged();
        if !prepared {
            return Err(QmpHotForkRequestError::TemplateNotPrepared);
        }

        let qmp_matches = child_qmp.staged()
            && child_qmp.generation() == stage.qmp_generation()
            && child_qmp.template_generation() == template.generation()
            && child_qmp.monitor_generation() != 0
            && child_qmp.resource_plan_bound()
            && child_qmp.monitor_basis_bound()
            && child_qmp.monitor_disposition_bound()
            && child_qmp.monitor_socket_resources_bound()
            && child_qmp.reinitializer_prepared()
            && !child_qmp.reinitialized()
            && !child_qmp.disposition_complete();
        if !qmp_matches {
            return Err(QmpHotForkRequestError::ChildQmpBasisMismatch);
        }
        let console_matches = child_console.staged()
            && child_console.generation() == stage.console_generation()
            && child_console.template_generation() == template.generation()
            && child_console.resource_plan_bound()
            && child_console.console_basis_bound()
            && child_console.reinitializer_prepared()
            && !child_console.reinitialized()
            && !child_console.disposition_complete();
        if !console_matches {
            return Err(QmpHotForkRequestError::ChildConsoleBasisMismatch);
        }
        let process_contract_matches = child_process_contract.staged()
            && !child_process_contract.consumed()
            && child_process_contract.generation() != 0
            && child_process_contract.template_generation() == template.generation();
        if !process_contract_matches {
            return Err(QmpHotForkRequestError::ChildProcessContractBasisMismatch);
        }

        Ok(Self {
            template_generation: template.generation(),
            private_ring_generation: stage.private_ring_generation(),
            diagnostic_generation: stage.diagnostic_generation(),
            qmp_generation: stage.qmp_generation(),
            console_generation: stage.console_generation(),
            monitor_generation: child_qmp.monitor_generation(),
            plugin_endpoint_generation: stage.plugin_endpoint_generation(),
            plugin_barrier_generation: template.plugin_barrier().generation(),
            rcu_barrier_generation: template.rcu_barrier().generation(),
            bh_timer_barrier_generation: template.bh_timer_barrier().generation(),
            block_barrier_generation: template.block_barrier().generation(),
            parent_process_generation: stage.parent_process_generation(),
            child_process_generation: stage.child_process_generation(),
            child_process_contract_generation: child_process_contract.generation(),
        })
    }

    #[cfg(test)]
    // crucible-lint: allow rust-allow -- the protocol fixture must vary each independent generation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn for_test(
        template_generation: u64,
        private_ring_generation: u64,
        diagnostic_generation: u64,
        qmp_generation: u64,
        console_generation: u64,
        monitor_generation: u64,
        plugin_endpoint_generation: u64,
        plugin_barrier_generation: u64,
        rcu_barrier_generation: u64,
        bh_timer_barrier_generation: u64,
        block_barrier_generation: u64,
        parent_process_generation: u64,
        child_process_generation: u64,
        child_process_contract_generation: u64,
    ) -> Self {
        Self {
            template_generation,
            private_ring_generation,
            diagnostic_generation,
            qmp_generation,
            console_generation,
            monitor_generation,
            plugin_endpoint_generation,
            plugin_barrier_generation,
            rcu_barrier_generation,
            bh_timer_barrier_generation,
            block_barrier_generation,
            parent_process_generation,
            child_process_generation,
            child_process_contract_generation,
        }
    }

    /// Returns the exact retained template generation.
    #[must_use]
    pub const fn template_generation(self) -> u64 {
        self.template_generation
    }

    /// Returns the exact branch-private ring generation.
    #[must_use]
    pub const fn private_ring_generation(self) -> u64 {
        self.private_ring_generation
    }

    /// Returns the exact branch-private diagnostics generation.
    #[must_use]
    pub const fn diagnostic_generation(self) -> u64 {
        self.diagnostic_generation
    }

    /// Returns the exact branch-private child-QMP generation.
    #[must_use]
    pub const fn qmp_generation(self) -> u64 {
        self.qmp_generation
    }

    /// Returns the exact branch-private child-console generation.
    #[must_use]
    pub const fn console_generation(self) -> u64 {
        self.console_generation
    }

    /// Returns the exact retained parent-monitor generation.
    #[must_use]
    pub const fn monitor_generation(self) -> u64 {
        self.monitor_generation
    }

    /// Returns the exact plugin-endpoint generation.
    #[must_use]
    pub const fn plugin_endpoint_generation(self) -> u64 {
        self.plugin_endpoint_generation
    }

    /// Returns the exact retained plugin-barrier generation.
    #[must_use]
    pub const fn plugin_barrier_generation(self) -> u64 {
        self.plugin_barrier_generation
    }

    /// Returns the exact retained RCU-barrier generation.
    #[must_use]
    pub const fn rcu_barrier_generation(self) -> u64 {
        self.rcu_barrier_generation
    }

    /// Returns the exact retained bottom-half/timer-barrier generation.
    #[must_use]
    pub const fn bh_timer_barrier_generation(self) -> u64 {
        self.bh_timer_barrier_generation
    }

    /// Returns the exact retained block-barrier generation.
    #[must_use]
    pub const fn block_barrier_generation(self) -> u64 {
        self.block_barrier_generation
    }

    /// Returns the exact registered plugin parent-process generation.
    #[must_use]
    pub const fn parent_process_generation(self) -> u64 {
        self.parent_process_generation
    }

    /// Returns the exact checked plugin child-process generation.
    #[must_use]
    pub const fn child_process_generation(self) -> u64 {
        self.child_process_generation
    }

    /// Returns the exact one-shot target process-contract generation.
    #[must_use]
    pub const fn child_process_contract_generation(self) -> u64 {
        self.child_process_contract_generation
    }

    pub(crate) fn wire_value(self) -> Value {
        serde_json::json!({
            "template-generation": self.template_generation,
            "private-ring-generation": self.private_ring_generation,
            "diagnostic-generation": self.diagnostic_generation,
            "qmp-generation": self.qmp_generation,
            "console-generation": self.console_generation,
            "monitor-generation": self.monitor_generation,
            "plugin-endpoint-generation": self.plugin_endpoint_generation,
            "plugin-barrier-generation": self.plugin_barrier_generation,
            "rcu-barrier-generation": self.rcu_barrier_generation,
            "bh-timer-barrier-generation": self.bh_timer_barrier_generation,
            "block-barrier-generation": self.block_barrier_generation,
            "parent-process-generation": self.parent_process_generation,
            "child-process-generation": self.child_process_generation,
            "child-process-contract-generation": self.child_process_contract_generation,
        })
    }
}

/// Parent-process outcome of one exact hot fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpHotForkOutcome {
    /// The child exists and parent disposition completed.
    Forked,
    /// The child exists but parent disposition failed.
    ParentDispositionFailed,
}

/// Exact authenticated parent-process result of one retained-template fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkState {
    request: QmpHotForkRequest,
    outcome: QmpHotForkOutcome,
    parent_status: i64,
    child_pid: i64,
}

impl QmpHotForkState {
    #[cfg(test)]
    pub(crate) const fn for_test(
        request: QmpHotForkRequest,
        outcome: QmpHotForkOutcome,
        child_pid: i64,
    ) -> Self {
        let parent_status = match outcome {
            QmpHotForkOutcome::Forked => 0,
            QmpHotForkOutcome::ParentDispositionFailed => -1,
        };
        Self {
            request,
            outcome,
            parent_status,
            child_pid,
        }
    }

    /// Returns the exact request basis echoed by QEMU.
    #[must_use]
    pub const fn request(self) -> QmpHotForkRequest {
        self.request
    }

    /// Returns the parent-process disposition outcome.
    #[must_use]
    pub const fn outcome(self) -> QmpHotForkOutcome {
        self.outcome
    }

    /// Returns zero on success or the negative parent-disposition status.
    #[must_use]
    pub const fn parent_status(self) -> i64 {
        self.parent_status
    }

    /// Returns the positive direct-child process identifier.
    #[must_use]
    pub const fn child_pid(self) -> i64 {
        self.child_pid
    }
}

pub(crate) fn parse_hot_fork_state(
    value: &Value,
    request: QmpHotForkRequest,
) -> Result<QmpHotForkState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotFork,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "outcome",
        "parent-status",
        "child-pid",
        "template-generation",
        "private-ring-generation",
        "diagnostic-generation",
        "qmp-generation",
        "console-generation",
        "monitor-generation",
        "plugin-endpoint-generation",
        "plugin-barrier-generation",
        "rcu-barrier-generation",
        "bh-timer-barrier-generation",
        "block-barrier-generation",
        "parent-process-generation",
        "child-process-generation",
        "child-process-contract-generation",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let unsigned = |field| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)
    };
    let signed = |field| {
        object
            .get(field)
            .and_then(Value::as_i64)
            .ok_or_else(&malformed)
    };
    let outcome = match object.get("outcome").and_then(Value::as_str) {
        Some("forked") => QmpHotForkOutcome::Forked,
        Some("parent-disposition-failed") => QmpHotForkOutcome::ParentDispositionFailed,
        _ => return Err(malformed()),
    };
    let parent_status = signed("parent-status")?;
    let child_pid = signed("child-pid")?;
    let echoed = QmpHotForkRequest {
        template_generation: unsigned("template-generation")?,
        private_ring_generation: unsigned("private-ring-generation")?,
        diagnostic_generation: unsigned("diagnostic-generation")?,
        qmp_generation: unsigned("qmp-generation")?,
        console_generation: unsigned("console-generation")?,
        monitor_generation: unsigned("monitor-generation")?,
        plugin_endpoint_generation: unsigned("plugin-endpoint-generation")?,
        plugin_barrier_generation: unsigned("plugin-barrier-generation")?,
        rcu_barrier_generation: unsigned("rcu-barrier-generation")?,
        bh_timer_barrier_generation: unsigned("bh-timer-barrier-generation")?,
        block_barrier_generation: unsigned("block-barrier-generation")?,
        parent_process_generation: unsigned("parent-process-generation")?,
        child_process_generation: unsigned("child-process-generation")?,
        child_process_contract_generation: unsigned("child-process-contract-generation")?,
    };
    let outcome_valid = match outcome {
        QmpHotForkOutcome::Forked => parent_status == 0,
        QmpHotForkOutcome::ParentDispositionFailed => parent_status < 0,
    };
    if unsigned("schema-version")? != u64::from(QMP_HOT_FORK_SCHEMA_VERSION)
        || echoed != request
        || child_pid <= 0
        || child_pid > i64::from(i32::MAX)
        || !outcome_valid
    {
        return Err(malformed());
    }

    Ok(QmpHotForkState {
        request,
        outcome,
        parent_status,
        child_pid,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn request() -> QmpHotForkRequest {
        QmpHotForkRequest::for_test(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)
    }

    #[test]
    fn response_requires_exact_echo_and_outcome_status() {
        let response = json!({
            "schema-version": 2,
            "outcome": "forked",
            "parent-status": 0,
            "child-pid": 321,
            "template-generation": 1,
            "private-ring-generation": 2,
            "diagnostic-generation": 3,
            "qmp-generation": 4,
            "console-generation": 5,
            "monitor-generation": 6,
            "plugin-endpoint-generation": 7,
            "plugin-barrier-generation": 8,
            "rcu-barrier-generation": 9,
            "bh-timer-barrier-generation": 10,
            "block-barrier-generation": 11,
            "parent-process-generation": 12,
            "child-process-generation": 13,
            "child-process-contract-generation": 14,
        });
        let Ok(state) = parse_hot_fork_state(&response, request()) else {
            panic!("exact hot-fork response should parse");
        };
        assert_eq!(state.child_pid(), 321);
        assert_eq!(state.outcome(), QmpHotForkOutcome::Forked);

        let mut wrong_echo = response.clone();
        wrong_echo["qmp-generation"] = json!(99);
        assert!(parse_hot_fork_state(&wrong_echo, request()).is_err());

        let mut wrong_status = response.clone();
        wrong_status["parent-status"] = json!(-5);
        assert!(parse_hot_fork_state(&wrong_status, request()).is_err());

        let mut oversized_pid = response.clone();
        oversized_pid["child-pid"] = json!(i64::from(i32::MAX) + 1);
        assert!(parse_hot_fork_state(&oversized_pid, request()).is_err());

        let mut failed = response;
        failed["outcome"] = json!("parent-disposition-failed");
        failed["parent-status"] = json!(-5);
        assert!(parse_hot_fork_state(&failed, request()).is_ok());
    }
}

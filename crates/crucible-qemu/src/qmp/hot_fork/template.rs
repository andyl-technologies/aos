//! Retained QEMU-owned hot-fork template preparation transaction.

use serde_json::Value;

use super::{
    QMP_HOT_FORK_REQUIRED_PROOFS, QmpHotForkPluginBarrierState,
    plugin::parse_hot_fork_plugin_barrier_state_for,
};
use crate::qmp::{QmpCommandKind, QmpError};

/// QMP command name used for QEMU's retained template-preparation coordinator.
pub const QMP_HOT_FORK_TEMPLATE_COMMAND: &str = "crucible-hot-fork-template";
/// Version of the QEMU-owned template-preparation transaction contract.
pub const QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION: u32 = 1;

/// Exact outcome of one hot-fork template coordinator operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpHotForkTemplateOutcome {
    /// No transaction or acquired subsystem barrier exists.
    Idle,
    /// The retained transaction is waiting for admitted work or reevaluation.
    Draining,
    /// Complete readiness was unavailable and every acquired barrier rolled back.
    Blocked,
    /// Every proof is present and the retained transaction remains prepared.
    Prepared,
    /// An active transaction was explicitly rolled back.
    Aborted,
}

/// Exact state returned by QEMU's retained template-preparation coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkTemplateState {
    generation: u64,
    outcome: QmpHotForkTemplateOutcome,
    transaction_active: bool,
    acknowledged_proofs: u64,
    missing_proofs: u64,
    plugin_barrier: QmpHotForkPluginBarrierState,
    rollback_complete: bool,
    ready: bool,
}

impl QmpHotForkTemplateState {
    /// Returns the process-local transaction generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the exact result of the requested coordinator operation.
    #[must_use]
    pub const fn outcome(self) -> QmpHotForkTemplateOutcome {
        self.outcome
    }

    /// Returns whether QEMU still owns acquired subsystem-barrier state.
    #[must_use]
    pub const fn transaction_active(self) -> bool {
        self.transaction_active
    }

    /// Returns the exact currently acknowledged proof bitmap.
    #[must_use]
    pub const fn acknowledged_proofs(self) -> u64 {
        self.acknowledged_proofs
    }

    /// Returns the exact required proof bits QEMU could not acknowledge.
    #[must_use]
    pub const fn missing_proofs(self) -> u64 {
        self.missing_proofs
    }

    /// Returns the plugin callback barrier after the operation and any rollback.
    #[must_use]
    pub const fn plugin_barrier(self) -> QmpHotForkPluginBarrierState {
        self.plugin_barrier
    }

    /// Returns whether QEMU attests that no transaction barrier remains acquired.
    #[must_use]
    pub const fn rollback_complete(self) -> bool {
        self.rollback_complete
    }

    /// Returns whether every proof is present in one retained prepared transaction.
    #[must_use]
    pub const fn ready(self) -> bool {
        self.ready
    }
}

pub(crate) fn parse_hot_fork_template_state(
    value: &Value,
) -> Result<QmpHotForkTemplateState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkTemplate,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "outcome",
        "transaction-active",
        "required-proofs",
        "acknowledged-proofs",
        "missing-proofs",
        "plugin-barrier",
        "rollback-complete",
        "ready",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let outcome = match object.get("outcome").and_then(Value::as_str) {
        Some("idle") => QmpHotForkTemplateOutcome::Idle,
        Some("draining") => QmpHotForkTemplateOutcome::Draining,
        Some("blocked") => QmpHotForkTemplateOutcome::Blocked,
        Some("prepared") => QmpHotForkTemplateOutcome::Prepared,
        Some("aborted") => QmpHotForkTemplateOutcome::Aborted,
        _ => return Err(malformed()),
    };
    let transaction_active = object
        .get("transaction-active")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let required_proofs = object
        .get("required-proofs")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let acknowledged_proofs = object
        .get("acknowledged-proofs")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let missing_proofs = object
        .get("missing-proofs")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let plugin_barrier = parse_hot_fork_plugin_barrier_state_for(
        QmpCommandKind::HotForkTemplate,
        object.get("plugin-barrier").ok_or_else(&malformed)?,
    )?;
    let rollback_complete = object
        .get("rollback-complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let ready = object
        .get("ready")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let proofs_valid = schema_version == u64::from(QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION)
        && required_proofs == QMP_HOT_FORK_REQUIRED_PROOFS
        && acknowledged_proofs & !required_proofs == 0
        && missing_proofs == required_proofs & !acknowledged_proofs;
    let expected_ready = outcome == QmpHotForkTemplateOutcome::Prepared
        && transaction_active
        && plugin_barrier.quiescent()
        && missing_proofs == 0;
    let expected_rollback = !transaction_active && !plugin_barrier.held();
    let shape_valid = match outcome {
        QmpHotForkTemplateOutcome::Idle => {
            !transaction_active && rollback_complete && !plugin_barrier.held() && !ready
        }
        QmpHotForkTemplateOutcome::Draining => {
            generation != 0
                && transaction_active
                && !rollback_complete
                && plugin_barrier.held()
                && !plugin_barrier.teardown_closed()
                && !ready
        }
        QmpHotForkTemplateOutcome::Blocked => {
            generation != 0
                && !transaction_active
                && rollback_complete
                && !plugin_barrier.held()
                && missing_proofs != 0
                && !ready
        }
        QmpHotForkTemplateOutcome::Prepared => {
            generation != 0
                && transaction_active
                && !rollback_complete
                && plugin_barrier.quiescent()
                && ready
        }
        QmpHotForkTemplateOutcome::Aborted => {
            generation != 0
                && !transaction_active
                && rollback_complete
                && !plugin_barrier.held()
                && !ready
        }
    };
    if !proofs_valid
        || ready != expected_ready
        || rollback_complete != expected_rollback
        || !shape_valid
    {
        return Err(malformed());
    }

    Ok(QmpHotForkTemplateState {
        generation,
        outcome,
        transaction_active,
        acknowledged_proofs,
        missing_proofs,
        plugin_barrier,
        rollback_complete,
        ready,
    })
}

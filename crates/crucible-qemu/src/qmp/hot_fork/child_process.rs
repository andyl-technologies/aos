//! Parent-QEMU ownership of one hot-fork child's final process status.

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpError};

/// QMP command that queries or releases one parent-owned child record.
pub const QMP_HOT_FORK_CHILD_PROCESS_COMMAND: &str = "crucible-hot-fork-child-process";
/// Version of the parent-owned child-process status contract.
pub const QMP_HOT_FORK_CHILD_PROCESS_SCHEMA_VERSION: u32 = 1;

/// Parent-owned lifecycle phase for one exact hot-fork child generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpHotForkChildProcessPhase {
    /// The source QEMU has not observed a final child wait status.
    Running,
    /// The child exited normally and the status is its exit code.
    Exited,
    /// The child terminated from a signal and the status is that signal.
    Signaled,
}

/// Exact child-process state retained by the source QEMU through reap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildProcessState {
    generation: u64,
    child_process_id: u32,
    phase: QmpHotForkChildProcessPhase,
    status: u8,
    retained: bool,
}

impl QmpHotForkChildProcessState {
    /// Returns the exact child-process generation from the fork request.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the positive process identifier reported by the source QEMU.
    #[must_use]
    pub const fn child_process_id(self) -> u32 {
        self.child_process_id
    }

    /// Returns the source QEMU's parent-owned process phase.
    #[must_use]
    pub const fn phase(self) -> QmpHotForkChildProcessPhase {
        self.phase
    }

    /// Returns zero while running, the exit code, or the terminating signal.
    #[must_use]
    pub const fn status(self) -> u8 {
        self.status
    }

    /// Returns whether the source QEMU still retains this generation record.
    #[must_use]
    pub const fn retained(self) -> bool {
        self.retained
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HotForkChildProcessAction {
    Query,
    Release,
}

impl HotForkChildProcessAction {
    pub(crate) const fn wire_name(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

pub(crate) fn parse_hot_fork_child_process_state(
    value: &Value,
    generation: u64,
    action: HotForkChildProcessAction,
) -> Result<QmpHotForkChildProcessState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkChildProcess,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "child-pid",
        "phase",
        "status",
        "retained",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let echoed_generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let child_process_id = object
        .get("child-pid")
        .and_then(Value::as_i64)
        .and_then(|process_id| u32::try_from(process_id).ok())
        .filter(|process_id| *process_id != 0 && *process_id <= 2_147_483_647)
        .ok_or_else(&malformed)?;
    let phase = match object.get("phase").and_then(Value::as_str) {
        Some("running") => QmpHotForkChildProcessPhase::Running,
        Some("exited") => QmpHotForkChildProcessPhase::Exited,
        Some("signaled") => QmpHotForkChildProcessPhase::Signaled,
        _ => return Err(malformed()),
    };
    let status = object
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u8::try_from(status).ok())
        .ok_or_else(&malformed)?;
    let retained = object
        .get("retained")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let state_valid = schema_version == u64::from(QMP_HOT_FORK_CHILD_PROCESS_SCHEMA_VERSION)
        && generation != 0
        && echoed_generation == generation
        && match phase {
            QmpHotForkChildProcessPhase::Running => status == 0 && retained,
            QmpHotForkChildProcessPhase::Exited => true,
            QmpHotForkChildProcessPhase::Signaled => status != 0,
        }
        && match action {
            HotForkChildProcessAction::Query => retained,
            HotForkChildProcessAction::Release => {
                !retained && phase != QmpHotForkChildProcessPhase::Running
            }
        };
    if !state_valid {
        return Err(malformed());
    }

    Ok(QmpHotForkChildProcessState {
        generation,
        child_process_id,
        phase,
        status,
        retained,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn child_process_state_binds_generation_phase_and_retention() {
        let running = json!({
            "schema-version": 1,
            "generation": 17,
            "child-pid": 321,
            "phase": "running",
            "status": 0,
            "retained": true,
        });
        assert!(
            parse_hot_fork_child_process_state(&running, 17, HotForkChildProcessAction::Query,)
                .is_ok()
        );
        assert!(
            parse_hot_fork_child_process_state(&running, 18, HotForkChildProcessAction::Query,)
                .is_err()
        );

        let mut released = running.clone();
        released["phase"] = json!("exited");
        released["status"] = json!(7);
        released["retained"] = json!(false);
        assert!(
            parse_hot_fork_child_process_state(&released, 17, HotForkChildProcessAction::Release,)
                .is_ok()
        );

        let mut invalid_running_release = running;
        invalid_running_release["retained"] = json!(false);
        assert!(
            parse_hot_fork_child_process_state(
                &invalid_running_release,
                17,
                HotForkChildProcessAction::Release,
            )
            .is_err()
        );

        let mut invalid_signal = released;
        invalid_signal["phase"] = json!("signaled");
        invalid_signal["status"] = json!(0);
        assert!(
            parse_hot_fork_child_process_state(
                &invalid_signal,
                17,
                HotForkChildProcessAction::Release,
            )
            .is_err()
        );
    }
}

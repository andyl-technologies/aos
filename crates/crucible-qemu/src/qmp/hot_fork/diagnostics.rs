//! QEMU-owned retention of one branch-private child diagnostics stream.

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpDescriptorName, QmpError};

/// QMP command that retains or releases the branch-private diagnostics stream.
pub const QMP_HOT_FORK_CHILD_DIAGNOSTICS_COMMAND: &str = "crucible-hot-fork-child-diagnostics";
/// Version of the retained child-diagnostics contract.
pub const QMP_HOT_FORK_CHILD_DIAGNOSTICS_SCHEMA_VERSION: u32 = 1;
/// Inherited descriptor slot replaced by the branch-private diagnostics stream.
pub const QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD: i32 = 2;

/// Exact QEMU-owned state for one retained branch-private diagnostics stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildDiagnosticState {
    generation: u64,
    template_generation: u64,
    descriptor_name: Option<QmpDescriptorName>,
    socket_cookie: u64,
    source_descriptor: i32,
    target_descriptor: i32,
    replacement_plan_bound: bool,
}

impl QmpHotForkChildDiagnosticState {
    #[cfg(test)]
    pub(crate) fn one_template_staged(
        generation: u64,
        template_generation: u64,
        descriptor_name: QmpDescriptorName,
        socket_cookie: u64,
        source_descriptor: i32,
        replacement_plan_bound: bool,
    ) -> Self {
        Self {
            generation,
            template_generation,
            descriptor_name: Some(descriptor_name),
            socket_cookie,
            source_descriptor,
            target_descriptor: QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD,
            replacement_plan_bound,
        }
    }

    /// Returns the process-local mutation generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact template generation that admitted this stream.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns whether QEMU retains one independently duplicated stream.
    #[must_use]
    pub const fn staged(&self) -> bool {
        self.descriptor_name.is_some()
    }

    /// Returns the standard-QMP descriptor name while staged.
    #[must_use]
    pub const fn descriptor_name(&self) -> Option<&QmpDescriptorName> {
        self.descriptor_name.as_ref()
    }

    /// Returns the authenticated Linux `SO_COOKIE` while staged.
    #[must_use]
    pub const fn socket_cookie(&self) -> Option<u64> {
        if self.staged() {
            Some(self.socket_cookie)
        } else {
            None
        }
    }

    /// Returns QEMU's retained replacement-source descriptor while staged.
    ///
    /// The process-local descriptor number is observational and grants no
    /// authority to apply or release the contribution.
    #[must_use]
    pub const fn source_descriptor(&self) -> Option<i32> {
        if self.staged() {
            Some(self.source_descriptor)
        } else {
            None
        }
    }

    /// Returns the exact inherited descriptor slot replaced in the child.
    #[must_use]
    pub const fn target_descriptor(&self) -> Option<i32> {
        if self.staged() {
            Some(self.target_descriptor)
        } else {
            None
        }
    }

    /// Returns whether the exact contribution is in the sealed complete plan.
    #[must_use]
    pub const fn replacement_plan_bound(&self) -> bool {
        self.replacement_plan_bound
    }
}

pub(crate) fn parse_hot_fork_child_diagnostic_state(
    value: &Value,
) -> Result<QmpHotForkChildDiagnosticState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkChildDiagnostics,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let required = [
        "schema-version",
        "generation",
        "template-generation",
        "staged",
        "socket-cookie",
        "source-fd",
        "target-fd",
        "replacement-plan-bound",
        "nonblocking-unix-stream",
        "disposition-complete",
        "readiness-proof-acknowledged",
    ];
    let has_name = object.contains_key("fdname");
    if object.len() != required.len() + usize::from(has_name)
        || !required.iter().all(|field| object.contains_key(*field))
    {
        return Err(malformed());
    }

    let unsigned = |field| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)
    };
    let boolean = |field| {
        object
            .get(field)
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)
    };
    let descriptor = |field| {
        object
            .get(field)
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(&malformed)
    };
    let schema_version = unsigned("schema-version")?;
    let generation = unsigned("generation")?;
    let template_generation = unsigned("template-generation")?;
    let staged = boolean("staged")?;
    let descriptor_name = object
        .get("fdname")
        .map(|name| {
            name.as_str()
                .ok_or_else(&malformed)
                .and_then(|name| QmpDescriptorName::new(name).map_err(|_error| malformed()))
        })
        .transpose()?;
    let socket_cookie = unsigned("socket-cookie")?;
    let source_descriptor = descriptor("source-fd")?;
    let target_descriptor = descriptor("target-fd")?;
    let replacement_plan_bound = boolean("replacement-plan-bound")?;
    let nonblocking_unix_stream = boolean("nonblocking-unix-stream")?;
    let disposition_complete = boolean("disposition-complete")?;
    let readiness_proof_acknowledged = boolean("readiness-proof-acknowledged")?;

    let staged_shape = generation != 0
        && template_generation != 0
        && descriptor_name.is_some()
        && socket_cookie != 0
        && source_descriptor >= 0
        && source_descriptor != QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD
        && target_descriptor == QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD
        && nonblocking_unix_stream;
    let absent_shape = template_generation == 0
        && descriptor_name.is_none()
        && socket_cookie == 0
        && source_descriptor == -1
        && target_descriptor == -1
        && !replacement_plan_bound
        && !nonblocking_unix_stream;
    let valid = schema_version == u64::from(QMP_HOT_FORK_CHILD_DIAGNOSTICS_SCHEMA_VERSION)
        && staged == descriptor_name.is_some()
        && !disposition_complete
        && !readiness_proof_acknowledged
        && if staged { staged_shape } else { absent_shape };
    if !valid {
        return Err(malformed());
    }

    Ok(QmpHotForkChildDiagnosticState {
        generation,
        template_generation,
        descriptor_name,
        socket_cookie,
        source_descriptor,
        target_descriptor,
        replacement_plan_bound,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn child_diagnostics_require_exact_nonblocking_stderr_replacement() {
        let staged = json!({
            "schema-version": 1,
            "generation": 7,
            "template-generation": 3,
            "staged": true,
            "fdname": "crucible-hfork-diagnostics-v1-000000000000000b",
            "socket-cookie": 11,
            "source-fd": 30,
            "target-fd": 2,
            "replacement-plan-bound": true,
            "nonblocking-unix-stream": true,
            "disposition-complete": false,
            "readiness-proof-acknowledged": false,
        });
        let parsed = parse_hot_fork_child_diagnostic_state(&staged)
            .expect("exact diagnostics state should parse");
        assert!(parsed.staged());
        assert_eq!(parsed.socket_cookie(), Some(11));
        assert_eq!(parsed.target_descriptor(), Some(2));
        assert!(parsed.replacement_plan_bound());

        let mut wrong = staged;
        wrong["target-fd"] = json!(1);
        assert!(parse_hot_fork_child_diagnostic_state(&wrong).is_err());
    }
}

//! QEMU-owned retention of one branch-private child console stream.

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpDescriptorName, QmpError};

/// QMP command that retains or releases the branch-private child console.
pub const QMP_HOT_FORK_CHILD_CONSOLE_COMMAND: &str = "crucible-hot-fork-child-console";
/// Version of the retained child-console endpoint contract.
pub const QMP_HOT_FORK_CHILD_CONSOLE_SCHEMA_VERSION: u32 = 1;

/// Exact QEMU-owned state for one retained branch-private child console.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildConsoleState {
    generation: u64,
    template_generation: u64,
    descriptor_name: Option<QmpDescriptorName>,
    socket_cookie: u64,
    retained_descriptor: i32,
    resource_plan_bound: bool,
    console_basis_bound: bool,
    reinitializer_prepared: bool,
    reinitialized: bool,
    disposition_complete: bool,
}

impl QmpHotForkChildConsoleState {
    #[cfg(test)]
    pub(crate) fn one_template_staged(
        generation: u64,
        template_generation: u64,
        descriptor_name: QmpDescriptorName,
        socket_cookie: u64,
        retained_descriptor: i32,
        resource_plan_bound: bool,
    ) -> Self {
        Self {
            generation,
            template_generation,
            descriptor_name: Some(descriptor_name),
            socket_cookie,
            retained_descriptor,
            resource_plan_bound,
            console_basis_bound: true,
            reinitializer_prepared: true,
            reinitialized: false,
            disposition_complete: false,
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

    /// Returns QEMU's retained child-console descriptor while staged.
    #[must_use]
    pub const fn retained_descriptor(&self) -> Option<i32> {
        if self.staged() {
            Some(self.retained_descriptor)
        } else {
            None
        }
    }

    /// Returns whether the exact retain contribution is in the sealed plan.
    #[must_use]
    pub const fn resource_plan_bound(&self) -> bool {
        self.resource_plan_bound
    }

    /// Returns whether QEMU retains the exact source-console ownership basis.
    #[must_use]
    pub const fn console_basis_bound(&self) -> bool {
        self.console_basis_bound
    }

    /// Returns whether the one-shot child-console adapter is exactly bound.
    #[must_use]
    pub const fn reinitializer_prepared(&self) -> bool {
        self.reinitializer_prepared
    }

    /// Returns whether the child console reconstruction completed exactly.
    #[must_use]
    pub const fn reinitialized(&self) -> bool {
        self.reinitialized
    }

    /// Returns whether the child accepted the complete console disposition.
    #[must_use]
    pub const fn disposition_complete(&self) -> bool {
        self.disposition_complete
    }
}

pub(crate) fn parse_hot_fork_child_console_state(
    value: &Value,
) -> Result<QmpHotForkChildConsoleState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkChildConsole,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let required = [
        "schema-version",
        "generation",
        "template-generation",
        "staged",
        "socket-cookie",
        "retained-fd",
        "resource-plan-bound",
        "nonblocking-unix-stream",
        "console-basis-bound",
        "reinitializer-prepared",
        "reinitialized",
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
    let retained_descriptor = descriptor("retained-fd")?;
    let resource_plan_bound = boolean("resource-plan-bound")?;
    let nonblocking_unix_stream = boolean("nonblocking-unix-stream")?;
    let console_basis_bound = boolean("console-basis-bound")?;
    let reinitializer_prepared = boolean("reinitializer-prepared")?;
    let reinitialized = boolean("reinitialized")?;
    let disposition_complete = boolean("disposition-complete")?;
    let readiness_proof_acknowledged = boolean("readiness-proof-acknowledged")?;

    let staged_shape = generation != 0
        && template_generation != 0
        && descriptor_name.is_some()
        && socket_cookie != 0
        && retained_descriptor >= 0
        && nonblocking_unix_stream
        && console_basis_bound
        && reinitializer_prepared;
    let absent_shape = template_generation == 0
        && descriptor_name.is_none()
        && socket_cookie == 0
        && retained_descriptor == -1
        && !resource_plan_bound
        && !nonblocking_unix_stream
        && !console_basis_bound
        && !reinitializer_prepared;
    let expected_readiness =
        staged_shape && resource_plan_bound && reinitialized && disposition_complete;
    let valid = schema_version == u64::from(QMP_HOT_FORK_CHILD_CONSOLE_SCHEMA_VERSION)
        && staged == descriptor_name.is_some()
        && reinitialized == disposition_complete
        && (!reinitialized || (staged && resource_plan_bound))
        && readiness_proof_acknowledged == expected_readiness
        && if staged { staged_shape } else { absent_shape };
    if !valid {
        return Err(malformed());
    }

    Ok(QmpHotForkChildConsoleState {
        generation,
        template_generation,
        descriptor_name,
        socket_cookie,
        retained_descriptor,
        resource_plan_bound,
        console_basis_bound,
        reinitializer_prepared,
        reinitialized,
        disposition_complete,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn console_requires_one_exact_nonblocking_retained_stream() {
        let staged = json!({
            "schema-version": 1,
            "generation": 9,
            "template-generation": 3,
            "staged": true,
            "fdname": "crucible-hfork-console-v1-000000000000000d",
            "socket-cookie": 13,
            "retained-fd": 34,
            "resource-plan-bound": true,
            "nonblocking-unix-stream": true,
            "console-basis-bound": true,
            "reinitializer-prepared": true,
            "reinitialized": false,
            "disposition-complete": false,
            "readiness-proof-acknowledged": false,
        });
        let parsed = parse_hot_fork_child_console_state(&staged)
            .unwrap_or_else(|error| panic!("exact child console state should parse: {error}"));
        assert!(parsed.staged());
        assert_eq!(parsed.socket_cookie(), Some(13));
        assert!(parsed.resource_plan_bound());
        assert!(parsed.console_basis_bound());

        let mut child = staged.clone();
        child["reinitialized"] = json!(true);
        child["disposition-complete"] = json!(true);
        child["readiness-proof-acknowledged"] = json!(true);
        assert!(parse_hot_fork_child_console_state(&child).is_ok());

        let mut contradictory = child;
        contradictory["readiness-proof-acknowledged"] = json!(false);
        assert!(parse_hot_fork_child_console_state(&contradictory).is_err());
    }
}

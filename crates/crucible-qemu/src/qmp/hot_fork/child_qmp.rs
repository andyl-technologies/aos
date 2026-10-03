//! QEMU-owned retention of one branch-private child QMP stream.

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpDescriptorName, QmpError};

/// QMP command that retains or releases the branch-private child QMP stream.
pub const QMP_HOT_FORK_CHILD_QMP_COMMAND: &str = "crucible-hot-fork-child-qmp";
/// Version of the retained child-QMP endpoint contract.
pub const QMP_HOT_FORK_CHILD_QMP_SCHEMA_VERSION: u32 = 8;

/// Exact QEMU-owned state for one retained branch-private child QMP stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildQmpState {
    generation: u64,
    template_generation: u64,
    monitor_generation: u64,
    descriptor_name: Option<QmpDescriptorName>,
    socket_cookie: u64,
    retained_descriptor: i32,
    resource_plan_bound: bool,
    monitor_basis_bound: bool,
    monitor_disposition_bound: bool,
    monitor_socket_resources_bound: bool,
    reinitializer_prepared: bool,
    reinitialized: bool,
    disposition_complete: bool,
}

impl QmpHotForkChildQmpState {
    #[cfg(any(test, feature = "test-support"))]
    // crucible-lint: allow rust-allow -- the fixture constructor binds every exact child-QMP generation and resource basis independently.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn one_template_staged(
        generation: u64,
        template_generation: u64,
        monitor_generation: u64,
        descriptor_name: QmpDescriptorName,
        socket_cookie: u64,
        retained_descriptor: i32,
        resource_plan_bound: bool,
        reinitializer_prepared: bool,
    ) -> Self {
        Self {
            generation,
            template_generation,
            monitor_generation,
            descriptor_name: Some(descriptor_name),
            socket_cookie,
            retained_descriptor,
            resource_plan_bound,
            monitor_basis_bound: true,
            monitor_disposition_bound: true,
            monitor_socket_resources_bound: true,
            reinitializer_prepared,
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

    /// Returns the exact supported parent-monitor lifecycle generation.
    #[must_use]
    pub const fn monitor_generation(&self) -> u64 {
        self.monitor_generation
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

    /// Returns QEMU's retained child-QMP descriptor while staged.
    ///
    /// The process-local descriptor number is observational and grants no
    /// authority to attach or release the endpoint.
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

    /// Returns whether QEMU retains the exact parent-monitor ownership basis.
    #[must_use]
    pub const fn monitor_basis_bound(&self) -> bool {
        self.monitor_basis_bound
    }

    /// Returns whether QEMU bound the exact inherited chardev disposition.
    #[must_use]
    pub const fn monitor_disposition_bound(&self) -> bool {
        self.monitor_disposition_bound
    }

    /// Returns whether QEMU bound the exact inherited socket resources.
    #[must_use]
    pub const fn monitor_socket_resources_bound(&self) -> bool {
        self.monitor_socket_resources_bound
    }

    /// Returns whether the one-shot child-monitor adapter is exactly bound.
    #[must_use]
    pub const fn reinitializer_prepared(&self) -> bool {
        self.reinitializer_prepared
    }

    /// Returns whether the child monitor runtime completed exactly.
    #[must_use]
    pub const fn reinitialized(&self) -> bool {
        self.reinitialized
    }

    /// Returns whether the child accepted the exact complete QMP disposition.
    #[must_use]
    pub const fn disposition_complete(&self) -> bool {
        self.disposition_complete
    }
}

pub(crate) fn parse_hot_fork_child_qmp_state(
    value: &Value,
) -> Result<QmpHotForkChildQmpState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkChildQmp,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let required = [
        "schema-version",
        "generation",
        "template-generation",
        "monitor-generation",
        "staged",
        "socket-cookie",
        "retained-fd",
        "resource-plan-bound",
        "nonblocking-unix-stream",
        "monitor-basis-bound",
        "monitor-disposition-bound",
        "monitor-socket-resources-bound",
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
    let monitor_generation = unsigned("monitor-generation")?;
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
    let monitor_basis_bound = boolean("monitor-basis-bound")?;
    let monitor_disposition_bound = boolean("monitor-disposition-bound")?;
    let monitor_socket_resources_bound = boolean("monitor-socket-resources-bound")?;
    let reinitializer_prepared = boolean("reinitializer-prepared")?;
    let reinitialized = boolean("reinitialized")?;
    let disposition_complete = boolean("disposition-complete")?;
    let readiness_proof_acknowledged = boolean("readiness-proof-acknowledged")?;

    let staged_shape = generation != 0
        && template_generation != 0
        && monitor_generation != 0
        && descriptor_name.is_some()
        && socket_cookie != 0
        && retained_descriptor >= 0
        && nonblocking_unix_stream
        && monitor_basis_bound
        && monitor_disposition_bound
        && monitor_socket_resources_bound
        && reinitializer_prepared;
    let absent_shape = template_generation == 0
        && monitor_generation == 0
        && descriptor_name.is_none()
        && socket_cookie == 0
        && retained_descriptor == -1
        && !resource_plan_bound
        && !nonblocking_unix_stream
        && !monitor_basis_bound
        && !monitor_disposition_bound
        && !monitor_socket_resources_bound
        && !reinitializer_prepared;
    let expected_readiness =
        staged_shape && resource_plan_bound && reinitialized && disposition_complete;
    let valid = schema_version == u64::from(QMP_HOT_FORK_CHILD_QMP_SCHEMA_VERSION)
        && staged == descriptor_name.is_some()
        && reinitialized == disposition_complete
        && (!reinitialized || (staged && resource_plan_bound))
        && readiness_proof_acknowledged == expected_readiness
        && if staged { staged_shape } else { absent_shape };
    if !valid {
        return Err(malformed());
    }

    Ok(QmpHotForkChildQmpState {
        generation,
        template_generation,
        monitor_generation,
        descriptor_name,
        socket_cookie,
        retained_descriptor,
        resource_plan_bound,
        monitor_basis_bound,
        monitor_disposition_bound,
        monitor_socket_resources_bound,
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
    fn child_qmp_requires_one_unattached_nonblocking_retained_stream() {
        let staged = json!({
            "schema-version": 8,
            "generation": 9,
            "template-generation": 3,
            "monitor-generation": 5,
            "staged": true,
            "fdname": "crucible-hfork-qmp-v1-000000000000000d",
            "socket-cookie": 13,
            "retained-fd": 34,
            "resource-plan-bound": true,
            "nonblocking-unix-stream": true,
            "monitor-basis-bound": true,
            "monitor-disposition-bound": true,
            "monitor-socket-resources-bound": true,
            "reinitializer-prepared": true,
            "reinitialized": false,
            "disposition-complete": false,
            "readiness-proof-acknowledged": false,
        });
        let Ok(parsed) = parse_hot_fork_child_qmp_state(&staged) else {
            panic!("exact child QMP state should parse");
        };
        assert!(parsed.staged());
        assert_eq!(parsed.socket_cookie(), Some(13));
        assert_eq!(parsed.retained_descriptor(), Some(34));
        assert_eq!(parsed.monitor_generation(), 5);
        assert!(parsed.resource_plan_bound());
        assert!(parsed.monitor_basis_bound());
        assert!(parsed.monitor_disposition_bound());
        assert!(parsed.monitor_socket_resources_bound());
        assert!(parsed.reinitializer_prepared());
        assert!(!parsed.disposition_complete());

        let mut child = staged.clone();
        child["reinitialized"] = json!(true);
        child["disposition-complete"] = json!(true);
        child["readiness-proof-acknowledged"] = json!(true);
        let Ok(child) = parse_hot_fork_child_qmp_state(&child) else {
            panic!("complete child QMP state should parse");
        };
        assert!(child.reinitialized());
        assert!(child.disposition_complete());

        let mut wrong = staged.clone();
        wrong["reinitializer-prepared"] = json!(false);
        assert!(parse_hot_fork_child_qmp_state(&wrong).is_err());

        let mut wrong = staged.clone();
        wrong["monitor-basis-bound"] = json!(false);
        assert!(parse_hot_fork_child_qmp_state(&wrong).is_err());

        let mut wrong = staged.clone();
        wrong["monitor-disposition-bound"] = json!(false);
        assert!(parse_hot_fork_child_qmp_state(&wrong).is_err());

        let mut wrong = staged;
        wrong["monitor-socket-resources-bound"] = json!(false);
        assert!(parse_hot_fork_child_qmp_state(&wrong).is_err());
    }
}

//! QEMU-owned one-shot containment contract for a hot-fork child.

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpDescriptorName, QmpError};

/// QMP command that stages the target attempt's child process contract.
pub const QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_COMMAND: &str =
    "crucible-hot-fork-child-process-contract";
/// Version of the child process contract status.
pub const QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_SCHEMA_VERSION: u32 = 1;

/// Exact kernel identities and file-size ceiling transferred for one child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildProcessContractIdentity {
    cgroup_device: u64,
    cgroup_inode: u64,
    cancellation_eventfd_id: u64,
    maximum_file_bytes: u64,
}

impl QmpHotForkChildProcessContractIdentity {
    /// Builds one nonzero exact process-contract identity.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::InvalidHotForkChildProcessContract`] when any
    /// identity field or the file-size ceiling is zero.
    pub fn new(
        cgroup_device: u64,
        cgroup_inode: u64,
        cancellation_eventfd_id: u64,
        maximum_file_bytes: u64,
    ) -> Result<Self, QmpError> {
        if cgroup_device == 0
            || cgroup_inode == 0
            || cancellation_eventfd_id == 0
            || maximum_file_bytes == 0
            || maximum_file_bytes == u64::MAX
        {
            return Err(QmpError::InvalidHotForkChildProcessContract);
        }
        Ok(Self {
            cgroup_device,
            cgroup_inode,
            cancellation_eventfd_id,
            maximum_file_bytes,
        })
    }

    /// Returns the cgroup directory device identity.
    #[must_use]
    pub const fn cgroup_device(self) -> u64 {
        self.cgroup_device
    }

    /// Returns the cgroup directory inode identity.
    #[must_use]
    pub const fn cgroup_inode(self) -> u64 {
        self.cgroup_inode
    }

    /// Returns the Linux eventfd identity for sticky cancellation.
    #[must_use]
    pub const fn cancellation_eventfd_id(self) -> u64 {
        self.cancellation_eventfd_id
    }

    /// Returns the exact per-file `RLIMIT_FSIZE` ceiling.
    #[must_use]
    pub const fn maximum_file_bytes(self) -> u64 {
        self.maximum_file_bytes
    }
}

/// Exact QEMU-owned state for one staged child process contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildProcessContractState {
    generation: u64,
    template_generation: u64,
    cgroup_name: Option<QmpDescriptorName>,
    cancellation_name: Option<QmpDescriptorName>,
    identity: Option<QmpHotForkChildProcessContractIdentity>,
    consumed: bool,
}

impl QmpHotForkChildProcessContractState {
    #[cfg(test)]
    pub(crate) fn one_template_staged(
        generation: u64,
        template_generation: u64,
        cgroup_name: QmpDescriptorName,
        cancellation_name: QmpDescriptorName,
        identity: QmpHotForkChildProcessContractIdentity,
    ) -> Self {
        Self {
            generation,
            template_generation,
            cgroup_name: Some(cgroup_name),
            cancellation_name: Some(cancellation_name),
            identity: Some(identity),
            consumed: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn one_released(generation: u64) -> Self {
        Self {
            generation,
            template_generation: 0,
            cgroup_name: None,
            cancellation_name: None,
            identity: None,
            consumed: false,
        }
    }

    /// Returns the source-QEMU mutation generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact retained template generation.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns whether QEMU retains the complete contract.
    #[must_use]
    pub const fn staged(&self) -> bool {
        self.identity.is_some()
    }

    /// Returns whether this one-shot contract has created a child.
    #[must_use]
    pub const fn consumed(&self) -> bool {
        self.consumed
    }

    /// Returns the standard-QMP cgroup descriptor name while staged.
    #[must_use]
    pub const fn cgroup_name(&self) -> Option<&QmpDescriptorName> {
        self.cgroup_name.as_ref()
    }

    /// Returns the standard-QMP cancellation descriptor name while staged.
    #[must_use]
    pub const fn cancellation_name(&self) -> Option<&QmpDescriptorName> {
        self.cancellation_name.as_ref()
    }

    /// Returns the exact staged descriptor identity and resource ceiling.
    #[must_use]
    pub const fn identity(&self) -> Option<QmpHotForkChildProcessContractIdentity> {
        self.identity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HotForkChildProcessContractAction {
    Stage,
    Query,
    Release,
}

impl HotForkChildProcessContractAction {
    pub(crate) const fn wire_name(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

pub(crate) fn parse_hot_fork_child_process_contract_state(
    value: &Value,
) -> Result<QmpHotForkChildProcessContractState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkChildProcessContract,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let required = [
        "schema-version",
        "generation",
        "template-generation",
        "staged",
        "consumed",
        "cgroup-device",
        "cgroup-inode",
        "cancellation-eventfd-id",
        "maximum-file-bytes",
        "clone-into-cgroup",
    ];
    let has_cgroup_name = object.contains_key("cgroup-fdname");
    let has_cancellation_name = object.contains_key("cancellation-fdname");
    if object.len()
        != required.len() + usize::from(has_cgroup_name) + usize::from(has_cancellation_name)
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
    let name = |field| {
        object
            .get(field)
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(&malformed)
                    .and_then(|name| QmpDescriptorName::new(name).map_err(|_error| malformed()))
            })
            .transpose()
    };

    let schema_version = unsigned("schema-version")?;
    let generation = unsigned("generation")?;
    let template_generation = unsigned("template-generation")?;
    let staged = boolean("staged")?;
    let consumed = boolean("consumed")?;
    let cgroup_name = name("cgroup-fdname")?;
    let cancellation_name = name("cancellation-fdname")?;
    let cgroup_device = unsigned("cgroup-device")?;
    let cgroup_inode = unsigned("cgroup-inode")?;
    let cancellation_eventfd_id = unsigned("cancellation-eventfd-id")?;
    let maximum_file_bytes = unsigned("maximum-file-bytes")?;
    let clone_into_cgroup = boolean("clone-into-cgroup")?;

    let identity = if staged {
        Some(QmpHotForkChildProcessContractIdentity::new(
            cgroup_device,
            cgroup_inode,
            cancellation_eventfd_id,
            maximum_file_bytes,
        )?)
    } else {
        None
    };
    let staged_shape = generation != 0
        && template_generation != 0
        && cgroup_name.is_some()
        && cancellation_name.is_some()
        && cgroup_name != cancellation_name
        && clone_into_cgroup;
    let absent_shape = template_generation == 0
        && cgroup_name.is_none()
        && cancellation_name.is_none()
        && cgroup_device == 0
        && cgroup_inode == 0
        && cancellation_eventfd_id == 0
        && maximum_file_bytes == 0
        && !clone_into_cgroup
        && !consumed;
    if schema_version != u64::from(QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_SCHEMA_VERSION)
        || staged != identity.is_some()
        || if staged { !staged_shape } else { !absent_shape }
    {
        return Err(malformed());
    }

    Ok(QmpHotForkChildProcessContractState {
        generation,
        template_generation,
        cgroup_name,
        cancellation_name,
        identity,
        consumed,
    })
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
    #![allow(clippy::expect_used)]

    use serde_json::json;

    use super::*;

    #[test]
    fn process_contract_requires_exact_staged_or_absent_shape() {
        let staged = json!({
            "schema-version": 1,
            "generation": 7,
            "template-generation": 3,
            "staged": true,
            "consumed": false,
            "cgroup-fdname": "crucible-hfork-cgroup-v1-0000000000000001",
            "cancellation-fdname": "crucible-hfork-cancel-v1-0000000000000001",
            "cgroup-device": 11,
            "cgroup-inode": 12,
            "cancellation-eventfd-id": 13,
            "maximum-file-bytes": 4096,
            "clone-into-cgroup": true,
        });
        let parsed = parse_hot_fork_child_process_contract_state(&staged)
            .expect("exact staged process contract should parse");
        assert!(parsed.staged());
        assert!(!parsed.consumed());

        let mut invalid = staged;
        invalid["clone-into-cgroup"] = json!(false);
        assert!(parse_hot_fork_child_process_contract_state(&invalid).is_err());

        let absent = json!({
            "schema-version": 1,
            "generation": 7,
            "template-generation": 0,
            "staged": false,
            "consumed": false,
            "cgroup-device": 0,
            "cgroup-inode": 0,
            "cancellation-eventfd-id": 0,
            "maximum-file-bytes": 0,
            "clone-into-cgroup": false,
        });
        assert!(
            !parse_hot_fork_child_process_contract_state(&absent)
                .expect("exact released process contract should parse")
                .staged()
        );
    }
}

//! QEMU-owned one-shot containment contract for a hot-fork child.
//!
//! The contract carries the target cgroup-v2 directory, the writable
//! `cgroup.procs` descriptor of that directory, and the sticky cancellation
//! eventfd. The fork child writes itself into `cgroup.procs` as its first
//! instruction; the kernel authorizes that write with the credentials of the
//! supervisor that opened the descriptor, which `clone3(CLONE_INTO_CGROUP)`
//! cannot do for an unprivileged source QEMU across a delegated root.

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpDescriptorName, QmpError};

/// QMP command that stages the target attempt's child process contract.
pub const QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_COMMAND: &str =
    "crucible-hot-fork-child-process-contract";
/// Version of the child process contract status.
pub const QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_SCHEMA_VERSION: u32 = 2;

/// Exact kernel identities and file-size ceiling transferred for one child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildProcessContractIdentity {
    cgroup_device: u64,
    cgroup_inode: u64,
    cgroup_procs_inode: u64,
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
        cgroup_procs_inode: u64,
        cancellation_eventfd_id: u64,
        maximum_file_bytes: u64,
    ) -> Result<Self, QmpError> {
        if cgroup_device == 0
            || cgroup_inode == 0
            || cgroup_procs_inode == 0
            || cancellation_eventfd_id == 0
            || maximum_file_bytes == 0
            || maximum_file_bytes == u64::MAX
        {
            return Err(QmpError::InvalidHotForkChildProcessContract);
        }
        Ok(Self {
            cgroup_device,
            cgroup_inode,
            cgroup_procs_inode,
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

    /// Returns the inode identity of the directory's `cgroup.procs` file.
    #[must_use]
    pub const fn cgroup_procs_inode(self) -> u64 {
        self.cgroup_procs_inode
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

/// Standard-QMP descriptor names of one staged child process contract.
///
/// The three names are distinct: the cgroup-v2 directory, its `cgroup.procs`
/// write descriptor, and the sticky cancellation eventfd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildProcessContractNames {
    cgroup: QmpDescriptorName,
    cgroup_procs: QmpDescriptorName,
    cancellation: QmpDescriptorName,
}

impl QmpHotForkChildProcessContractNames {
    /// Binds three distinct descriptor names.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::InvalidHotForkChildProcessContract`] when any two
    /// names are equal.
    pub fn new(
        cgroup: QmpDescriptorName,
        cgroup_procs: QmpDescriptorName,
        cancellation: QmpDescriptorName,
    ) -> Result<Self, QmpError> {
        if cgroup == cgroup_procs || cgroup == cancellation || cgroup_procs == cancellation {
            return Err(QmpError::InvalidHotForkChildProcessContract);
        }
        Ok(Self {
            cgroup,
            cgroup_procs,
            cancellation,
        })
    }

    /// Returns the cgroup directory name.
    #[must_use]
    pub const fn cgroup(&self) -> &QmpDescriptorName {
        &self.cgroup
    }

    /// Returns the `cgroup.procs` descriptor name.
    #[must_use]
    pub const fn cgroup_procs(&self) -> &QmpDescriptorName {
        &self.cgroup_procs
    }

    /// Returns the cancellation eventfd name.
    #[must_use]
    pub const fn cancellation(&self) -> &QmpDescriptorName {
        &self.cancellation
    }
}

/// Exact QEMU-owned state for one staged child process contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildProcessContractState {
    generation: u64,
    template_generation: u64,
    cgroup_name: Option<QmpDescriptorName>,
    cgroup_procs_name: Option<QmpDescriptorName>,
    cancellation_name: Option<QmpDescriptorName>,
    identity: Option<QmpHotForkChildProcessContractIdentity>,
    consumed: bool,
}

impl QmpHotForkChildProcessContractState {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn one_template_staged(
        generation: u64,
        template_generation: u64,
        names: &QmpHotForkChildProcessContractNames,
        identity: QmpHotForkChildProcessContractIdentity,
    ) -> Self {
        Self {
            generation,
            template_generation,
            cgroup_name: Some(names.cgroup().clone()),
            cgroup_procs_name: Some(names.cgroup_procs().clone()),
            cancellation_name: Some(names.cancellation().clone()),
            identity: Some(identity),
            consumed: false,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn one_released(generation: u64) -> Self {
        Self {
            generation,
            template_generation: 0,
            cgroup_name: None,
            cgroup_procs_name: None,
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

    /// Returns the standard-QMP `cgroup.procs` descriptor name while staged.
    #[must_use]
    pub const fn cgroup_procs_name(&self) -> Option<&QmpDescriptorName> {
        self.cgroup_procs_name.as_ref()
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

    /// Returns whether the staged names are exactly `names`.
    #[must_use]
    pub fn names_match(&self, names: &QmpHotForkChildProcessContractNames) -> bool {
        self.cgroup_name.as_ref() == Some(names.cgroup())
            && self.cgroup_procs_name.as_ref() == Some(names.cgroup_procs())
            && self.cancellation_name.as_ref() == Some(names.cancellation())
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
        "cgroup-procs-inode",
        "cancellation-eventfd-id",
        "maximum-file-bytes",
        "cgroup-placement-bound",
    ];
    let has_cgroup_name = object.contains_key("cgroup-fdname");
    let has_cgroup_procs_name = object.contains_key("cgroup-procs-fdname");
    let has_cancellation_name = object.contains_key("cancellation-fdname");
    if object.len()
        != required.len()
            + usize::from(has_cgroup_name)
            + usize::from(has_cgroup_procs_name)
            + usize::from(has_cancellation_name)
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
    let cgroup_procs_name = name("cgroup-procs-fdname")?;
    let cancellation_name = name("cancellation-fdname")?;
    let cgroup_device = unsigned("cgroup-device")?;
    let cgroup_inode = unsigned("cgroup-inode")?;
    let cgroup_procs_inode = unsigned("cgroup-procs-inode")?;
    let cancellation_eventfd_id = unsigned("cancellation-eventfd-id")?;
    let maximum_file_bytes = unsigned("maximum-file-bytes")?;
    let placement_bound = boolean("cgroup-placement-bound")?;

    let identity = if staged {
        Some(QmpHotForkChildProcessContractIdentity::new(
            cgroup_device,
            cgroup_inode,
            cgroup_procs_inode,
            cancellation_eventfd_id,
            maximum_file_bytes,
        )?)
    } else {
        None
    };
    let staged_shape = generation != 0
        && template_generation != 0
        && cgroup_name.is_some()
        && cgroup_procs_name.is_some()
        && cancellation_name.is_some()
        && cgroup_name != cancellation_name
        && cgroup_name != cgroup_procs_name
        && cgroup_procs_name != cancellation_name
        && placement_bound;
    let absent_shape = template_generation == 0
        && cgroup_name.is_none()
        && cgroup_procs_name.is_none()
        && cancellation_name.is_none()
        && cgroup_device == 0
        && cgroup_inode == 0
        && cgroup_procs_inode == 0
        && cancellation_eventfd_id == 0
        && maximum_file_bytes == 0
        && !placement_bound
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
        cgroup_procs_name,
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
            "schema-version": 2,
            "generation": 7,
            "template-generation": 3,
            "staged": true,
            "consumed": false,
            "cgroup-fdname": "crucible-hfork-cgroup-v1-0000000000000001",
            "cgroup-procs-fdname": "crucible-hfork-cgroup-procs-v1-0000000000000002",
            "cancellation-fdname": "crucible-hfork-cancel-v1-0000000000000001",
            "cgroup-device": 11,
            "cgroup-inode": 12,
            "cgroup-procs-inode": 14,
            "cancellation-eventfd-id": 13,
            "maximum-file-bytes": 4096,
            "cgroup-placement-bound": true,
        });
        let parsed = parse_hot_fork_child_process_contract_state(&staged)
            .expect("exact staged process contract should parse");
        assert!(parsed.staged());
        assert!(!parsed.consumed());
        assert_eq!(
            parsed
                .identity()
                .map(|identity| identity.cgroup_procs_inode()),
            Some(14)
        );

        let mut invalid = staged.clone();
        invalid["cgroup-placement-bound"] = json!(false);
        assert!(parse_hot_fork_child_process_contract_state(&invalid).is_err());
        let mut missing_procs = staged;
        missing_procs
            .as_object_mut()
            .expect("staged fixture is an object")
            .remove("cgroup-procs-fdname");
        assert!(parse_hot_fork_child_process_contract_state(&missing_procs).is_err());

        let absent = json!({
            "schema-version": 2,
            "generation": 7,
            "template-generation": 0,
            "staged": false,
            "consumed": false,
            "cgroup-device": 0,
            "cgroup-inode": 0,
            "cgroup-procs-inode": 0,
            "cancellation-eventfd-id": 0,
            "maximum-file-bytes": 0,
            "cgroup-placement-bound": false,
        });
        assert!(
            !parse_hot_fork_child_process_contract_state(&absent)
                .expect("exact released process contract should parse")
                .staged()
        );
    }
}

//! QEMU-owned one-shot child-private native file plan for a hot-fork child.
//!
//! Every originally writable native leaf beneath a retained source root needs
//! an empty destination that the fork child adopts as its private copy. The
//! host transfers each destination through standard `getfd`, names the root by
//! backend or parentless node name, and stages the complete list once per
//! child. QEMU binds the plan to the retained template and reports it back in
//! this exact shape:
//!
//! ```text
//! {
//!   "schema-version": 1,
//!   "generation": 3,
//!   "template-generation": 2,
//!   "staged": true,
//!   "consumed": false,
//!   "maximum-bytes": 1073741824,
//!   "files": [
//!     {"node-name": "vmstate", "fdname": "crucible-hfork-file-v1-0000-00000000000a1b2c",
//!      "expected-device": 66306, "expected-inode": 660012}
//!   ]
//! }
//! ```

use serde_json::Value;

use super::block_barrier::QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES;
use crate::qmp::{QmpCommandKind, QmpDescriptorName, QmpError};

/// QMP command that stages, queries, or releases the child-private file plan.
pub const QMP_HOT_FORK_CHILD_FILES_COMMAND: &str = "crucible-hot-fork-child-files";
/// Version of the child-private file plan status.
pub const QMP_HOT_FORK_CHILD_FILES_SCHEMA_VERSION: u32 = 1;
/// Upper bound on destinations QEMU accepts in one plan.
pub const QMP_HOT_FORK_CHILD_FILES_MAX: usize = 4096;

/// Retained source root that owns one originally writable native leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QmpHotForkChildFileRoot {
    /// A retained `BlockBackend` named at launch, such as the root drive.
    Device(String),
    /// A parentless named native root, such as the VMState container.
    NodeName(String),
}

impl QmpHotForkChildFileRoot {
    /// Selects the root by its retained backend name.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::InvalidHotForkChildFiles`] when the name is empty
    /// or longer than the block node-name bound.
    pub fn device(name: impl Into<String>) -> Result<Self, QmpError> {
        let name = name.into();
        Self::validate_name(&name)?;
        Ok(Self::Device(name))
    }

    /// Selects a parentless root by its node name.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::InvalidHotForkChildFiles`] when the name is empty
    /// or longer than the block node-name bound.
    pub fn node_name(name: impl Into<String>) -> Result<Self, QmpError> {
        let name = name.into();
        Self::validate_name(&name)?;
        Ok(Self::NodeName(name))
    }

    fn validate_name(name: &str) -> Result<(), QmpError> {
        if name.is_empty()
            || name.len() > QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(QmpError::InvalidHotForkChildFiles);
        }
        Ok(())
    }

    /// Returns the selector name without its kind.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Device(name) | Self::NodeName(name) => name,
        }
    }
}

/// One caller-owned empty destination bound to a retained root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildFile {
    root: QmpHotForkChildFileRoot,
    name: QmpDescriptorName,
    device: u64,
    inode: u64,
}

impl QmpHotForkChildFile {
    /// Binds one standard-QMP destination name to a root and its exact identity.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::InvalidHotForkChildFiles`] when either identity
    /// component is zero.
    pub fn new(
        root: QmpHotForkChildFileRoot,
        name: QmpDescriptorName,
        device: u64,
        inode: u64,
    ) -> Result<Self, QmpError> {
        if device == 0 || inode == 0 {
            return Err(QmpError::InvalidHotForkChildFiles);
        }
        Ok(Self {
            root,
            name,
            device,
            inode,
        })
    }

    /// Returns the retained root selector.
    #[must_use]
    pub const fn root(&self) -> &QmpHotForkChildFileRoot {
        &self.root
    }

    /// Returns the standard-QMP destination descriptor name.
    #[must_use]
    pub const fn name(&self) -> &QmpDescriptorName {
        &self.name
    }

    /// Returns the expected destination `st_dev`.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the expected destination `st_ino`.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    pub(crate) fn wire_value(&self) -> Value {
        let mut object = serde_json::Map::new();
        match &self.root {
            QmpHotForkChildFileRoot::Device(name) => {
                object.insert(String::from("device"), Value::String(name.clone()));
            }
            QmpHotForkChildFileRoot::NodeName(name) => {
                object.insert(String::from("node-name"), Value::String(name.clone()));
            }
        }
        object.insert(
            String::from("fdname"),
            Value::String(self.name.as_str().to_owned()),
        );
        object.insert(String::from("expected-device"), Value::from(self.device));
        object.insert(String::from("expected-inode"), Value::from(self.inode));
        Value::Object(object)
    }
}

/// Exact QEMU-owned state for one staged child-private file plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildFilesState {
    generation: u64,
    template_generation: u64,
    staged: bool,
    consumed: bool,
    maximum_bytes: u64,
    files: Vec<QmpHotForkChildFile>,
}

impl QmpHotForkChildFilesState {
    #[cfg(test)]
    pub(crate) fn one_template_staged(
        generation: u64,
        template_generation: u64,
        maximum_bytes: u64,
        files: Vec<QmpHotForkChildFile>,
    ) -> Self {
        Self {
            generation,
            template_generation,
            staged: true,
            consumed: false,
            maximum_bytes,
            files,
        }
    }

    #[cfg(test)]
    pub(crate) const fn one_released(generation: u64) -> Self {
        Self {
            generation,
            template_generation: 0,
            staged: false,
            consumed: false,
            maximum_bytes: 0,
            files: Vec::new(),
        }
    }

    /// Returns the source-QEMU plan mutation generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact retained template generation while staged.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns whether QEMU retains every destination duplicate.
    #[must_use]
    pub const fn staged(&self) -> bool {
        self.staged
    }

    /// Returns whether this one-shot plan has created a child.
    #[must_use]
    pub const fn consumed(&self) -> bool {
        self.consumed
    }

    /// Returns the aggregate source-byte budget for private copies.
    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    /// Returns the staged destinations in stage order.
    #[must_use]
    pub fn files(&self) -> &[QmpHotForkChildFile] {
        &self.files
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HotForkChildFilesAction {
    Stage,
    Query,
    Release,
}

impl HotForkChildFilesAction {
    pub(crate) const fn wire_name(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

pub(crate) fn parse_hot_fork_child_files_state(
    value: &Value,
) -> Result<QmpHotForkChildFilesState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkChildFiles,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let required = [
        "schema-version",
        "generation",
        "template-generation",
        "staged",
        "consumed",
        "maximum-bytes",
        "files",
    ];
    if object.len() != required.len() || !required.iter().all(|field| object.contains_key(*field)) {
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

    let schema_version = unsigned("schema-version")?;
    let generation = unsigned("generation")?;
    let template_generation = unsigned("template-generation")?;
    let staged = boolean("staged")?;
    let consumed = boolean("consumed")?;
    let maximum_bytes = unsigned("maximum-bytes")?;
    let entries = object
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if entries.len() > QMP_HOT_FORK_CHILD_FILES_MAX {
        return Err(malformed());
    }
    let mut files = Vec::with_capacity(entries.len());
    for entry in entries {
        files.push(parse_child_file(entry).ok_or_else(&malformed)?);
    }

    let staged_shape = generation != 0
        && template_generation != 0
        && maximum_bytes != 0
        && maximum_bytes != u64::MAX
        && !files.is_empty();
    let absent_shape =
        template_generation == 0 && maximum_bytes == 0 && files.is_empty() && !consumed;
    if schema_version != u64::from(QMP_HOT_FORK_CHILD_FILES_SCHEMA_VERSION)
        || if staged { !staged_shape } else { !absent_shape }
    {
        return Err(malformed());
    }

    Ok(QmpHotForkChildFilesState {
        generation,
        template_generation,
        staged,
        consumed,
        maximum_bytes,
        files,
    })
}

fn parse_child_file(value: &Value) -> Option<QmpHotForkChildFile> {
    let object = value.as_object()?;
    let device_name = object.get("device").map(Value::as_str);
    let node_name = object.get("node-name").map(Value::as_str);
    let root = match (device_name, node_name) {
        (Some(Some(name)), None) => QmpHotForkChildFileRoot::device(name).ok()?,
        (None, Some(Some(name))) => QmpHotForkChildFileRoot::node_name(name).ok()?,
        _ => return None,
    };
    let expected_fields = 4;
    if object.len() != expected_fields {
        return None;
    }
    let name = QmpDescriptorName::new(object.get("fdname")?.as_str()?).ok()?;
    let device = object.get("expected-device")?.as_u64()?;
    let inode = object.get("expected-inode")?.as_u64()?;
    QmpHotForkChildFile::new(root, name, device, inode).ok()
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
    #![allow(clippy::expect_used)]

    use serde_json::json;

    use super::*;

    #[test]
    fn child_files_require_exact_staged_or_absent_shape() {
        let staged = json!({
            "schema-version": 1,
            "generation": 3,
            "template-generation": 2,
            "staged": true,
            "consumed": false,
            "maximum-bytes": 4096,
            "files": [{
                "node-name": "vmstate",
                "fdname": "crucible-hfork-file-v1-0000-0000000000000001",
                "expected-device": 11,
                "expected-inode": 12,
            }, {
                "device": "root",
                "fdname": "crucible-hfork-file-v1-0001-0000000000000002",
                "expected-device": 11,
                "expected-inode": 13,
            }],
        });
        let parsed = parse_hot_fork_child_files_state(&staged)
            .expect("exact staged child file plan should parse");
        assert!(parsed.staged());
        assert!(!parsed.consumed());
        assert_eq!(parsed.files().len(), 2);
        assert_eq!(
            parsed.files()[0].root(),
            &QmpHotForkChildFileRoot::NodeName(String::from("vmstate"))
        );
        assert_eq!(
            parsed.files()[1].root(),
            &QmpHotForkChildFileRoot::Device(String::from("root"))
        );

        let mut both_selectors = staged.clone();
        both_selectors["files"][0]["device"] = json!("root");
        assert!(parse_hot_fork_child_files_state(&both_selectors).is_err());

        let mut empty_staged = staged.clone();
        empty_staged["files"] = json!([]);
        assert!(parse_hot_fork_child_files_state(&empty_staged).is_err());

        let mut zero_inode = staged;
        zero_inode["files"][1]["expected-inode"] = json!(0);
        assert!(parse_hot_fork_child_files_state(&zero_inode).is_err());

        let absent = json!({
            "schema-version": 1,
            "generation": 3,
            "template-generation": 0,
            "staged": false,
            "consumed": false,
            "maximum-bytes": 0,
            "files": [],
        });
        assert!(
            !parse_hot_fork_child_files_state(&absent)
                .expect("exact released child file plan should parse")
                .staged()
        );

        let mut consumed_absent = absent;
        consumed_absent["consumed"] = json!(true);
        assert!(parse_hot_fork_child_files_state(&consumed_absent).is_err());
    }

    #[test]
    fn root_selectors_are_bounded_block_names() {
        assert!(QmpHotForkChildFileRoot::device("").is_err());
        assert!(QmpHotForkChildFileRoot::node_name("a".repeat(32)).is_err());
        assert!(QmpHotForkChildFileRoot::node_name("vm state").is_err());
        assert_eq!(
            QmpHotForkChildFileRoot::device("root-drive")
                .expect("bounded device name")
                .as_str(),
            "root-drive"
        );
    }
}

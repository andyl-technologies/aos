//! Validates native source provenance retained by an immutable-root binding.
//!
//! The enclosing block barrier binds this report to its owner and graph/backend
//! generations. Counts describe the captured sources, not current permissions
//! or a child-private graph installation:
//!
//! ```json
//! {"schema-version":1,"frozen":true,"root-count":2,"node-count":4,
//!  "originally-writable-root-count":2,"originally-writable-backend-count":1}
//! ```

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpError};

/// Version of the retained native source-set provenance contract.
pub const QMP_HOT_FORK_BLOCK_SOURCE_PROOF_SCHEMA_VERSION: u32 = 1;

/// QEMU-attested native source closure captured during snapshot binding.
///
/// A frozen source set includes backend roots and parentless roots such as
/// VMState containers. It does not attest installation of private child graphs
/// or authorize child execution. Current write permissions remain separate in
/// [`super::QmpHotForkBlockBarrierState`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkBlockSourceProof {
    frozen: bool,
    root_count: u64,
    node_count: u64,
    originally_writable_root_count: u64,
    originally_writable_backend_count: u64,
}

impl QmpHotForkBlockSourceProof {
    /// Returns whether binding authenticated a complete frozen source set.
    #[must_use]
    pub const fn frozen(&self) -> bool {
        self.frozen
    }

    /// Returns the exact retained root count, including parentless containers.
    #[must_use]
    pub const fn root_count(&self) -> u64 {
        self.root_count
    }

    /// Returns the exact number of distinct retained native graph nodes.
    #[must_use]
    pub const fn node_count(&self) -> u64 {
        self.node_count
    }

    /// Returns the number of roots writable before source preparation.
    #[must_use]
    pub const fn originally_writable_root_count(&self) -> u64 {
        self.originally_writable_root_count
    }

    /// Returns the number of backends requesting write before preparation.
    #[must_use]
    pub const fn originally_writable_backend_count(&self) -> u64 {
        self.originally_writable_backend_count
    }

    #[cfg(test)]
    pub(super) const fn empty_frozen() -> Self {
        Self {
            frozen: true,
            root_count: 0,
            node_count: 0,
            originally_writable_root_count: 0,
            originally_writable_backend_count: 0,
        }
    }

    pub(super) fn parse(command: QmpCommandKind, value: &Value) -> Result<Self, QmpError> {
        let malformed = || QmpError::MalformedTypedResponse {
            command,
            response: value.to_string(),
        };
        let object = value.as_object().ok_or_else(&malformed)?;
        let fields = [
            "schema-version",
            "frozen",
            "root-count",
            "node-count",
            "originally-writable-root-count",
            "originally-writable-backend-count",
        ];
        if object.len() != fields.len() || !fields.iter().all(|key| object.contains_key(*key)) {
            return Err(malformed());
        }
        let number = |field| {
            object
                .get(field)
                .and_then(Value::as_u64)
                .ok_or_else(&malformed)
        };
        let schema_version = number("schema-version")?;
        let proof = Self {
            frozen: object
                .get("frozen")
                .and_then(Value::as_bool)
                .ok_or_else(&malformed)?,
            root_count: number("root-count")?,
            node_count: number("node-count")?,
            originally_writable_root_count: number("originally-writable-root-count")?,
            originally_writable_backend_count: number("originally-writable-backend-count")?,
        };

        // QEMU bounds the complete source set to 65,536 graph visits. An
        // absent proof is all-zero; an authenticated empty set is distinct.
        let valid = schema_version == u64::from(QMP_HOT_FORK_BLOCK_SOURCE_PROOF_SCHEMA_VERSION)
            && proof.node_count <= 65_536
            && proof.root_count <= proof.node_count
            && (proof.root_count == 0) == (proof.node_count == 0)
            && proof.originally_writable_root_count <= proof.root_count
            && proof.originally_writable_backend_count <= proof.originally_writable_root_count
            && (proof.frozen || proof.node_count == 0);
        if !valid {
            return Err(malformed());
        }
        Ok(proof)
    }
}
